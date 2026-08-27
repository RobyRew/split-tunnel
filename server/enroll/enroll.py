#!/usr/bin/env python3
"""
split-tunnel enrollment service.

Turns a Logto login into a short-lived SSH certificate, so nobody ever
exchanges a public key by hand.

    client                     this service                  sshd (tunnel)
    ------                     ------------                  -------------
    device-flow login  ──────▶ verify tokens vs Logto JWKS
    generate keypair           check scope + email allowlist
    POST /enroll  ────────────▶ ssh-keygen -s CA  ──▶ cert
    ssh -i key ───────────────────────────────────────────▶ TrustedUserCAKeys

Design notes worth keeping in mind before changing anything here:

* TWO tokens are required, and they serve different jobs. The *access token*
  carries the authorisation (`scope`), and its audience is this API. The
  *ID token* carries the identity (`email`), and its audience is the client.
  Using the ID token alone would authorise on a token minted for somebody
  else's audience; using the access token alone leaves you with a UUID and no
  way to run an email allowlist. Both are verified, and their `sub` must match.

* The signed certificate carries `-O clear -O permit-port-forwarding` — no pty,
  no agent forwarding, no X11. A stolen cert forwards TCP and nothing else.

* The private key is generated on the client and never transits the network.
  This service only ever sees a public key.
"""

import base64
import fcntl
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path

import jwt
from flask import Flask, jsonify, request
from waitress import serve

# ── Config ────────────────────────────────────────────────────────────────
CONFIG_PATH = os.environ.get("ENROLL_CONFIG", "/config/config.json")

with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
    CFG = json.load(fh)

ISSUER = CFG["issuer"]
JWKS_URI = CFG["jwks_uri"]
CLIENT_ID = CFG["client_id"]
API_RESOURCE = CFG["api_resource"]
REQUIRED_SCOPE = CFG.get("required_scope", "tunnel:connect")
ALLOWED_EMAILS = {e.strip().lower() for e in CFG.get("allowed_emails", []) if e.strip()}
REQUIRE_VERIFIED_EMAIL = bool(CFG.get("require_verified_email", True))
ALGORITHMS = CFG.get("algorithms", ["ES384", "ES256", "RS256"])

CA_KEY = CFG.get("ca_key", "/ca/tunnel_ca")
PRINCIPAL = CFG.get("principal", "tunnel")
CERT_TTL = CFG.get("cert_ttl", "12h")
SERIAL_FILE = CFG.get("serial_file", "/state/serial")

TUNNEL_HOST = CFG["tunnel_host"]
TUNNEL_PORT = int(CFG.get("tunnel_port", 2223))
TUNNEL_USER = CFG.get("tunnel_user", "tunnel")
HOST_KEY = CFG.get("host_key", "")           # "ssh-ed25519 AAAA..." for known_hosts
HOST_FINGERPRINT = CFG.get("host_fingerprint", "")

RATE_LIMIT = int(CFG.get("rate_limit_per_hour", 20))
MAX_BODY = 8 * 1024

# Only ed25519. Not a fashion statement: it keeps the parser below tiny, and
# every client we ship generates ed25519 anyway.
ALLOWED_KEY_TYPES = {"ssh-ed25519"}
KEYID_SAFE = re.compile(r"[^A-Za-z0-9._@+-]")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("enroll")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY

# PyJWKClient caches keys and refetches on an unknown `kid`, which is what we
# want across a Logto signing-key rotation.
jwks_client = jwt.PyJWKClient(JWKS_URI, cache_keys=True, lifespan=3600)

_hits = defaultdict(deque)


class Denied(Exception):
    """Rejected for a reason the caller is allowed to be told about."""

    def __init__(self, message, status=403):
        super().__init__(message)
        self.message = message
        self.status = status


# ── Token verification ────────────────────────────────────────────────────
def _verify(token, audience, what):
    """Verify one JWT against Logto's JWKS. Raises Denied with a usable reason."""
    try:
        key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as exc:  # network, malformed token, unknown kid
        raise Denied(f"{what}: cannot resolve signing key ({exc})", 401) from exc

    try:
        return jwt.decode(
            token,
            key.key,
            algorithms=ALGORITHMS,
            audience=audience,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise Denied(f"{what}: expired — sign in again", 401) from exc
    except jwt.InvalidAudienceError as exc:
        raise Denied(
            f"{what}: wrong audience (expected {audience!r}). "
            "Check the Logto app's API resource / client id.",
            401,
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise Denied(f"{what}: invalid ({exc})", 401) from exc


def _rate_limit(subject):
    now = time.time()
    window = _hits[subject]
    while window and now - window[0] > 3600:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        raise Denied("too many enrolments this hour — try later", 429)
    window.append(now)


# ── Public key handling ───────────────────────────────────────────────────
def parse_public_key(raw):
    """
    Accept exactly one ed25519 public key in OpenSSH format.

    Rejects certificates outright: feeding a *-cert.pub back in would ask the
    CA to re-sign an already-signed blob, and the type/blob cross-check below
    is what stops a mismatched header lying about what the key really is.
    """
    if not isinstance(raw, str):
        raise Denied("public_key must be a string", 400)

    raw = raw.strip()
    if not raw or "\n" in raw or "\r" in raw:
        raise Denied("public_key must be a single line", 400)
    if len(raw) > 1024:
        raise Denied("public_key is implausibly long", 400)

    parts = raw.split()
    if len(parts) < 2:
        raise Denied("public_key is malformed", 400)

    keytype, blob_b64 = parts[0], parts[1]
    if "cert-v01" in keytype:
        raise Denied("public_key is a certificate, not a key", 400)
    if keytype not in ALLOWED_KEY_TYPES:
        raise Denied(
            f"unsupported key type {keytype!r} — this service signs "
            f"{'/'.join(sorted(ALLOWED_KEY_TYPES))} only",
            400,
        )

    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except Exception as exc:
        raise Denied("public_key body is not valid base64", 400) from exc

    # An OpenSSH key blob starts with a length-prefixed copy of its own type.
    # If it disagrees with the header, the header is lying.
    if len(blob) < 4:
        raise Denied("public_key body is truncated", 400)
    inner_len = int.from_bytes(blob[:4], "big")
    if inner_len > len(blob) - 4 or inner_len > 64:
        raise Denied("public_key body is malformed", 400)
    inner = blob[4 : 4 + inner_len].decode("ascii", errors="replace")
    if inner != keytype:
        raise Denied(f"public_key type mismatch ({keytype!r} vs {inner!r})", 400)

    return f"{keytype} {blob_b64}"


def next_serial():
    """Monotonic certificate serial, so revocation lists can name one cert."""
    path = Path(SERIAL_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        try:
            current = int((fh.read() or "0").strip())
        except ValueError:
            current = 0
        current += 1
        fh.seek(0)
        fh.truncate()
        fh.write(str(current))
        fh.flush()
        os.fsync(fh.fileno())
        fcntl.flock(fh, fcntl.LOCK_UN)
    return current


def sign_certificate(public_key, key_id):
    """Sign `public_key` with the CA. Returns (cert_text, serial)."""
    serial = next_serial()
    safe_id = KEYID_SAFE.sub("_", key_id)[:100] or "unknown"

    with tempfile.TemporaryDirectory() as tmp:
        pub_path = Path(tmp) / "id.pub"
        pub_path.write_text(public_key + "\n", encoding="utf-8")

        cmd = [
            "ssh-keygen",
            "-s", CA_KEY,
            "-I", safe_id,
            "-n", PRINCIPAL,
            "-V", f"+{CERT_TTL}",
            "-z", str(serial),
            # Drop every default extension, then re-add only what a SOCKS
            # tunnel needs. No pty, no agent forwarding, no X11.
            "-O", "clear",
            "-O", "permit-port-forwarding",
            "-q",
            str(pub_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            log.error("ssh-keygen failed: %s %s", proc.stdout, proc.stderr)
            raise Denied("certificate signing failed", 500)

        cert_path = Path(tmp) / "id-cert.pub"
        if not cert_path.exists():
            raise Denied("certificate signing produced no output", 500)
        return cert_path.read_text(encoding="utf-8").strip(), serial


# ── Routes ────────────────────────────────────────────────────────────────
@app.errorhandler(Denied)
def _denied(exc):
    return jsonify({"error": exc.message}), exc.status


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "principal": PRINCIPAL, "ttl": CERT_TTL})


@app.get("/config")
def client_config():
    """
    Everything a fresh client needs to start a sign-in, so a new user types one
    URL and nothing else.

    All of this is public by construction: `client_id` identifies a *public*
    native OAuth client, which by RFC 8252 holds no secret and is safe to hand
    out. Nothing here grants access — the tokens do, and those still have to be
    earned by logging in as somebody holding the role.
    """
    return jsonify({
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "resource": API_RESOURCE,
        "scope": REQUIRED_SCOPE,
        "cert_ttl": CERT_TTL,
    })


@app.post("/enroll")
def enroll():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise Denied("missing bearer access token", 401)
    access_token = auth[7:].strip()

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Denied("body must be JSON", 400)

    id_token = body.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise Denied("id_token is required", 400)

    public_key = parse_public_key(body.get("public_key"))

    # Authorisation comes from the access token (audience = this API).
    access = _verify(access_token, API_RESOURCE, "access token")
    scopes = set((access.get("scope") or "").split())
    if REQUIRED_SCOPE not in scopes:
        raise Denied(
            f"account lacks the {REQUIRED_SCOPE!r} permission — "
            "ask the administrator to grant you the tunnel role",
            403,
        )

    # Identity comes from the ID token (audience = the client app).
    identity = _verify(id_token, CLIENT_ID, "id token")
    if identity.get("sub") != access.get("sub"):
        raise Denied("id token and access token belong to different users", 401)

    email = (identity.get("email") or "").strip().lower()
    if not email:
        raise Denied(
            "no email in the id token — request the 'email' scope at sign-in",
            403,
        )
    if REQUIRE_VERIFIED_EMAIL and not identity.get("email_verified", False):
        raise Denied(f"email {email} is not verified in Logto", 403)
    if ALLOWED_EMAILS and email not in ALLOWED_EMAILS:
        raise Denied(f"{email} is not on the tunnel allowlist", 403)

    _rate_limit(access["sub"])

    certificate, serial = sign_certificate(public_key, email)
    expires_at = int(time.time()) + _ttl_seconds(CERT_TTL)

    log.info(
        "issued cert serial=%s id=%s sub=%s expires_in=%s",
        serial, email, access["sub"], CERT_TTL,
    )

    return jsonify({
        "certificate": certificate,
        "serial": serial,
        "identity": email,
        "principal": PRINCIPAL,
        "expires_at": expires_at,
        # Everything the client needs to connect, so a new user configures
        # nothing by hand after signing in.
        "tunnel": {
            "host": TUNNEL_HOST,
            "port": TUNNEL_PORT,
            "user": TUNNEL_USER,
            "host_key": HOST_KEY,
            "host_fingerprint": HOST_FINGERPRINT,
        },
    })


def _ttl_seconds(ttl):
    units = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
    match = re.fullmatch(r"(\d+)([mhdw])", ttl.strip())
    if not match:
        return 43200
    return int(match.group(1)) * units[match.group(2)]


if __name__ == "__main__":
    if not Path(CA_KEY).exists():
        log.error("CA key %s is missing — refusing to start", CA_KEY)
        sys.exit(1)
    log.info(
        "enroll service up — issuer=%s resource=%s allowlist=%s ttl=%s",
        ISSUER, API_RESOURCE, len(ALLOWED_EMAILS) or "any-with-scope", CERT_TTL,
    )
    serve(app, host="0.0.0.0", port=8080, threads=4, ident="enroll")
