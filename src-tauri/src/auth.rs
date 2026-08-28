//! OAuth 2.0 Device Authorization Grant (RFC 8628) against an OIDC provider.
//!
//! Chosen over the usual desktop redirect flow deliberately. A redirect flow
//! needs a loopback HTTP listener inside this process and a redirect URI
//! registered to match it; the device flow needs neither. The app asks for a
//! code, opens the browser, and polls. Nothing listens, nothing is registered,
//! and it behaves identically on a locked-down corporate desktop — which is
//! the network this whole program exists to get out of.
//!
//! Two tokens come back and both matter:
//!   * `access_token` — audience is the enrollment API, carries the scope.
//!   * `id_token`     — audience is this app, carries the email.
//! The server checks both. See the enroll service for why.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the identity provider lives. Baked into the *config*, never into the
/// binary — the published build must contain no personal infrastructure.
///
/// `serde(default)` is required, not cosmetic: the UI sends `oidc: {}` before
/// anything has been discovered, and a config written by an older build has no
/// `scopes` key. Without it every save fails with "missing field".
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct OidcSettings {
    /// e.g. https://auth.example.com/oidc
    pub issuer: String,
    pub client_id: String,
    /// The API resource indicator registered with the IdP.
    pub resource: String,
    /// Extra scope that authorises tunnel use, e.g. "tunnel:connect".
    pub scope: String,
    /// The FULL scope string to request, as dictated by the server.
    ///
    /// Server-driven because identity providers grant user scopes per
    /// application: asking for one the provider has not granted fails the
    /// whole sign-in with `invalid_scope`. Letting the server say what to ask
    /// for means that changes there never need a new client build.
    pub scopes: String,
    /// Loopback port for the authorization-code redirect. Server-driven so it
    /// always matches what is registered with the identity provider — a
    /// mismatch is rejected outright and is tedious to diagnose.
    pub redirect_port: u16,
}

/// The redirect URI, built from the port. 127.0.0.1 rather than "localhost" on
/// purpose: "localhost" can resolve to ::1 and then fail to match a listener
/// bound to IPv4.
pub fn redirect_uri(port: u16) -> String {
    format!("http://127.0.0.1:{port}/callback")
}

impl OidcSettings {
    pub fn is_complete(&self) -> bool {
        !self.issuer.trim().is_empty() && !self.client_id.trim().is_empty()
    }
    fn device_endpoint(&self) -> String {
        format!("{}/device/auth", self.issuer.trim_end_matches('/'))
    }
    fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer.trim_end_matches('/'))
    }
    fn scopes(&self) -> String {
        if !self.scopes.trim().is_empty() {
            return self.scopes.trim().to_string();
        }
        // Fallback for a server too old to advertise a scope list. Kept
        // conservative: `openid` and `offline_access` are always grantable,
        // whereas `email` and `profile` are per-application.
        let mut s = vec!["openid", "offline_access"];
        if !self.scope.trim().is_empty() {
            s.push(self.scope.trim());
        }
        s.join(" ")
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct DevicePrompt {
    pub user_code: String,
    pub verification_uri: String,
    /// The URI with the code already embedded. When the provider supplies it
    /// the user only has to click; no typing the code by hand.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    #[serde(skip)]
    pub device_code: String,
    #[serde(skip)]
    pub interval: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Tokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
    /// Unix seconds. Only used to decide when to refresh.
    pub expires_at: u64,
    /// Read out of the id_token for display. NOT trusted for anything —
    /// the server verifies the signature and makes its own decision.
    pub email: String,
}

impl Tokens {
    pub fn is_expired(&self) -> bool {
        now() + 60 >= self.expires_at
    }
    pub fn path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("tokens.json")
    }
    /// Stored under the per-user app config directory, which on Windows is
    /// already ACL'd to this user. A refresh token here is worth no more than
    /// the SSH key sitting beside it.
    pub fn load(dir: &std::path::Path) -> Option<Self> {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }
    pub fn save(&self, dir: &std::path::Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(dir), body).map_err(|e| e.to_string())
    }
    pub fn forget(dir: &std::path::Path) {
        let _ = std::fs::remove_file(Self::path(dir));
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the payload of a JWT without verifying it.
///
/// Safe here *only* because the result is used for on-screen display. Every
/// security decision is made by the enrollment service, which checks the
/// signature against the provider's JWKS.
fn jwt_claim(token: &str, claim: &str) -> String {
    let Some(payload) = token.split('.').nth(1) else {
        return String::new();
    };
    let mut b64 = payload.replace('-', "+").replace('_', "/");
    while b64.len() % 4 != 0 {
        b64.push('=');
    }
    let Ok(bytes) = base64_decode(&b64) else {
        return String::new();
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get(claim).and_then(|c| c.as_str().map(String::from)))
        .unwrap_or_default()
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let Some(idx) = T.iter().position(|&t| t == c) else {
            return Err(());
        };
        buf = (buf << 6) | idx as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

fn post_form(
    agent: &ureq::Agent,
    url: &str,
    form: &[(&str, &str)],
) -> Result<serde_json::Value, String> {
    let resp = agent.post(url).send_form(form);
    match resp {
        Ok(r) => r.into_json().map_err(|e| format!("bad response: {e}")),
        // The device flow signals "not yet" with a 400 body, so error bodies
        // are load-bearing rather than merely informative.
        Err(ureq::Error::Status(_, r)) => r
            .into_json()
            .map_err(|e| format!("bad error response: {e}")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

/// Step 1 — ask the provider for a user code.
pub fn begin(agent: &ureq::Agent, settings: &OidcSettings) -> Result<DevicePrompt, String> {
    if !settings.is_complete() {
        return Err("Sign-in is not configured (issuer and client id).".into());
    }
    let scopes = settings.scopes();
    let mut form: Vec<(&str, &str)> = vec![
        ("client_id", settings.client_id.as_str()),
        ("scope", scopes.as_str()),
    ];
    if !settings.resource.trim().is_empty() {
        form.push(("resource", settings.resource.trim()));
    }

    let v = post_form(agent, &settings.device_endpoint(), &form)?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(describe(err, &v));
    }

    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let device_code = get("device_code");
    if device_code.is_empty() {
        return Err("provider returned no device code".into());
    }
    let uri = get("verification_uri");
    let complete = {
        let c = get("verification_uri_complete");
        if c.is_empty() { uri.clone() } else { c }
    };
    Ok(DevicePrompt {
        user_code: get("user_code"),
        verification_uri: uri,
        verification_uri_complete: complete,
        expires_in: v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(600),
        device_code,
        interval: v.get("interval").and_then(|x| x.as_u64()).unwrap_or(5).max(1),
    })
}

/// Step 2 — poll until the user finishes in the browser.
///
/// `cancelled` lets the UI abort a poll that would otherwise run for the full
/// code lifetime (typically ten minutes).
pub fn poll(
    agent: &ureq::Agent,
    settings: &OidcSettings,
    prompt: &DevicePrompt,
    cancelled: &dyn Fn() -> bool,
) -> Result<Tokens, String> {
    let deadline = now() + prompt.expires_in;
    let mut interval = prompt.interval;

    while now() < deadline {
        for _ in 0..interval {
            if cancelled() {
                return Err("sign-in cancelled".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", prompt.device_code.as_str()),
            ("client_id", settings.client_id.as_str()),
        ];
        if !settings.resource.trim().is_empty() {
            form.push(("resource", settings.resource.trim()));
        }

        let v = post_form(agent, &settings.token_endpoint(), &form)?;
        match v.get("error").and_then(|e| e.as_str()) {
            None => return Ok(into_tokens(v)),
            Some("authorization_pending") => continue,
            // The provider is telling us we are polling too fast. Obeying this
            // matters: ignoring it earns a hard `access_denied`.
            Some("slow_down") => {
                interval += 5;
                continue;
            }
            Some(err) => return Err(describe(err, &v)),
        }
    }
    Err("the sign-in code expired — try again".into())
}

/// Exchange a stored refresh token for a fresh access token, with no user
/// interaction. This is what makes certificate renewal silent.
pub fn refresh(
    agent: &ureq::Agent,
    settings: &OidcSettings,
    refresh_token: &str,
) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", settings.client_id.as_str()),
    ];
    if !settings.resource.trim().is_empty() {
        form.push(("resource", settings.resource.trim()));
    }
    let v = post_form(agent, &settings.token_endpoint(), &form)?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(describe(err, &v));
    }
    let mut t = into_tokens(v);
    // Providers may rotate refresh tokens, or may omit an unchanged one.
    if t.refresh_token.is_empty() {
        t.refresh_token = refresh_token.to_string();
    }
    Ok(t)
}

fn into_tokens(v: serde_json::Value) -> Tokens {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let id_token = get("id_token");
    Tokens {
        email: jwt_claim(&id_token, "email"),
        access_token: get("access_token"),
        id_token,
        refresh_token: get("refresh_token"),
        expires_at: now() + v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(3600),
    }
}

/// Turn OAuth error codes into something a human can act on.
fn describe(err: &str, v: &serde_json::Value) -> String {
    let detail = v
        .get("error_description")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let base = match err {
        "access_denied" => "sign-in was refused — the account may lack tunnel access".to_string(),
        "expired_token" => "the sign-in code expired — try again".to_string(),
        "invalid_client" => {
            "the client id is wrong, or the app is not configured for the device flow".to_string()
        }
        "invalid_grant" => "the session is no longer valid — sign in again".to_string(),
        "invalid_target" => {
            "the API resource is not registered with the identity provider".to_string()
        }
        "invalid_scope" => {
            "the requested permission does not exist on the identity provider".to_string()
        }
        other => format!("sign-in failed ({other})"),
    };
    if detail.is_empty() {
        base
    } else {
        format!("{base}: {detail}")
    }
}

/// Open a URL in the user's default browser.
pub fn open_in_browser(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The empty "" is cmd's window-title argument. Omitting it makes cmd
        // treat a quoted URL as the title and open nothing at all.
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(0x0800_0000)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

// ── Authorization Code + PKCE ─────────────────────────────────────────────
//
// This exists because Logto's device flow does NOT attach API-resource scopes
// to the grant. Verified in the database: a device-code Grant carries only
// `openid.scope` and no `resources` key at all, while an authorization-code
// Grant from the same server carries `resources: {...}`. So `tunnel:connect`
// could never reach the access token over the device flow, no matter how the
// roles were configured.
//
// The loopback listener is confined to 127.0.0.1 and lives for one request, so
// it works identically on a locked-down network — nothing leaves the machine.

/// base64url without padding, per RFC 7636.
fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(T[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
        }
    }
    out
}

fn random_b64(len: usize) -> String {
    // ssh-key already brings a CSPRNG; reuse it rather than add another crate.
    use ssh_key::rand_core::RngCore;
    let mut buf = vec![0u8; len];
    ssh_key::rand_core::OsRng.fill_bytes(&mut buf);
    b64url(&buf)
}

fn percent(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

pub fn pkce() -> Pkce {
    use sha2::{Digest, Sha256};
    let verifier = random_b64(48);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
        state: random_b64(16),
    }
}

/// The URL to open in the browser.
pub fn authorize_url(settings: &OidcSettings, redirect_uri: &str, p: &Pkce) -> String {
    let mut url = format!(
        "{}/auth?client_id={}&response_type=code&redirect_uri={}&scope={}\
         &code_challenge={}&code_challenge_method=S256&state={}",
        settings.issuer.trim_end_matches('/'),
        percent(&settings.client_id),
        percent(redirect_uri),
        percent(&settings.scopes()),
        percent(&p.challenge),
        percent(&p.state),
    );
    if !settings.resource.trim().is_empty() {
        url.push_str(&format!("&resource={}", percent(settings.resource.trim())));
    }
    url
}

/// Wait on 127.0.0.1:`port` for the browser redirect and return the code.
///
/// Bound to the loopback interface and closed after one request. `state` is
/// checked because without it any local process could feed us a code.
pub fn await_code(
    port: u16,
    expect_state: &str,
    timeout_secs: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("cannot listen on 127.0.0.1:{port} for the sign-in reply: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure the sign-in listener: {e}"))?;

    let deadline = now() + timeout_secs;
    while now() < deadline {
        if cancelled() {
            return Err("sign-in cancelled".into());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();

                let target = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
                let mut code = String::new();
                let mut state = String::new();
                let mut err = String::new();
                // The description is the only part that says WHY. Dropping it
                // turned a one-line diagnosis into a round trip.
                let mut err_desc = String::new();
                for pair in query.split('&') {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    let v = v.replace('+', " ");
                    let v = percent_decode(&v);
                    match k {
                        "code" => code = v,
                        "state" => state = v,
                        "error" => err = v,
                        "error_description" => err_desc = v,
                        _ => {}
                    }
                }

                let ok = err.is_empty() && !code.is_empty() && state == expect_state;
                let body = if ok {
                    "<h2>Signed in</h2><p>You can close this tab and return to SplitTunnel.</p>"
                } else {
                    "<h2>Sign-in failed</h2><p>Return to SplitTunnel for the reason.</p>"
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
                let _ = stream.flush();

                if !err.is_empty() {
                    return Err(if err_desc.is_empty() {
                        format!("the identity provider refused: {err}")
                    } else {
                        format!("the identity provider refused: {err} — {err_desc}")
                    });
                }
                if code.is_empty() {
                    return Err("the browser came back without an authorization code".into());
                }
                if state != expect_state {
                    return Err("sign-in state mismatch — the reply did not match the request".into());
                }
                return Ok(code);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("sign-in listener failed: {e}")),
        }
    }
    Err("timed out waiting for the browser sign-in".into())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Exchange the authorization code for tokens.
pub fn exchange_code(
    agent: &ureq::Agent,
    settings: &OidcSettings,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", settings.client_id.as_str()),
        ("code_verifier", verifier),
    ];
    if !settings.resource.trim().is_empty() {
        form.push(("resource", settings.resource.trim()));
    }
    let v = post_form(agent, &settings.token_endpoint(), &form)?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(describe(err, &v));
    }
    Ok(into_tokens(v))
}
