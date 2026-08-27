<div align="center">
  <img src="assets/logo.png" width="104" alt="SplitTunnel" />
  <h1>SplitTunnel</h1>
  <p><b>Route one Windows application through your own server. Leave everything else alone.</b></p>
</div>

---

SplitTunnel opens a SOCKS5 proxy on `127.0.0.1` that is carried over SSH to a
server you control. You point a single application at that proxy — Spotify, a
browser profile, a game launcher — and **only that application's traffic** takes
the detour. The rest of the machine keeps using its normal connection.

No system-wide VPN. No driver. No routing-table surgery. If the app dies, your
network is untouched.

```
                 ┌── everything else ─────────────▶ your normal connection
your PC ─────────┤
                 └── one app ──▶ 127.0.0.1:1080 ──▶ SSH ──▶ your VPS ──▶ internet
```

## Why SSH and not a bare SOCKS daemon

A plain SOCKS5 server (`microsocks`, `dante`) means **another open port and
unencrypted traffic on the wire**. An open SOCKS proxy is found by scanners
within days and abused as an open relay. SSH gives you an encrypted tunnel and
key-only authentication on a port you already run and already harden. On a
1 vCPU box the encryption cost for an audio stream is negligible.

> **Server setup lives in [`server/`](server/)** — docker-compose, multi-user
> keys, and an optional egress allowlist that restricts the tunnel to specific
> destinations. Clone the repo and you have both halves.

## Requirements

| | |
|---|---|
| Client | Windows 10 / 11 |
| Server | Any Linux host with SSH, ~10 MB RAM |
| Keys | An SSH keypair. PuTTY `.ppk` format, or a key already loaded in Pageant |

PuTTY does **not** need to be installed — `plink.exe` and `pageant.exe` are
bundled. If you already run Pageant for other tunnels, SplitTunnel reuses it
rather than starting a second agent.

---

## 1. Server setup

Full instructions, compose file and hardening scripts: **[`server/README.md`](server/README.md)**.

```bash
git clone https://github.com/RobyRew/split-tunnel
cd split-tunnel/server
cp /path/to/alice.pub pubkeys/alice.pub   # one .pub per person
docker compose up -d
sudo ufw allow 2223/tcp
```

Isolation is the point: a shell-less container means that if a key leaks, the
holder gets a TCP relay — **not an account on your host**. Each person gets
their own key file, so revoking one does not disturb the others.

**Optional, off by default:** an egress allowlist that limits the tunnel to
specific destinations (e.g. Spotify only), by UID, on IPv4 *and* IPv6. Useful
when sharing with someone else — a leaked key then cannot be used as a
general-purpose relay for abuse that would trace back to your IP.

<details><summary>The original compose, inline</summary>

```yaml
# /opt/split-tunnel/docker-compose.yml
services:
  tunnel:
    image: lscr.io/linuxserver/openssh-server:latest
    container_name: split-tunnel
    restart: unless-stopped
    network_mode: "host"          # see the note below
    environment:
      PUID: "1000"
      PGID: "1000"
      USER_NAME: "tunnel"
      PUBLIC_KEY: "ssh-ed25519 AAAA... your-key"
      PASSWORD_ACCESS: "false"
      SUDO_ACCESS: "false"
      LISTEN_PORT: "2223"
    volumes:
      - ./config:/config
    mem_limit: 64m
    security_opt: ["no-new-privileges:true"]
```

</details>

> **Why `network_mode: host`.** A normally published Docker port sits behind
> `ufw-docker`'s `DOCKER-USER` default-deny, whitelisted against a container IP
> that **changes** when the container is recreated. When it drifts, the port is
> silently blackholed. Host networking makes this a plain host port and a plain
> `ufw` rule, and the whole failure mode disappears.

Harden the container's sshd — this account forwards TCP and does nothing else:

```
# /opt/split-tunnel/config/sshd/sshd_config.d/99-tunnel.conf
PermitRootLogin no
PasswordAuthentication no
AllowTcpForwarding yes
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
MaxAuthTries 3
```

### Two firewalls will bite you

1. **The host firewall** (`ufw`, `firewalld`) — opened above.
2. **Your provider's edge firewall.** Hetzner, IONOS, OVH, AWS and others filter
   in front of the machine. If the port is open in `ufw`, `ss` shows sshd
   listening, and it still times out from outside — **it is the provider's
   firewall policy.** Add the port in their control panel.

Confirm which one is at fault:

```bash
ss -tlnp | grep 2223       # is sshd listening?
sudo ufw status | grep 2223 # is the host firewall open?
nc -vz your.server.ip 2223  # from OUTSIDE — fails here only => provider firewall
```

### Brute-force protection will lock you out

If the server runs `fail2ban` or CrowdSec, a reconnect loop with a bad key looks
exactly like an attack and bans your home IP in seconds — which presents as
"the tunnel randomly stopped working". **Test once by hand before enabling
auto-start**, and consider adding your IP to `ignoreip`.

---

## 2. Install the app

Download `SplitTunnel_x.y.z_x64-setup.exe` from [Releases](../../releases) and
run it. There are two ways to get access, and the app supports both.

### With a sign-in (if your server runs the enrollment service)

1. Type the **tunnel server** address, e.g. `tunnel.example.com`.
2. **Sign in.** A browser opens; log in with the account you were authorised
   with. If it does not open, the app shows a code and a URL to enter it at.
3. That is all. The app generates its own key, receives a short-lived
   certificate, and fills in the host, port, username and host key for you.

Your private key is created on your PC and never leaves it — only the public
half is sent. Access renews itself silently and expires on its own.

### With a key file

1. Fill in **Host**, **Port**, **User** under *Manual setup*.
2. Either leave **Private key** empty (uses a key already in Pageant) or point
   it at your `.ppk`.

Convert an OpenSSH key to `.ppk` with PuTTYgen: *Conversions → Import key →
Save private key*.

Either way: **Connect.** The pill turns green once a real SOCKS5 handshake
succeeds — not merely when the process starts.

## 3. Point Spotify at it

Spotify → **Settings** → **Proxy settings**:

| Field | Value |
|---|---|
| Proxy type | **SOCKS5** |
| Host | `127.0.0.1` |
| Port | `1080` |

**Fully quit Spotify and reopen it** — including the tray icon
(`taskkill /IM Spotify.exe /F`). Proxy settings are read only at startup.

SplitTunnel can write these settings for you (*Options → Manage Spotify's proxy
setting*). It is **off by default and experimental**: it edits Spotify's `prefs`
file, so it backs the file up first and restores it on disconnect.

> **Honest limits.** An app-level proxy is best-effort. Some components —
> autoupdate, DRM licensing, local device discovery — may still take the direct
> route, and you cannot control whether the app resolves DNS locally or through
> the proxy. This is split-tunnelling, not a privacy guarantee.

## 4. Verify

```powershell
# what the world sees through the tunnel
curl.exe --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
# ...versus your real address
curl.exe https://ifconfig.me
```

Different answers means it works.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Stuck on *Starting…* | Server unreachable. Check the **provider** firewall first |
| *Error: cannot start plink* | Reinstall, or install PuTTY — the app prefers a `plink.exe` on `PATH` |
| Connects, then reconnect-loops | Key not accepted, or brute-force protection banned you |
| Green, but the app is unaffected | The app wasn't fully restarted, or it ignores proxy settings |
| Works, then dies after sleep | Expected — the supervisor reconnects with backoff |

The **Environment** card shows which `plink.exe` is in use and whether your own
Pageant was detected.

## Security notes

- Nothing is baked into the binary. No server address ships with the app; the
  config lives in `%APPDATA%\com.robyrew.splittunnel\config.json`.
- Private keys are never read or stored by the app — `plink` and Pageant handle
  them.
- `plink.exe` / `pageant.exe` are downloaded **in CI** from the official PuTTY
  site and checksum-verified against the published sums. They are not committed.
- Auto-start uses a Scheduled Task, removed cleanly by the uninstaller.

## Build from source

```bash
rustup default stable
cargo install tauri-cli --version "^2.0" --locked
# place plink.exe + pageant.exe in src-tauri/bin/ (CI does this automatically)
cargo tauri build
```

Output: `src-tauri/target/release/bundle/nsis/`.

## Licence

MIT — see [LICENSE](LICENSE).
