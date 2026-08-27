# SplitTunnel — server setup

A shell-less SSH endpoint whose only job is `ssh -D` dynamic forwarding.
Containerised for isolation: **if a key leaks, the holder gets a TCP relay, not
an account on your host.**

Works on anything that runs Docker. ~10 MB RAM.

## 1. Start it

```bash
git clone https://github.com/RobyRew/split-tunnel
cd split-tunnel/server

# one .pub file per person — they generate their own, you never see a private key
cp /path/to/alice.pub pubkeys/alice.pub

docker compose up -d
```

## 2. Open the port — **both** firewalls

```bash
sudo ufw allow 2223/tcp        # or firewalld/nftables
```

> **The one that catches everyone out:** most providers (IONOS, Hetzner, OVH,
> AWS…) filter *in front of* the machine. If `ss -tlnp | grep 2223` shows sshd
> listening, `ufw` allows it, and it **still** times out from outside, it is the
> provider's firewall — add the port in their control panel.

## 3. Connect

```bash
ssh -N -D 127.0.0.1:1080 -p 2223 -i ~/.ssh/your_key tunnel@your.server
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me   # should print the server's IP
```

On Windows, use the [SplitTunnel app](../README.md) instead.

---

## Adding and removing people

Each `.pub` in `pubkeys/` is one authorised person.

```bash
cp bob.pub pubkeys/bob.pub && docker compose restart   # grant
rm pubkeys/bob.pub        && docker compose restart   # revoke
```

Revoking one person does not disturb anyone else, and the SSH log records the
key fingerprint per session, so activity stays attributable.

> **The real risk of sharing is not technical.** Their traffic leaves from
> **your** IP. If they do something abusive, it comes back to your server.
> Share only with people you trust — and consider the egress allowlist below.

---

## Optional: sign-in instead of key files

Everything above hands out access by copying a `.pub` into `pubkeys/`. That is
fine for one or two people. For a larger or less-trusted group, `enroll/` adds
an alternative: the user signs in to **your** identity provider (any OIDC one —
Logto, Keycloak, Authentik, Auth0) and the server signs a **12-hour SSH
certificate** for a key generated on their machine.

```
sign in (browser) ──▶ enroll service verifies the login
                      ssh-keygen -s CA ──▶ short-lived certificate
                                           │
sshd TrustedUserCAKeys ◀───────────────────┘   (no authorized_keys entry at all)
```

What it buys you:

| | `pubkeys/` | certificates |
|---|---|---|
| Onboarding | they send a key, you redeploy | they sign in |
| Expiry | never | built in, enforced by sshd |
| Audit | every key looks alike | sshd logs *which identity* opened each session |
| Revoking | delete the file, restart | remove their role at the IdP |

Requirements: an OIDC provider that supports the **device authorization grant**
(RFC 8628), and a TLS-terminating reverse proxy in front of the service.

Setup is in [`enroll/docker-compose.yml`](enroll/docker-compose.yml); the
certificate is signed `-O clear -O permit-port-forwarding`, so it carries no
pty, no agent forwarding and no X11 — it forwards TCP and nothing else.

The `pubkeys/` route keeps working alongside it, and is worth keeping as the
break-glass path for when your identity provider is the thing that is down.

## Optional: restrict the tunnel to specific destinations

**Disabled by default.** When enabled, the tunnel user may only reach the
resolved addresses of an allowlist of domains — so a leaked key cannot be used
as a general-purpose relay for spam, scanning or anything else that would come
back to your IP.

```bash
sudo apt install -y ipset
sudo install -d /opt/split-tunnel/egress /etc/split-tunnel
sudo cp egress/split-tunnel-egress.sh /opt/split-tunnel/egress/
sudo cp egress/egress.conf.example /etc/split-tunnel/egress.conf
sudo cp egress/split-tunnel-egress.{service,timer} /etc/systemd/system/

sudo sed -i 's/^ENABLED=no/ENABLED=yes/' /etc/split-tunnel/egress.conf
sudo systemctl daemon-reload
sudo systemctl enable --now split-tunnel-egress.timer
```

How it works, and why it is built this way:

- **Filters by UID**, so only the tunnel user is affected — nothing else on the
  host is touched. That is why `PUID` is `8022` and not `1000`: `1000` is
  usually your own login user.
- **IPv4 *and* IPv6.** A dual-stack host will happily reach a CDN over IPv6, so
  an IPv4-only allowlist enforces nothing at all.
- **Resolves names on a timer** instead of pinning IPs, because streaming CDNs
  rotate addresses constantly. Entries carry a TTL and age out on their own.
- **`ESTABLISHED` is allowed first**, or the rules would sever the tunnel's own
  SSH session to the client.

### How the allowlist keeps up with Spotify's CDNs

A fixed list of IPs — or even of hostnames — cannot work here. Audio and artwork
come from `*.scdn.co`, `*.spotifycdn.com` and Akamai/Fastly hostnames that
rotate constantly and differ by region. Any static list leaves gaps, and a gap
means music that stops playing.

So the allowlist populates **itself**. A dedicated `dnsmasq` resolves for the
container only, and every address it returns for a Spotify domain **and all its
subdomains** is written straight into the ipset at lookup time:

```
ipset=/spotify.com/scdn.co/pscdn.co/spotifycdn.com/.../splittunnel-allow4,splittunnel-allow6
```

Install it alongside the allowlist:

```bash
sudo apt install -y dnsmasq
sudo cp dns/split-tunnel-dns.conf /etc/dnsmasq.d/
sudo install -d /etc/systemd/system/dnsmasq.service.d
sudo cp dns/dnsmasq-ipsets.conf /etc/systemd/system/dnsmasq.service.d/
sudo systemctl daemon-reload && sudo systemctl restart dnsmasq
```

Two details that will bite you otherwise:

- It listens on **127.0.0.1:53**, not a high port — `resolv.conf` has no syntax
  for a port. That address is free because systemd-resolved binds `127.0.0.53`
  and `127.0.0.54`, so nothing conflicts.
- ipsets live in the kernel and **vanish on reboot**, and dnsmasq refuses to
  start when a set named in `ipset=` is missing. The systemd drop-in creates
  them in `ExecStartPre`, so the resolver survives a restart.

> ⚠️ **Still worth watching.** If something breaks, rejections are logged
> rate-limited, so you can see exactly what to add:
>
> ```bash
> sudo journalctl -k -g SPLITTUNNEL-DROP --since -10min
> ```
>
> Add the domain to `DOMAINS` in `/etc/split-tunnel/egress.conf`, then
> `sudo systemctl start split-tunnel-egress.service`.

Turn it off at any time — this removes the rules cleanly:

```bash
sudo sed -i 's/^ENABLED=yes/ENABLED=no/' /etc/split-tunnel/egress.conf
sudo systemctl start split-tunnel-egress.service
```

## Hardening notes

- `AllowTcpForwarding` is forced **on** by `custom-cont-init.d/`, because the
  base image ships it **off** — which silently breaks the only thing this
  container does. Login succeeds, the SOCKS listener opens, and every channel
  dies with `administratively prohibited`.
- That script patches `/config/sshd/sshd_config`, **not** `/etc/ssh/sshd_config`
  — sshd here runs with `-f`, so patching the obvious file changes nothing.
- Password auth, root login, agent forwarding, X11 and TTY are all off.
- `network_mode: host` avoids Docker's `DOCKER-USER` default-deny chain, whose
  container-IP whitelist drifts on recreate and silently blackholes the port.

## Brute-force protection will lock you out

If the host runs fail2ban or CrowdSec, a client reconnect loop with a bad key
looks exactly like an attack and bans the client's IP within seconds — which
presents as "the tunnel randomly stopped working". Test by hand once before
enabling any auto-start, and consider adding your own IP to `ignoreip`.
