//! Supervises the plink child process and reports honest status.
//!
//! "Is the process alive" is not good enough: plink can sit there with a dead
//! forwarding channel. So health is proven by completing a real SOCKS5
//! handshake against the local listener.

use serde::Serialize;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Config;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "state", content = "detail")]
pub enum Status {
    Stopped,
    Starting,
    Connected,
    Reconnecting(String),
    Error(String),
}

pub struct Supervisor {
    pub status: Arc<Mutex<Status>>,
    running: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    /// The wstunnel process, when the relay is in use. Held separately because
    /// it outlives individual ssh restarts — tearing the WebSocket down and
    /// rebuilding it on every ssh retry would be slow and pointless.
    relay_child: Arc<Mutex<Option<Child>>>,
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Which SSH client carries the tunnel.
///
/// Certificates use Windows' own OpenSSH rather than plink for a concrete
/// reason: plink reads keys only in PuTTY's `.ppk` format, so the certificate
/// path would need a PPK serialiser here for no benefit. OpenSSH ships in
/// Windows 10 1809 and later, understands certificates natively, and finds
/// `<key>-cert.pub` on its own.
#[derive(Clone, Debug)]
pub enum Transport {
    /// Manual key, via bundled or installed PuTTY. Uses Pageant when loaded.
    Plink { exe: PathBuf },
    /// Certificate issued by the enrollment service.
    OpenSsh {
        exe: PathBuf,
        key: PathBuf,
        known_hosts: PathBuf,
    },
}

/// A wstunnel relay: carries the SSH connection inside a WebSocket on 443.
///
/// Needed because a managed network proxies HTTPS and drops direct TCP. A
/// proxy will forward a WebSocket to 443; it will never forward raw SSH to
/// 2223. The relay makes the transport look like ordinary web traffic.
#[derive(Clone, Debug)]
pub struct Relay {
    pub exe: PathBuf,
    /// e.g. wss://tunnel.example.com
    pub ws_url: String,
    pub path_prefix: String,
    /// What the far end should connect to, e.g. "198.51.100.10:2223".
    pub target: String,
    /// Local port ssh will dial instead of the real server.
    pub local_port: u16,
    /// HTTP proxy to reach the relay through. Empty means direct.
    pub proxy: String,
}

impl Relay {
    /// Build a relay from the URL the server advertised.
    ///
    /// wstunnel wants the server origin and the path prefix as SEPARATE
    /// arguments, so "wss://host/ws" has to be taken apart: passing the full
    /// URL as the server address makes the handshake 404 at the reverse proxy.
    pub fn new(exe: PathBuf, ws_url: &str, target: &str, local_port: u16, proxy: &str) -> Self {
        let trimmed = ws_url.trim().trim_end_matches('/');
        let (origin, prefix) = match trimmed.find("://") {
            Some(i) => {
                let (scheme, rest) = trimmed.split_at(i + 3);
                match rest.find('/') {
                    Some(j) => (
                        format!("{scheme}{}", &rest[..j]),
                        rest[j + 1..].trim_matches('/').to_string(),
                    ),
                    None => (trimmed.to_string(), String::new()),
                }
            }
            None => (trimmed.to_string(), String::new()),
        };
        Self {
            exe,
            ws_url: origin,
            path_prefix: if prefix.is_empty() { "ws".into() } else { prefix },
            target: target.to_string(),
            local_port,
            proxy: proxy.to_string(),
        }
    }
}

fn spawn_relay(relay: &Relay) -> std::io::Result<Child> {
    let mut cmd = Command::new(&relay.exe);
    cmd.arg("client")
        .arg("-L")
        .arg(format!(
            "tcp://127.0.0.1:{}:{}",
            relay.local_port, relay.target
        ))
        .arg("-P")
        .arg(&relay.path_prefix)
        .arg("--log-lvl")
        .arg("INFO");
    if !relay.proxy.trim().is_empty() {
        // wstunnel wants USER:PASS@HOST:PORT without a scheme.
        let p = relay
            .proxy
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        cmd.arg("--http-proxy").arg(p);
    }
    cmd.arg(&relay.ws_url);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn()
}

/// Is a plain TCP connection to this endpoint possible? Decides whether the
/// relay is needed at all.
pub fn tcp_reachable(host: &str, port: u16, secs: u64) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|a| TcpStream::connect_timeout(&a, Duration::from_secs(secs)).is_ok())
}

/// Locate the OpenSSH client that ships with Windows.
pub fn openssh_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let p = PathBuf::from(&root).join("System32\\OpenSSH\\ssh.exe");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("ssh")
}

fn spawn(
    transport: &Transport,
    cfg: &Config,
    host: &str,
    port: u16,
) -> std::io::Result<Child> {
    let mut cmd = match transport {
        Transport::Plink { exe } => {
            let mut c = Command::new(exe);
            c.arg("-N")                             // no shell, forwarding only
                .arg("-batch")                      // never prompt — we are headless
                .arg("-ssh")
                .arg("-P").arg(port.to_string())
                .arg("-D").arg(format!("127.0.0.1:{}", cfg.local_port))
                .arg(format!("{}@{}", cfg.user, host));
            if !cfg.key_path.trim().is_empty() {
                c.arg("-i").arg(&cfg.key_path);
            }
            c
        }
        Transport::OpenSsh { exe, key, known_hosts } => {
            let mut c = Command::new(exe);
            c.arg("-N")
                .arg("-T")
                .arg("-p").arg(port.to_string())
                .arg("-D").arg(format!("127.0.0.1:{}", cfg.local_port))
                .arg("-i").arg(key)
                // Offer ONLY this key. Without it ssh walks every key in the
                // agent and in ~/.ssh first, and the server's MaxAuthTries 3
                // disconnects before our certificate is ever tried.
                .arg("-o").arg("IdentitiesOnly=yes")
                .arg("-o").arg("IdentityAgent=none")
                .arg("-o").arg("BatchMode=yes")
                // Fail loudly if the forward cannot be established, instead of
                // sitting there connected with a dead SOCKS port.
                .arg("-o").arg("ExitOnForwardFailure=yes")
                .arg("-o").arg("ServerAliveInterval=30")
                .arg("-o").arg("ServerAliveCountMax=3")
                .arg("-o").arg(format!("UserKnownHostsFile={}", known_hosts.display()))
                // The pinned key is stored under a fixed alias, so it matches
                // whether we dial the server directly or 127.0.0.1 via the relay.
                .arg("-o").arg(format!("HostKeyAlias={}", crate::enroll::HOST_ALIAS));

            // Pin the host key when the enrollment reply gave us one. If it
            // did not, `yes` would refuse to connect at all against an empty
            // known_hosts — so fall back to recording it on first use rather
            // than shipping a client that cannot connect.
            c.arg("-o").arg(if known_hosts.exists() {
                "StrictHostKeyChecking=yes"
            } else {
                "StrictHostKeyChecking=accept-new"
            });

            c.arg(format!("{}@{}", cfg.user, host));
            c
        }
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn()
}

/// Complete a SOCKS5 no-auth handshake. Proves the tunnel actually forwards,
/// not merely that a process exists.
pub fn socks_healthy(port: u16) -> bool {
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(1500)));
    if s.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut buf = [0u8; 2];
    let ok = s.read_exact(&mut buf).is_ok() && buf[0] == 0x05;
    let _ = s.shutdown(Shutdown::Both);
    ok
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(Status::Stopped)),
            running: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
            relay_child: Arc::new(Mutex::new(None)),
        }
    }

    pub fn status(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or(Status::Stopped)
    }

    pub fn start(&self, transport: Transport, cfg: Config, relay: Option<Relay>) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // already supervising
        }
        let status = Arc::clone(&self.status);
        let running = Arc::clone(&self.running);
        let child_slot = Arc::clone(&self.child);
        let relay_slot = Arc::clone(&self.relay_child);

        std::thread::spawn(move || {
            // Backoff matters: a hardened server will ban the client IP after a
            // handful of failed auths, and a tight retry loop looks exactly
            // like a brute-force attempt.
            let mut backoff = 5u64;

            // Where ssh should actually dial. With a relay that is a local
            // port; without one it is the server itself.
            let (host, port) = match &relay {
                Some(r) => ("127.0.0.1".to_string(), r.local_port),
                None => (cfg.host.clone(), cfg.port),
            };

            while running.load(Ordering::SeqCst) {
                *status.lock().unwrap() = Status::Starting;

                // Bring the WebSocket up first, and only if it is not already
                // running from a previous iteration.
                if let Some(r) = &relay {
                    let need = relay_slot
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|c| matches!(c.try_wait(), Ok(Some(_))))
                        .unwrap_or(true);
                    if need {
                        match spawn_relay(r) {
                            Ok(c) => *relay_slot.lock().unwrap() = Some(c),
                            Err(e) => {
                                *status.lock().unwrap() =
                                    Status::Error(format!("cannot start the relay: {e}"));
                                running.store(false, Ordering::SeqCst);
                                return;
                            }
                        }
                        // Wait for its local listener before ssh dials it,
                        // otherwise the first attempt always fails.
                        let mut up = false;
                        for _ in 0..30 {
                            if !running.load(Ordering::SeqCst) {
                                break;
                            }
                            if tcp_reachable("127.0.0.1", r.local_port, 1) {
                                up = true;
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(400));
                        }
                        if !up {
                            *status.lock().unwrap() = Status::Reconnecting(
                                "the WebSocket relay did not come up".into(),
                            );
                        }
                    }
                }

                let mut child = match spawn(&transport, &cfg, &host, port) {
                    Ok(c) => c,
                    Err(e) => {
                        let what = match &transport {
                            Transport::Plink { .. } => "plink",
                            Transport::OpenSsh { .. } => "ssh",
                        };
                        *status.lock().unwrap() =
                            Status::Error(format!("cannot start {what}: {e}"));
                        running.store(false, Ordering::SeqCst);
                        return;
                    }
                };

                // Give the forward up to ~15s to come up.
                let mut up = false;
                for _ in 0..30 {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    if socks_healthy(cfg.local_port) {
                        up = true;
                        break;
                    }
                    if let Ok(Some(_)) = child.try_wait() {
                        break; // died during startup
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }

                if up {
                    backoff = 5;
                    *status.lock().unwrap() = Status::Connected;
                    *child_slot.lock().unwrap() = Some(child);

                    // Watch it. Poll the SOCKS port too, so a half-dead
                    // forwarding channel is detected rather than trusted.
                    loop {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(5));
                        let dead = {
                            let mut guard = child_slot.lock().unwrap();
                            match guard.as_mut() {
                                Some(c) => matches!(c.try_wait(), Ok(Some(_))),
                                None => true,
                            }
                        };
                        if dead || !socks_healthy(cfg.local_port) {
                            break;
                        }
                    }
                    if let Some(mut c) = child_slot.lock().unwrap().take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                } else {
                    let _ = child.kill();
                    let _ = child.wait();
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }
                *status.lock().unwrap() =
                    Status::Reconnecting(format!("retrying in {backoff}s"));
                for _ in 0..backoff {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                backoff = (backoff * 2).min(60);
            }
            if let Some(mut c) = relay_slot.lock().unwrap().take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            *status.lock().unwrap() = Status::Stopped;
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // The relay is a child process of ours; leaving it running would hold
        // the local port and make the next start fail.
        if let Some(mut c) = self.relay_child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        *self.status.lock().unwrap() = Status::Stopped;
    }
}

/// A process currently holding connections to the local SOCKS listener.
#[derive(Serialize, Clone, Debug)]
pub struct ClientApp {
    pub name: String,
    pub pid: u32,
    pub connections: u32,
}

/// Which applications are actually using the tunnel right now.
///
/// There is no OS-wide register of "apps configured for a SOCKS proxy" —
/// SOCKS is per-application configuration, not a system setting, so the
/// question can only be answered by observation. What CAN be seen is who holds
/// an established connection to our listener, which is the useful half anyway:
/// it answers "is Spotify actually going through this?" rather than "was
/// Spotify configured at some point?".
#[cfg(windows)]
pub fn connected_apps(local_port: u16) -> Vec<ClientApp> {
    use std::collections::HashMap;
    use std::os::windows::process::CommandExt;

    let out = match std::process::Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    // Count established connections whose REMOTE end is our listener; the
    // listener's own accepted sockets appear with it as the local end, which
    // would count the tunnel process itself rather than its clients.
    let needle = format!("127.0.0.1:{local_port}");
    let mut by_pid: HashMap<u32, u32> = HashMap::new();
    for line in out.lines() {
        if !line.contains("ESTABLISHED") {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[2] != needle {
            continue;
        }
        if let Ok(pid) = f[4].parse::<u32>() {
            *by_pid.entry(pid).or_insert(0) += 1;
        }
    }
    if by_pid.is_empty() {
        return Vec::new();
    }

    let tasks = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let mut names: HashMap<u32, String> = HashMap::new();
    for line in tasks.lines() {
        let cols: Vec<&str> = line.split("\",\"").collect();
        if cols.len() < 2 {
            continue;
        }
        let name = cols[0].trim_matches('"').to_string();
        if let Ok(pid) = cols[1].trim_matches('"').trim().parse::<u32>() {
            names.insert(pid, name);
        }
    }

    let mut apps: Vec<ClientApp> = by_pid
        .into_iter()
        .map(|(pid, connections)| ClientApp {
            name: names.get(&pid).cloned().unwrap_or_else(|| format!("PID {pid}")),
            pid,
            connections,
        })
        .collect();
    apps.sort_by(|a, b| b.connections.cmp(&a.connections));
    apps
}

#[cfg(not(windows))]
pub fn connected_apps(_local_port: u16) -> Vec<ClientApp> {
    Vec::new()
}
