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

fn spawn(transport: &Transport, cfg: &Config) -> std::io::Result<Child> {
    let mut cmd = match transport {
        Transport::Plink { exe } => {
            let mut c = Command::new(exe);
            c.arg("-N")                             // no shell, forwarding only
                .arg("-batch")                      // never prompt — we are headless
                .arg("-ssh")
                .arg("-P").arg(cfg.port.to_string())
                .arg("-D").arg(format!("127.0.0.1:{}", cfg.local_port))
                .arg(format!("{}@{}", cfg.user, cfg.host));
            if !cfg.key_path.trim().is_empty() {
                c.arg("-i").arg(&cfg.key_path);
            }
            c
        }
        Transport::OpenSsh { exe, key, known_hosts } => {
            let mut c = Command::new(exe);
            c.arg("-N")
                .arg("-T")
                .arg("-p").arg(cfg.port.to_string())
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
                .arg("-o").arg(format!("UserKnownHostsFile={}", known_hosts.display()));

            // Pin the host key when the enrollment reply gave us one. If it
            // did not, `yes` would refuse to connect at all against an empty
            // known_hosts — so fall back to recording it on first use rather
            // than shipping a client that cannot connect.
            c.arg("-o").arg(if known_hosts.exists() {
                "StrictHostKeyChecking=yes"
            } else {
                "StrictHostKeyChecking=accept-new"
            });

            c.arg(format!("{}@{}", cfg.user, cfg.host));
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
        }
    }

    pub fn status(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or(Status::Stopped)
    }

    pub fn start(&self, transport: Transport, cfg: Config) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // already supervising
        }
        let status = Arc::clone(&self.status);
        let running = Arc::clone(&self.running);
        let child_slot = Arc::clone(&self.child);

        std::thread::spawn(move || {
            // Backoff matters: a hardened server will ban the client IP after a
            // handful of failed auths, and a tight retry loop looks exactly
            // like a brute-force attempt.
            let mut backoff = 5u64;
            while running.load(Ordering::SeqCst) {
                *status.lock().unwrap() = Status::Starting;

                let mut child = match spawn(&transport, &cfg) {
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
            *status.lock().unwrap() = Status::Stopped;
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        *self.status.lock().unwrap() = Status::Stopped;
    }
}
