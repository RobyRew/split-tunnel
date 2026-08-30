//! Turns a signed-in session into an SSH certificate.
//!
//! The private key is generated here and never leaves this machine. Only the
//! public half is sent, and what comes back is a certificate that expires on
//! its own — so a stolen copy is worth hours, not forever.
//!
//! Files written next to the config (`%APPDATA%\..\SplitStream\`):
//!   id_ed25519           private key      (never transmitted)
//!   id_ed25519.pub       public key
//!   id_ed25519-cert.pub  the certificate  — OpenSSH finds this by NAME,
//!                        purely because it sits beside the private key
//!   known_hosts          the server's host key, pinned from the enrol reply

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Tokens;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Enrollment {
    pub identity: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_fingerprint: String,
    /// Unix seconds at which the certificate stops being accepted.
    pub expires_at: u64,
    pub serial: u64,
    /// WebSocket relay, when the server offers one. Lets the tunnel survive a
    /// network that proxies HTTPS and drops direct TCP to the tunnel port.
    pub ws_url: String,
    pub ws_target: String,
}

impl Enrollment {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("enrollment.json")
    }
    pub fn load(dir: &Path) -> Option<Self> {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(dir), body).map_err(|e| e.to_string())
    }
    /// True when the certificate is close enough to expiry that we should get
    /// a new one. Two hours of slack means a normal listening session never
    /// hits a mid-song reconnect.
    pub fn needs_renewal(&self) -> bool {
        now() + 7200 >= self.expires_at
    }
    pub fn is_valid(&self) -> bool {
        self.expires_at > now()
    }
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("id_ed25519")
}
pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join("id_ed25519-cert.pub")
}
pub fn known_hosts_path(dir: &Path) -> PathBuf {
    dir.join("known_hosts")
}

/// The name the server's host key is pinned under. Constant so that the entry
/// matches whether we connect directly or through the relay.
pub const HOST_ALIAS: &str = "splitstream-server";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate a fresh ed25519 keypair, replacing any existing one.
///
/// A new key every enrolment is deliberate. It costs nothing, and it means a
/// key that leaked while a certificate was live cannot be reused with the next
/// certificate.
fn generate_key(dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;

    let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
        .map_err(|e| format!("key generation failed: {e}"))?;

    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("cannot encode private key: {e}"))?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("cannot encode public key: {e}"))?;

    let kp = key_path(dir);
    // Remove first: on Windows a rewrite keeps the original ACL, and a stale
    // certificate beside a new key produces a baffling auth failure.
    let _ = std::fs::remove_file(&kp);
    let _ = std::fs::remove_file(cert_path(dir));
    std::fs::write(&kp, private.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("id_ed25519.pub"), format!("{public}\n")).map_err(|e| e.to_string())?;

    restrict(&kp)?;
    Ok(public)
}

/// OpenSSH refuses to use a private key that other accounts can read. On
/// Windows that check is an ACL check, not a mode check, so `icacls` is the
/// only thing that satisfies it.
#[cfg(windows)]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let p = path.display().to_string();
    let user = std::env::var("USERNAME").unwrap_or_default();
    let grant = if user.is_empty() {
        "%USERNAME%:F".to_string()
    } else {
        format!("{user}:F")
    };
    let out = std::process::Command::new("icacls")
        .args([&p, "/inheritance:r", "/grant:r", &grant])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| format!("icacls failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "could not restrict {p}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())
}

/// Generate a key, exchange it for a certificate, and write everything out.
pub fn enroll(
    agent: &ureq::Agent,
    dir: &Path,
    enroll_url: &str,
    tokens: &Tokens,
) -> Result<Enrollment, String> {
    if enroll_url.trim().is_empty() {
        return Err("No enrollment URL configured.".into());
    }
    let public = generate_key(dir)?;

    let body = serde_json::json!({
        "id_token": tokens.id_token,
        "public_key": public,
    });

    let resp = agent
        .post(enroll_url.trim())
        .set("Authorization", &format!("Bearer {}", tokens.access_token))
        .send_json(body);

    let value: serde_json::Value = match resp {
        Ok(r) => r.into_json().map_err(|e| format!("bad response: {e}"))?,
        Err(ureq::Error::Status(code, r)) => {
            // The service explains itself in `error`; surfacing that verbatim
            // is the difference between "403" and "you lack the tunnel role".
            let detail = r
                .into_json::<serde_json::Value>()
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
                .unwrap_or_else(|| format!("HTTP {code}"));
            return Err(detail);
        }
        Err(e) => return Err(format!("cannot reach the enrollment service: {e}")),
    };

    let certificate = value
        .get("certificate")
        .and_then(|c| c.as_str())
        .ok_or("the enrollment service returned no certificate")?;
    if !certificate.contains("cert-v01@openssh.com") {
        return Err("the enrollment service returned something that is not a certificate".into());
    }
    std::fs::write(cert_path(dir), format!("{certificate}\n")).map_err(|e| e.to_string())?;

    let tunnel = value.get("tunnel").cloned().unwrap_or_default();
    let s = |v: &serde_json::Value, k: &str| {
        v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };

    // Pin the host key. Without this the first connection is trust-on-first-use,
    // which is exactly the moment a hostile network would want to intervene.
    let host = s(&tunnel, "host");
    let port = tunnel.get("port").and_then(|p| p.as_u64()).unwrap_or(2223) as u16;
    let host_key = s(&tunnel, "host_key");
    if !host_key.is_empty() {
        // Recorded under a FIXED alias rather than host:port. Through the
        // WebSocket relay ssh dials 127.0.0.1 on an arbitrary local port, and
        // a host:port-keyed entry would never match; `HostKeyAlias` makes the
        // same pinned key valid on both paths.
        std::fs::write(known_hosts_path(dir), format!("{HOST_ALIAS} {host_key}\n"))
            .map_err(|e| e.to_string())?;
    }

    let record = Enrollment {
        identity: s(&value, "identity"),
        host,
        port,
        user: {
            let u = s(&tunnel, "user");
            if u.is_empty() { "tunnel".into() } else { u }
        },
        host_fingerprint: s(&tunnel, "host_fingerprint"),
        ws_url: s(&tunnel, "ws_url"),
        ws_target: s(&tunnel, "ws_target"),
        expires_at: value
            .get("expires_at")
            .and_then(|x| x.as_u64())
            .unwrap_or_else(|| now() + 43200),
        serial: value.get("serial").and_then(|x| x.as_u64()).unwrap_or(0),
    };
    record.save(dir)?;
    Ok(record)
}

/// Delete every credential this machine holds. Used by "Sign out".
pub fn clear(dir: &Path) {
    for f in [
        key_path(dir),
        cert_path(dir),
        known_hosts_path(dir),
        dir.join("id_ed25519.pub"),
        Enrollment::path(dir),
    ] {
        let _ = std::fs::remove_file(f);
    }
}
