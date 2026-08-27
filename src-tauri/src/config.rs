use crate::auth::OidcSettings;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Everything the user configures. Nothing here is baked into the binary —
/// the app ships with no server address, so the published build contains no
/// personal infrastructure details.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Local SOCKS5 listener the target app points at.
    pub local_port: u16,
    /// PuTTY .ppk. Empty means "use whatever key Pageant already holds",
    /// which is the normal case when Pageant is running for other tunnels.
    /// Only consulted on the manual (non-sign-in) path.
    pub key_path: String,
    pub autostart: bool,
    /// Off by default on purpose: it rewrites Spotify's prefs file.
    pub manage_spotify: bool,

    /// Base URL of the enrollment service, e.g. https://tunnel.example.com
    ///
    /// This is the ONLY thing a new user has to type. Everything else —
    /// identity provider, client id, server host, port, username, host key —
    /// is fetched from it or handed back when a certificate is issued.
    pub enroll_base: String,
    /// Cached from `<enroll_base>/config` so a sign-in can start offline-ish
    /// and so the UI can show which provider it will use.
    pub oidc: OidcSettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 2223,
            user: "tunnel".into(),
            local_port: 1080,
            key_path: String::new(),
            autostart: false,
            manage_spotify: false,
            enroll_base: String::new(),
            oidc: OidcSettings::default(),
        }
    }
}

impl Config {
    pub fn path(dir: &PathBuf) -> PathBuf {
        dir.join("config.json")
    }

    pub fn load(dir: &PathBuf) -> Self {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &PathBuf) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(dir), body).map_err(|e| e.to_string())
    }

    /// Enough to attempt a connection.
    pub fn is_complete(&self) -> bool {
        !self.host.trim().is_empty() && !self.user.trim().is_empty() && self.port > 0
    }

    /// Normalised base URL with any trailing slash removed, so joining paths
    /// never produces a double slash the router will not match.
    pub fn enroll_base_url(&self) -> String {
        let b = self.enroll_base.trim().trim_end_matches('/');
        if b.is_empty() {
            return String::new();
        }
        if b.starts_with("http://") || b.starts_with("https://") {
            b.to_string()
        } else {
            // Plain hostname typed in. HTTPS is not negotiable here: the
            // enrollment reply carries the host key we are about to pin.
            format!("https://{b}")
        }
    }

    pub fn enroll_url(&self) -> String {
        let b = self.enroll_base_url();
        if b.is_empty() {
            String::new()
        } else {
            format!("{b}/enroll")
        }
    }

    pub fn discovery_url(&self) -> String {
        let b = self.enroll_base_url();
        if b.is_empty() {
            String::new()
        } else {
            format!("{b}/config")
        }
    }
}
