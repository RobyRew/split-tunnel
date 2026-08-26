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
    pub key_path: String,
    pub autostart: bool,
    /// Off by default on purpose: it rewrites Spotify's prefs file.
    pub manage_spotify: bool,
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
}
