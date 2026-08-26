//! Optional: point Spotify's own SOCKS5 setting at our local listener.
//!
//! EXPERIMENTAL and off by default. Spotify stores preferences as a flat
//! key=value file and the numeric proxy-mode mapping is not documented, so the
//! original file is backed up before any write and can be restored.

use std::path::PathBuf;

/// Observed mapping. Verify before trusting: if Spotify shows the wrong proxy
/// type after applying, correct this value.
const MODE_SOCKS5: &str = "3";

pub fn prefs_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Spotify").join("prefs"))
}

fn set_key(body: &str, key: &str, value: &str) -> String {
    let mut seen = false;
    let mut out: Vec<String> = body
        .lines()
        .map(|l| {
            if l.split('=').next().map(str::trim) == Some(key) {
                seen = true;
                format!("{key}={value}")
            } else {
                l.to_string()
            }
        })
        .collect();
    if !seen {
        out.push(format!("{key}={value}"));
    }
    out.join("\n")
}

/// Returns the backup path so the caller can tell the user what was touched.
pub fn apply(local_port: u16) -> Result<PathBuf, String> {
    let p = prefs_path().ok_or("APPDATA not set")?;
    if !p.exists() {
        return Err(format!("Spotify prefs not found at {}", p.display()));
    }
    let backup = p.with_extension("splittunnel.bak");
    if !backup.exists() {
        std::fs::copy(&p, &backup).map_err(|e| e.to_string())?;
    }
    let body = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let body = set_key(&body, "network.proxy.mode", MODE_SOCKS5);
    let body = set_key(&body, "network.proxy.address", "127.0.0.1");
    let body = set_key(&body, "network.proxy.port", &local_port.to_string());
    std::fs::write(&p, body).map_err(|e| e.to_string())?;
    Ok(backup)
}

pub fn restore() -> Result<(), String> {
    let p = prefs_path().ok_or("APPDATA not set")?;
    let backup = p.with_extension("splittunnel.bak");
    if backup.exists() {
        std::fs::copy(&backup, &p).map_err(|e| e.to_string())?;
    }
    Ok(())
}
