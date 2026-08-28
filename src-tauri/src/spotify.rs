//! Point Spotify's own proxy setting at our local SOCKS listener.
//!
//! Spotify keeps preferences in a flat `key=value` file, and the exact shape
//! was taken from a working installation rather than guessed — see MODE_PROXY.
//! Spotify silently ignores keys it does not recognise and unquoted strings, so
//! a wrong guess looks exactly like the feature doing nothing.
//!
//! This module therefore READS THE FILE BACK and reports what Spotify is
//! actually configured with. The first attempt did check itself, but against
//! its own wrong expectation, which is worse than not checking at all.
//!
//! Spotify reads prefs only at startup. Changing them while it runs has no
//! effect until it is fully quit — not just closed to the tray.

use serde::Serialize;
use std::path::PathBuf;

/// Taken from a working installation rather than guessed. Spotify stores the
/// whole endpoint in ONE key:
///
///     network.proxy.addr="127.0.0.1:1080@socks5"
///     network.proxy.mode=4
///
/// There is no `network.proxy.port` key at all, and the mode for a manual
/// SOCKS5 proxy is 4. The first version wrote mode 3, a bare address and a
/// separate port — and then "verified" the result against its own wrong
/// expectation, which is worse than not checking.
pub const MODE_PROXY: i32 = 4;
pub const MODE_NONE: i32 = 0;

#[derive(Serialize, Clone, Debug, Default)]
pub struct SpotifyState {
    /// Whether a prefs file was found at all.
    pub found: bool,
    pub path: String,
    pub mode: i32,
    pub addr: String,
    pub port: u16,
    /// True when Spotify is pointed at our listener right now.
    pub points_at_us: bool,
    /// True when Spotify is running, in which case prefs changes do nothing
    /// until it is fully quit.
    pub running: bool,
}

pub fn prefs_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Spotify").join("prefs"))
}

fn get_key(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let (k, v) = line.split_once('=')?;
        if k.trim() == key {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
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

#[cfg(windows)]
pub fn is_running() -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq Spotify.exe", "/NH"])
        .creation_flags(0x0800_0000)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Spotify.exe"))
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub fn is_running() -> bool {
    false
}

/// Read back what Spotify is actually configured with.
pub fn state(local_port: u16) -> SpotifyState {
    let Some(p) = prefs_path() else {
        return SpotifyState::default();
    };
    let mut s = SpotifyState {
        path: p.display().to_string(),
        running: is_running(),
        ..Default::default()
    };
    let Ok(body) = std::fs::read_to_string(&p) else {
        return s;
    };
    s.found = true;
    s.mode = get_key(&body, "network.proxy.mode")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    s.addr = get_key(&body, "network.proxy.addr").unwrap_or_default();
    // "127.0.0.1:1080@socks5" — split off the scheme, then the port.
    let (hostport, scheme) = match s.addr.split_once('@') {
        Some((hp, sc)) => (hp.to_string(), sc.to_string()),
        None => (s.addr.clone(), String::new()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
        None => (hostport.clone(), 0),
    };
    s.port = port;
    s.points_at_us = s.mode == MODE_PROXY
        && port == local_port
        && scheme.eq_ignore_ascii_case("socks5")
        && (host == "127.0.0.1" || host == "localhost");
    s
}

/// Point Spotify at our listener. Returns the state read back afterwards, so
/// the caller can report what Spotify will actually use rather than assuming.
pub fn apply(local_port: u16) -> Result<SpotifyState, String> {
    let p = prefs_path().ok_or("APPDATA is not set")?;
    if !p.exists() {
        return Err(format!(
            "Spotify's settings file was not found at {}. Open Spotify once, then try again.",
            p.display()
        ));
    }
    let backup = p.with_extension("splittunnel.bak");
    if !backup.exists() {
        std::fs::copy(&p, &backup).map_err(|e| e.to_string())?;
    }
    let body = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let body = set_key(&body, "network.proxy.mode", &MODE_PROXY.to_string());
    // One key carries host, port and scheme, and it must be quoted.
    let body = set_key(
        &body,
        "network.proxy.addr",
        &format!("\"127.0.0.1:{local_port}@socks5\""),
    );
    std::fs::write(&p, body).map_err(|e| e.to_string())?;
    Ok(state(local_port))
}

/// Put the proxy mode back to "no proxy", leaving the rest of prefs alone.
pub fn restore() -> Result<(), String> {
    let p = prefs_path().ok_or("APPDATA is not set")?;
    if !p.exists() {
        return Ok(());
    }
    let body = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let body = set_key(&body, "network.proxy.mode", &MODE_NONE.to_string());
    std::fs::write(&p, body).map_err(|e| e.to_string())
}
