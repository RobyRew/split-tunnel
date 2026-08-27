//! HTTP with corporate-proxy support.
//!
//! `ureq` does not read the system proxy, which is fine on a home network and
//! fatal on a managed one: the browser works, this app times out, and the only
//! symptom is "Cannot connect". That is exactly the network this program
//! exists to escape, so it has to work there first.
//!
//! Resolution order — first hit wins:
//!   1. an explicit proxy in the app's settings
//!   2. HTTPS_PROXY / HTTP_PROXY / ALL_PROXY (either case)
//!   3. Windows: HKCU Internet Settings, if ProxyEnable is 1
//!
//! A PAC script (`AutoConfigURL`) is deliberately NOT evaluated — that needs a
//! JavaScript engine. It is detected and reported, so the UI can tell the user
//! to enter the proxy by hand instead of leaving them guessing.

use std::time::Duration;

/// What we found, in a form fit to show a human.
#[derive(Clone, Debug, Default)]
pub struct ProxyInfo {
    pub url: String,
    pub source: String,
    /// Set when the machine is configured by PAC script, which we cannot read.
    pub pac_url: String,
}

impl ProxyInfo {
    pub fn describe(&self) -> String {
        if !self.url.is_empty() {
            format!("{} ({})", self.url, self.source)
        } else if !self.pac_url.is_empty() {
            format!("auto-config script — not readable ({})", self.pac_url)
        } else {
            "none".into()
        }
    }
}

fn from_env() -> Option<(String, String)> {
    for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some((v, format!("${key}")));
            }
        }
    }
    None
}

/// Read a single value out of the Internet Settings key.
///
/// Shelling out to `reg` rather than taking a registry crate: one fewer
/// dependency to break the Windows build, and the output is trivially checkable
/// by hand when something looks wrong.
#[cfg(windows)]
fn reg_value(name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            name,
        ])
        .creation_flags(0x0800_0000)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // "    ProxyServer    REG_SZ    proxy.corp.example:8080"
    let line = text.lines().find(|l| l.trim_start().starts_with(name))?;
    let mut parts = line.split_whitespace();
    parts.next()?; // name
    parts.next()?; // type
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        None
    } else {
        Some(rest.join(" "))
    }
}

#[cfg(not(windows))]
fn reg_value(_name: &str) -> Option<String> {
    None
}

/// `ProxyServer` is either "host:port" or "http=h:p;https=h:p;ftp=…".
fn pick_scheme(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains('=') {
        return Some(raw.to_string());
    }
    let mut http = None;
    for part in raw.split(';') {
        let mut kv = part.splitn(2, '=');
        let k = kv.next()?.trim().to_ascii_lowercase();
        let v = kv.next().unwrap_or("").trim();
        if v.is_empty() {
            continue;
        }
        if k == "https" {
            return Some(v.to_string()); // best match — we only make HTTPS calls
        }
        if k == "http" {
            http = Some(v.to_string());
        }
    }
    http
}

fn normalise(v: &str) -> String {
    let v = v.trim();
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("socks5://") {
        v.to_string()
    } else {
        format!("http://{v}")
    }
}

/// Work out which proxy to use. `override_url` comes from the app's settings.
pub fn detect(override_url: &str) -> ProxyInfo {
    let mut info = ProxyInfo::default();

    if !override_url.trim().is_empty() {
        info.url = normalise(override_url);
        info.source = "app setting".into();
        return info;
    }

    if let Some((v, src)) = from_env() {
        info.url = normalise(&v);
        info.source = src;
        return info;
    }

    let enabled = reg_value("ProxyEnable")
        .map(|v| v.trim().ends_with('1'))
        .unwrap_or(false);
    if enabled {
        if let Some(server) = reg_value("ProxyServer").and_then(|s| pick_scheme(&s)) {
            info.url = normalise(&server);
            info.source = "Windows settings".into();
            return info;
        }
    }

    if let Some(pac) = reg_value("AutoConfigURL") {
        if !pac.trim().is_empty() {
            info.pac_url = pac.trim().to_string();
        }
    }
    info
}

/// Build an HTTP agent honouring the resolved proxy.
pub fn agent(override_url: &str, timeout_secs: u64) -> ureq::Agent {
    let info = detect(override_url);
    let mut b = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(timeout_secs.min(15)))
        .timeout(Duration::from_secs(timeout_secs));
    if !info.url.is_empty() {
        if let Ok(p) = ureq::Proxy::new(&info.url) {
            b = b.proxy(p);
        }
    }
    b.build()
}
