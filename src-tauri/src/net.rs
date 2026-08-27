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

/// One line of a connectivity report.
#[derive(serde::Serialize, Clone, Debug)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &str, ok: bool, detail: String) -> Check {
    Check { name: name.into(), ok, detail }
}

/// Resolve a host, returning every address, so a v6-only answer is visible.
fn resolve(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map(|i| i.collect())
        .map_err(|e| e.to_string())
}

/// Can we open a TCP connection at all? Separating this from the HTTPS request
/// is the whole point: a proxy can carry HTTPS but never the SSH tunnel, so
/// "the website works" says nothing about whether the tunnel will.
fn tcp(host: &str, port: u16, secs: u64) -> Check {
    let label = format!("TCP {host}:{port}");
    let addrs = match resolve(host, port) {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => return check(&label, false, "no addresses returned".into()),
        Err(e) => return check(&label, false, format!("DNS failed: {e}")),
    };
    let started = std::time::Instant::now();
    for a in &addrs {
        if std::net::TcpStream::connect_timeout(a, Duration::from_secs(secs)).is_ok() {
            return check(&label, true, format!("connected to {a} in {:?}", started.elapsed()));
        }
    }
    check(
        &label,
        false,
        format!("could not connect to {} after {:?}", addrs[0], started.elapsed()),
    )
}

/// Everything needed to tell a blocked domain apart from a blocked port, a
/// dead server, a proxy requirement, or TLS interception.
pub fn connectivity_report(base_host: &str, tunnel_port: u16, proxy_override: &str) -> Vec<Check> {
    let mut out = Vec::new();
    let info = detect(proxy_override);
    out.push(check("Proxy", true, info.describe()));

    if base_host.is_empty() {
        out.push(check("Server address", false, "not set".into()));
        return out;
    }

    match resolve(base_host, 443) {
        Ok(a) => out.push(check(
            "DNS",
            !a.is_empty(),
            a.iter().map(|x| x.ip().to_string()).collect::<Vec<_>>().join(", "),
        )),
        Err(e) => out.push(check("DNS", false, e)),
    }

    // A control, so "everything is blocked" is distinguishable from "this
    // domain is blocked" — the usual verdict on a brand-new hostname.
    out.push(tcp("www.microsoft.com", 443, 6));
    out.push(tcp(base_host, 443, 8));
    out.push(tcp(base_host, tunnel_port, 8));

    // The real HTTPS request, with the untranslated error.
    let url = format!("https://{base_host}/config");
    let started = std::time::Instant::now();
    match agent(proxy_override, 15).get(&url).call() {
        Ok(r) => out.push(check("HTTPS /config", true, format!("HTTP {}", r.status()))),
        Err(ureq::Error::Status(c, _)) => {
            out.push(check("HTTPS /config", false, format!("HTTP {c}")))
        }
        Err(e) => out.push(check(
            "HTTPS /config",
            false,
            format!("{e} (after {:?})", started.elapsed()),
        )),
    }
    out
}
