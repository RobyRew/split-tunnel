//! OAuth 2.0 Device Authorization Grant (RFC 8628) against an OIDC provider.
//!
//! Chosen over the usual desktop redirect flow deliberately. A redirect flow
//! needs a loopback HTTP listener inside this process and a redirect URI
//! registered to match it; the device flow needs neither. The app asks for a
//! code, opens the browser, and polls. Nothing listens, nothing is registered,
//! and it behaves identically on a locked-down corporate desktop — which is
//! the network this whole program exists to get out of.
//!
//! Two tokens come back and both matter:
//!   * `access_token` — audience is the enrollment API, carries the scope.
//!   * `id_token`     — audience is this app, carries the email.
//! The server checks both. See the enroll service for why.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the identity provider lives. Baked into the *config*, never into the
/// binary — the published build must contain no personal infrastructure.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OidcSettings {
    /// e.g. https://auth.example.com/oidc
    pub issuer: String,
    pub client_id: String,
    /// The API resource indicator registered with the IdP.
    pub resource: String,
    /// Extra scope that authorises tunnel use, e.g. "tunnel:connect".
    pub scope: String,
}

impl OidcSettings {
    pub fn is_complete(&self) -> bool {
        !self.issuer.trim().is_empty() && !self.client_id.trim().is_empty()
    }
    fn device_endpoint(&self) -> String {
        format!("{}/device/auth", self.issuer.trim_end_matches('/'))
    }
    fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer.trim_end_matches('/'))
    }
    fn scopes(&self) -> String {
        let mut s = vec!["openid", "profile", "email", "offline_access"];
        if !self.scope.trim().is_empty() {
            s.push(self.scope.trim());
        }
        s.join(" ")
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct DevicePrompt {
    pub user_code: String,
    pub verification_uri: String,
    /// The URI with the code already embedded. When the provider supplies it
    /// the user only has to click; no typing the code by hand.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    #[serde(skip)]
    pub device_code: String,
    #[serde(skip)]
    pub interval: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Tokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
    /// Unix seconds. Only used to decide when to refresh.
    pub expires_at: u64,
    /// Read out of the id_token for display. NOT trusted for anything —
    /// the server verifies the signature and makes its own decision.
    pub email: String,
}

impl Tokens {
    pub fn is_expired(&self) -> bool {
        now() + 60 >= self.expires_at
    }
    pub fn path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("tokens.json")
    }
    /// Stored under the per-user app config directory, which on Windows is
    /// already ACL'd to this user. A refresh token here is worth no more than
    /// the SSH key sitting beside it.
    pub fn load(dir: &std::path::Path) -> Option<Self> {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }
    pub fn save(&self, dir: &std::path::Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(Self::path(dir), body).map_err(|e| e.to_string())
    }
    pub fn forget(dir: &std::path::Path) {
        let _ = std::fs::remove_file(Self::path(dir));
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the payload of a JWT without verifying it.
///
/// Safe here *only* because the result is used for on-screen display. Every
/// security decision is made by the enrollment service, which checks the
/// signature against the provider's JWKS.
fn jwt_claim(token: &str, claim: &str) -> String {
    let Some(payload) = token.split('.').nth(1) else {
        return String::new();
    };
    let mut b64 = payload.replace('-', "+").replace('_', "/");
    while b64.len() % 4 != 0 {
        b64.push('=');
    }
    let Ok(bytes) = base64_decode(&b64) else {
        return String::new();
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get(claim).and_then(|c| c.as_str().map(String::from)))
        .unwrap_or_default()
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let Some(idx) = T.iter().position(|&t| t == c) else {
            return Err(());
        };
        buf = (buf << 6) | idx as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

fn post_form(url: &str, form: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let resp = ureq::post(url)
        .timeout(Duration::from_secs(20))
        .send_form(form);
    match resp {
        Ok(r) => r.into_json().map_err(|e| format!("bad response: {e}")),
        // The device flow signals "not yet" with a 400 body, so error bodies
        // are load-bearing rather than merely informative.
        Err(ureq::Error::Status(_, r)) => r
            .into_json()
            .map_err(|e| format!("bad error response: {e}")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

/// Step 1 — ask the provider for a user code.
pub fn begin(settings: &OidcSettings) -> Result<DevicePrompt, String> {
    if !settings.is_complete() {
        return Err("Sign-in is not configured (issuer and client id).".into());
    }
    let scopes = settings.scopes();
    let mut form: Vec<(&str, &str)> = vec![
        ("client_id", settings.client_id.as_str()),
        ("scope", scopes.as_str()),
    ];
    if !settings.resource.trim().is_empty() {
        form.push(("resource", settings.resource.trim()));
    }

    let v = post_form(&settings.device_endpoint(), &form)?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(describe(err, &v));
    }

    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let device_code = get("device_code");
    if device_code.is_empty() {
        return Err("provider returned no device code".into());
    }
    let uri = get("verification_uri");
    let complete = {
        let c = get("verification_uri_complete");
        if c.is_empty() { uri.clone() } else { c }
    };
    Ok(DevicePrompt {
        user_code: get("user_code"),
        verification_uri: uri,
        verification_uri_complete: complete,
        expires_in: v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(600),
        device_code,
        interval: v.get("interval").and_then(|x| x.as_u64()).unwrap_or(5).max(1),
    })
}

/// Step 2 — poll until the user finishes in the browser.
///
/// `cancelled` lets the UI abort a poll that would otherwise run for the full
/// code lifetime (typically ten minutes).
pub fn poll(
    settings: &OidcSettings,
    prompt: &DevicePrompt,
    cancelled: &dyn Fn() -> bool,
) -> Result<Tokens, String> {
    let deadline = now() + prompt.expires_in;
    let mut interval = prompt.interval;

    while now() < deadline {
        for _ in 0..interval {
            if cancelled() {
                return Err("sign-in cancelled".into());
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", prompt.device_code.as_str()),
            ("client_id", settings.client_id.as_str()),
        ];
        if !settings.resource.trim().is_empty() {
            form.push(("resource", settings.resource.trim()));
        }

        let v = post_form(&settings.token_endpoint(), &form)?;
        match v.get("error").and_then(|e| e.as_str()) {
            None => return Ok(into_tokens(v)),
            Some("authorization_pending") => continue,
            // The provider is telling us we are polling too fast. Obeying this
            // matters: ignoring it earns a hard `access_denied`.
            Some("slow_down") => {
                interval += 5;
                continue;
            }
            Some(err) => return Err(describe(err, &v)),
        }
    }
    Err("the sign-in code expired — try again".into())
}

/// Exchange a stored refresh token for a fresh access token, with no user
/// interaction. This is what makes certificate renewal silent.
pub fn refresh(settings: &OidcSettings, refresh_token: &str) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", settings.client_id.as_str()),
    ];
    if !settings.resource.trim().is_empty() {
        form.push(("resource", settings.resource.trim()));
    }
    let v = post_form(&settings.token_endpoint(), &form)?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(describe(err, &v));
    }
    let mut t = into_tokens(v);
    // Providers may rotate refresh tokens, or may omit an unchanged one.
    if t.refresh_token.is_empty() {
        t.refresh_token = refresh_token.to_string();
    }
    Ok(t)
}

fn into_tokens(v: serde_json::Value) -> Tokens {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let id_token = get("id_token");
    Tokens {
        email: jwt_claim(&id_token, "email"),
        access_token: get("access_token"),
        id_token,
        refresh_token: get("refresh_token"),
        expires_at: now() + v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(3600),
    }
}

/// Turn OAuth error codes into something a human can act on.
fn describe(err: &str, v: &serde_json::Value) -> String {
    let detail = v
        .get("error_description")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let base = match err {
        "access_denied" => "sign-in was refused — the account may lack tunnel access".to_string(),
        "expired_token" => "the sign-in code expired — try again".to_string(),
        "invalid_client" => {
            "the client id is wrong, or the app is not configured for the device flow".to_string()
        }
        "invalid_grant" => "the session is no longer valid — sign in again".to_string(),
        "invalid_target" => {
            "the API resource is not registered with the identity provider".to_string()
        }
        "invalid_scope" => {
            "the requested permission does not exist on the identity provider".to_string()
        }
        other => format!("sign-in failed ({other})"),
    };
    if detail.is_empty() {
        base
    } else {
        format!("{base}: {detail}")
    }
}

/// Open a URL in the user's default browser.
pub fn open_in_browser(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The empty "" is cmd's window-title argument. Omitting it makes cmd
        // treat a quoted URL as the title and open nothing at all.
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(0x0800_0000)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}
