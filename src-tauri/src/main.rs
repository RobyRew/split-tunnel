// Windows GUI app: no console window on launch.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod autostart;
mod config;
mod enroll;
mod net;
mod pageant;
mod spotify;
mod tunnel;

use auth::{DevicePrompt, OidcSettings, Tokens};
use config::Config;
use enroll::Enrollment;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State, WindowEvent};
use tunnel::{Status, Supervisor, Transport};

/// Where the sign-in has got to. The UI polls this rather than waiting on a
/// command, because the device flow can legitimately take minutes — the user
/// has to go and log in — and a blocked command would freeze the window.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "state", content = "detail")]
enum AuthState {
    SignedOut,
    Waiting(DevicePrompt),
    Enrolling,
    SignedIn { email: String, expires_at: u64 },
    Failed(String),
}

struct App {
    sup: Supervisor,
    dir: PathBuf,
    bundled_bin: PathBuf,
    cfg: Mutex<Config>,
    auth: Arc<Mutex<AuthState>>,
    cancel_signin: Arc<AtomicBool>,
}

// NOTE ON THREADING: a synchronous `#[tauri::command]` runs on the MAIN
// thread, which is the same thread that drives the webview. Any command doing
// network, subprocess or disk work therefore freezes the window for its whole
// duration — a 12-second HTTP timeout froze typing for 12 seconds. Everything
// that can block is declared `#[tauri::command(async)]`, which Tauri runs on a
// worker thread. Only cheap in-memory reads stay synchronous below.
/// What an update check found. Kept deliberately small: the UI only needs to
/// know whether to offer the button and what version it would install.
#[derive(Serialize, Clone, Debug)]
struct UpdateInfo {
    available: bool,
    current: String,
    version: String,
    notes: String,
}

/// Ask the release feed whether a newer signed build exists.
///
/// The signature is checked by the plugin against the public key baked into
/// tauri.conf.json, so an update that was tampered with — or served from
/// somewhere else entirely — is refused before anything is written to disk.
/// Build an updater that honours the corporate proxy.
///
/// The plugin has its own HTTP client and knows nothing about the proxy the
/// rest of the app resolves, so on a managed network every check failed with a
/// bare "error sending request" — on a machine whose browser reaches GitHub
/// perfectly well.
fn updater_for(app: &tauri::AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    use tauri_plugin_updater::UpdaterExt;
    // Copy what we need and drop the lock before any await.
    let proxy = {
        let state = app.state::<App>();
        let cfg = state.cfg.lock().unwrap().clone();
        net::detect_for(&cfg.proxy, "https://github.com").url
    };
    let mut b = app.updater_builder();
    if !proxy.is_empty() {
        if let Ok(u) = tauri::Url::parse(&proxy) {
            b = b.proxy(u);
        }
    }
    b.build().map_err(|e| format!("updater unavailable: {e}"))
}

#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<UpdateInfo, String> {
    let current = app.package_info().version.to_string();
    let updater = updater_for(&app)?;
    match updater.check().await {
        Ok(Some(u)) => Ok(UpdateInfo {
            available: true,
            current,
            version: u.version.clone(),
            notes: u.body.clone().unwrap_or_default(),
        }),
        Ok(None) => Ok(UpdateInfo {
            available: false,
            current: current.clone(),
            version: current,
            notes: String::new(),
        }),
        Err(e) => Err(format!("could not check for updates: {e}")),
    }
}

/// Download, verify and install the update, then restart into it.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    let updater = updater_for(&app)?;
    let update = updater
        .check()
        .await
        .map_err(|e| format!("could not check for updates: {e}"))?
        .ok_or("no update available")?;

    update
        .download_and_install(|_chunk, _total| {}, || {})
        .await
        .map_err(|e| format!("update failed: {e}"))?;

    // The installer has replaced the binary; restart so the user is actually
    // running the version they just installed.
    //
    // `restart()` diverges (returns `!`), which makes the Ok below unreachable
    // — written this way so the function typechecks whichever signature the
    // Tauri version in use has, rather than betting on it.
    app.restart();
    #[allow(unreachable_code)]
    Ok(())
}

/// What Spotify is actually configured with — read back from its own prefs
/// rather than assumed, because a wrong key or an unquoted value looks exactly
/// like the feature silently doing nothing.
#[tauri::command(async)]
fn spotify_state(app: State<App>) -> spotify::SpotifyState {
    let port = app.cfg.lock().unwrap().local_port;
    spotify::state(port)
}

#[tauri::command(async)]
fn spotify_apply(app: State<App>) -> Result<spotify::SpotifyState, String> {
    let port = app.cfg.lock().unwrap().local_port;
    spotify::apply(port)
}

#[tauri::command(async)]
fn spotify_restore() -> Result<(), String> {
    spotify::restore()
}

/// Which applications currently hold connections to the local SOCKS listener.
#[tauri::command(async)]
fn connected_apps(app: State<App>) -> Vec<tunnel::ClientApp> {
    let port = app.cfg.lock().unwrap().local_port;
    tunnel::connected_apps(port)
}

/// The Windows accent colour, so the app can match the rest of the desktop.
#[tauri::command(async)]
fn system_accent() -> Option<String> {
    net::windows_accent()
}

/// Delete everything this app has created and return it to a first run.
///
/// Deliberately thorough: the certificate and key, the tokens, the enrollment
/// record, the pinned host key, the saved settings, the start-up entry, the
/// remembered proxy, and Spotify's proxy setting if we were the ones who
/// changed it. Anything left behind would make "reset" a lie and would be
/// invisible to the user, since all of it lives outside the app's window.
///
/// NOT deleted: Spotify's own prefs backup, which is the user's safety net and
/// not ours to remove.
#[tauri::command(async)]
fn reset_all(app: State<App>) -> Result<(), String> {
    let cfg = app.cfg.lock().unwrap().clone();

    // Stop first: the supervisor would otherwise keep using a key that is
    // about to disappear, and keep the relay's local port bound.
    app.sup.stop();

    if cfg.manage_spotify {
        let _ = spotify::restore();
    }
    let _ = autostart::disable();

    Tokens::forget(&app.dir);
    enroll::clear(&app.dir);
    let _ = std::fs::remove_file(Config::path(&app.dir));
    net::forget();

    *app.cfg.lock().unwrap() = Config::default();
    *app.auth.lock().unwrap() = AuthState::SignedOut;
    Ok(())
}

#[tauri::command]
fn get_config(app: State<App>) -> Config {
    app.cfg.lock().unwrap().clone()
}

#[tauri::command(async)]
fn save_config(app: State<App>, cfg: Config) -> Result<(), String> {
    cfg.save(&app.dir)?;
    *app.cfg.lock().unwrap() = cfg;
    Ok(())
}

#[tauri::command]
fn get_status(app: State<App>) -> Status {
    app.sup.status()
}

#[tauri::command(async)]
fn pageant_running() -> bool {
    pageant::is_running()
}

/// Which SSH tools will actually be used — surfaced in the UI so it is obvious
/// whether the user's own PuTTY, the bundled copy, or Windows' own OpenSSH is
/// in play.
#[tauri::command(async)]
fn tool_paths(app: State<App>) -> serde_json::Value {
    let ssh = tunnel::openssh_path();
    serde_json::json!({
        "plink": pageant::resolve_tool(&app.bundled_bin, "plink.exe").display().to_string(),
        "pageant": pageant::resolve_tool(&app.bundled_bin, "pageant.exe").display().to_string(),
        "ssh": ssh.display().to_string(),
        "ssh_available": ssh.exists() || ssh == PathBuf::from("ssh"),
    })
}

// ── Sign-in ───────────────────────────────────────────────────────────────

/// Ask the enrollment service which identity provider to use.
///
/// This is what lets a new user type one URL instead of four fields. None of
/// it is secret: a public OAuth client holds no secret by design.
#[tauri::command(async)]
fn discover(app: State<App>, base: String) -> Result<OidcSettings, String> {
    let mut cfg = app.cfg.lock().unwrap().clone();
    cfg.enroll_base = base.trim().to_string();
    let url = cfg.discovery_url();
    if url.is_empty() {
        return Err("Enter the tunnel server address first.".into());
    }

    let v: serde_json::Value = net::agent_for(&cfg.proxy, &url, 20)
        .get(&url)
        .call()
        .map_err(|e| format!("cannot reach {url}: {e}"))?
        .into_json()
        .map_err(|e| format!("bad response from {url}: {e}"))?;

    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let settings = OidcSettings {
        issuer: s("issuer"),
        client_id: s("client_id"),
        resource: s("resource"),
        scope: s("scope"),
        scopes: s("scopes"),
        redirect_port: v
            .get("redirect_port")
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u16,
    };
    if !settings.is_complete() {
        return Err("That server did not return a usable sign-in configuration.".into());
    }

    cfg.oidc = settings.clone();
    cfg.save(&app.dir)?;
    *app.cfg.lock().unwrap() = cfg;
    Ok(settings)
}

/// Result of probing the enrollment server, so the UI can say whether the
/// address actually works *before* the user presses Sign in and waits.
#[derive(Serialize, Clone, Debug)]
struct ServerProbe {
    reachable: bool,
    detail: String,
    /// The untranslated error. Friendly text is for the status line; this is
    /// what actually identifies the fault, and throwing it away cost a round
    /// trip and a wrong diagnosis.
    raw: String,
    issuer: String,
    cert_ttl: String,
}

/// Probe `<base>/config`. Deliberately reports *why* it failed: "unreachable"
/// with no reason is the thing that makes people re-type a correct address.
#[tauri::command(async)]
fn check_server(app: State<App>, base: String) -> ServerProbe {
    let mut cfg = app.cfg.lock().unwrap().clone();
    cfg.enroll_base = base.trim().to_string();
    let url = cfg.discovery_url();

    let fail = |detail: String, raw: String| ServerProbe {
        reachable: false,
        detail,
        raw,
        issuer: String::new(),
        cert_ttl: String::new(),
    };

    if url.is_empty() {
        return fail("No address entered".into(), String::new());
    }

    let proxy = net::detect_for(&cfg.proxy, &url);
    match net::agent_for(&cfg.proxy, &url, 12).get(&url).call() {
        Ok(r) => match r.into_json::<serde_json::Value>() {
            Ok(v) => {
                let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                if s("client_id").is_empty() || s("issuer").is_empty() {
                    return fail("Reachable, but not configured for sign-in".into(), String::new());
                }
                // This proxy demonstrably works; remember it so a later WPAD
                // failure does not strand the user.
                if !proxy.url.is_empty() {
                    net::remember(&proxy.url);
                    // Persist it too, so the next launch starts knowing.
                    let mut guard = app.cfg.lock().unwrap();
                    if guard.proxy_last_good != proxy.url {
                        guard.proxy_last_good = proxy.url.clone();
                        let _ = guard.save(&app.dir);
                    }
                }
                ServerProbe {
                    reachable: true,
                    detail: "Online".into(),
                    raw: String::new(),
                    // Host only — the full issuer URL is noise in a status line.
                    issuer: s("issuer")
                        .replace("https://", "")
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    cert_ttl: s("cert_ttl"),
                }
            }
            Err(e) => fail("Something answered, but it is not a tunnel server".into(), e.to_string()),
        },
        Err(ureq::Error::Status(404, _)) => fail(
            "Reached the host, but no tunnel server there (404)".into(),
            "HTTP 404".into(),
        ),
        Err(ureq::Error::Status(code, _)) => {
            fail(format!("Server answered HTTP {code}"), format!("HTTP {code}"))
        }
        Err(ureq::Error::Transport(t)) => {
            // ureq folds DNS, TCP and TLS problems into one type; the message
            // is the only thing that distinguishes them for the user.
            let m = t.to_string();
            let lower = m.to_lowercase();
            let hint = if lower.contains("dns") || lower.contains("resolve") {
                "Address not found — check the spelling".to_string()
            } else if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake") {
                "HTTPS certificate problem".to_string()
            } else if proxy.url.is_empty() && !proxy.pac_url.is_empty() {
                // The give-away for a managed network: the browser works via a
                // PAC script we cannot read, so we are the only thing offline.
                "No response. This PC uses an automatic proxy script that this \
                 app cannot read — open Manual setup and enter the proxy address"
                    .to_string()
            } else if proxy.url.is_empty() {
                "No response — the server may be down, or this network may need \
                 a proxy (set one under Manual setup)"
                    .to_string()
            } else {
                format!("No response via proxy {}", proxy.url)
            };
            fail(hint, m)
        }
    }
}

/// Everything needed to diagnose "nothing happens when I press things"
/// without asking the user to find a log file. Shown in the app's Log panel.
#[tauri::command(async)]
fn diagnostics(app: State<App>) -> serde_json::Value {
    let cfg = app.cfg.lock().unwrap().clone();
    let ssh = tunnel::openssh_path();
    let exists = |p: PathBuf| p.exists();
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "config_dir": app.dir.display().to_string(),
        "enroll_base": cfg.enroll_base,
        "enroll_url": cfg.enroll_url(),
        "discovery_url": cfg.discovery_url(),
        "oidc_issuer": cfg.oidc.issuer,
        "oidc_client_id": cfg.oidc.client_id,
        "oidc_scopes": cfg.oidc.scopes,
        "proxy": net::detect_for(&cfg.proxy, &cfg.discovery_url()).describe(),
        "proxy_setting": cfg.proxy,
        "transport_mode": cfg.transport,
        "relay_port": cfg.relay_port,
        "ssh_path": ssh.display().to_string(),
        "ssh_found": ssh.exists(),
        "have_key": exists(enroll::key_path(&app.dir)),
        "have_cert": exists(enroll::cert_path(&app.dir)),
        "have_known_hosts": exists(enroll::known_hosts_path(&app.dir)),
        "have_tokens": Tokens::load(&app.dir).is_some(),
        "enrollment": Enrollment::load(&app.dir),
    })
}

/// Copy text via the OS, because the webview's navigator.clipboard is refused
/// in this context — and a log you cannot copy is not much of a log.
/// Run a full connectivity report. Exists so a network problem can be
/// identified from inside the app instead of asking the user to run shell
/// commands they will reasonably not run.
#[tauri::command(async)]
fn network_test(app: State<App>) -> Vec<net::Check> {
    let cfg = app.cfg.lock().unwrap().clone();
    let host = cfg
        .enroll_base_url()
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    net::connectivity_report(&host, cfg.port, &cfg.proxy)
}

#[tauri::command(async)]
#[cfg(windows)]
fn copy_text(text: String) -> Result<(), String> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut child = Command::new("clip")
        .stdin(Stdio::piped())
        .creation_flags(0x0800_0000)
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .as_mut()
        .ok_or("no stdin")?
        .write_all(text.as_bytes())
        .map_err(|e| e.to_string())?;
    child.wait().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
#[cfg(not(windows))]
fn copy_text(_text: String) -> Result<(), String> {
    Err("clipboard not supported on this platform".into())
}

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
fn auth_state(app: State<App>) -> AuthState {
    app.auth.lock().unwrap().clone()
}

/// Start a device-flow sign-in, then enrol, all on a background thread.
#[tauri::command(async)]
fn sign_in(app: State<App>) -> Result<DevicePrompt, String> {
    let cfg = app.cfg.lock().unwrap().clone();
    if !cfg.oidc.is_complete() {
        return Err("Enter the tunnel server address and press Connect account first.".into());
    }

    // Authorization code + PKCE whenever the server names a redirect port.
    //
    // The device flow is kept only as a fallback: Logto does not attach
    // API-resource scopes to a device-code grant, so a token minted that way
    // never carries `tunnel:connect` and enrolment always fails. Confirmed
    // against the Grant records — device-code grants have no `resources` key.
    if cfg.oidc.redirect_port > 0 {
        return sign_in_authcode(app, cfg);
    }

    let agent = net::agent_for(&cfg.proxy, &cfg.oidc.issuer, 20);
    let prompt = auth::begin(&agent, &cfg.oidc)?;
    // Send them straight to the pre-filled page. The code stays on screen for
    // the case where the browser opens somewhere unexpected.
    auth::open_in_browser(&prompt.verification_uri_complete);

    *app.auth.lock().unwrap() = AuthState::Waiting(prompt.clone());
    app.cancel_signin.store(false, Ordering::SeqCst);

    let state = Arc::clone(&app.auth);
    let cancel = Arc::clone(&app.cancel_signin);
    let dir = app.dir.clone();
    let p = prompt.clone();

    std::thread::spawn(move || {
        let cancelled = || cancel.load(Ordering::SeqCst);
        let agent = net::agent_for(&cfg.proxy, &cfg.oidc.issuer, 20);
        let tokens = match auth::poll(&agent, &cfg.oidc, &p, &cancelled) {
            Ok(t) => t,
            Err(e) => {
                *state.lock().unwrap() = AuthState::Failed(e);
                return;
            }
        };
        if let Err(e) = tokens.save(&dir) {
            *state.lock().unwrap() = AuthState::Failed(e);
            return;
        }

        *state.lock().unwrap() = AuthState::Enrolling;
        match enroll::enroll(&agent, &dir, &cfg.enroll_url(), &tokens) {
            Ok(rec) => {
                *state.lock().unwrap() = AuthState::SignedIn {
                    email: if rec.identity.is_empty() { tokens.email.clone() } else { rec.identity.clone() },
                    expires_at: rec.expires_at,
                }
            }
            Err(e) => *state.lock().unwrap() = AuthState::Failed(e),
        }
    });

    Ok(prompt)
}

/// Browser redirect flow. Returns a prompt so the UI can show the same
/// "finish in your browser" card the device flow uses.
fn sign_in_authcode(app: State<App>, cfg: Config) -> Result<DevicePrompt, String> {
    let port = cfg.oidc.redirect_port;
    let redirect = auth::redirect_uri(port);
    let p = auth::pkce();
    let url = auth::authorize_url(&cfg.oidc, &redirect, &p);

    auth::open_in_browser(&url);

    let prompt = DevicePrompt {
        user_code: String::new(),
        verification_uri: url.clone(),
        verification_uri_complete: url,
        expires_in: 300,
        device_code: String::new(),
        interval: 1,
    };
    *app.auth.lock().unwrap() = AuthState::Waiting(prompt.clone());
    app.cancel_signin.store(false, Ordering::SeqCst);

    let state = Arc::clone(&app.auth);
    let cancel = Arc::clone(&app.cancel_signin);
    let dir = app.dir.clone();
    let verifier = p.verifier;
    let expect_state = p.state;

    std::thread::spawn(move || {
        let cancelled = || cancel.load(Ordering::SeqCst);
        let code = match auth::await_code(port, &expect_state, 300, &cancelled) {
            Ok(c) => c,
            Err(e) => {
                *state.lock().unwrap() = AuthState::Failed(e);
                return;
            }
        };
        let agent = net::agent_for(&cfg.proxy, &cfg.oidc.issuer, 20);
        let tokens = match auth::exchange_code(&agent, &cfg.oidc, &redirect, &code, &verifier) {
            Ok(t) => t,
            Err(e) => {
                *state.lock().unwrap() = AuthState::Failed(e);
                return;
            }
        };
        if let Err(e) = tokens.save(&dir) {
            *state.lock().unwrap() = AuthState::Failed(e);
            return;
        }
        *state.lock().unwrap() = AuthState::Enrolling;
        match enroll::enroll(&agent, &dir, &cfg.enroll_url(), &tokens) {
            Ok(rec) => {
                *state.lock().unwrap() = AuthState::SignedIn {
                    email: if rec.identity.is_empty() {
                        tokens.email.clone()
                    } else {
                        rec.identity.clone()
                    },
                    expires_at: rec.expires_at,
                }
            }
            Err(e) => *state.lock().unwrap() = AuthState::Failed(e),
        }
    });

    Ok(prompt)
}

#[tauri::command]
fn cancel_sign_in(app: State<App>) {
    app.cancel_signin.store(true, Ordering::SeqCst);
    *app.auth.lock().unwrap() = AuthState::SignedOut;
}

#[tauri::command(async)]
fn sign_out(app: State<App>) {
    app.cancel_signin.store(true, Ordering::SeqCst);
    app.sup.stop();
    Tokens::forget(&app.dir);
    enroll::clear(&app.dir);
    *app.auth.lock().unwrap() = AuthState::SignedOut;
}

#[tauri::command(async)]
fn enrollment(app: State<App>) -> Option<Enrollment> {
    Enrollment::load(&app.dir)
}

/// Renew the certificate without user interaction, using the stored refresh
/// token. Returns false when the user genuinely has to sign in again.
fn renew_quietly(dir: &PathBuf, cfg: &Config) -> Result<Enrollment, String> {
    let stored = Tokens::load(dir).ok_or("not signed in")?;
    if stored.refresh_token.is_empty() {
        return Err("no refresh token — sign in again".into());
    }
    let agent = net::agent_for(&cfg.proxy, &cfg.oidc.issuer, 20);
    let fresh = auth::refresh(&agent, &cfg.oidc, &stored.refresh_token)?;
    fresh.save(dir)?;
    enroll::enroll(&agent, dir, &cfg.enroll_url(), &fresh)
}

#[tauri::command(async)]
fn renew(app: State<App>) -> Result<Enrollment, String> {
    let cfg = app.cfg.lock().unwrap().clone();
    renew_quietly(&app.dir, &cfg)
}

// ── Tunnel ────────────────────────────────────────────────────────────────

#[tauri::command(async)]
fn start_tunnel(app: State<App>) -> Result<(), String> {
    let mut cfg = app.cfg.lock().unwrap().clone();

    // Prefer a certificate whenever one exists. Renew it first if it is close
    // to expiring, so the tunnel does not die twenty minutes from now.
    let record = match Enrollment::load(&app.dir) {
        Some(r) if r.is_valid() && !r.needs_renewal() => Some(r),
        Some(r) => match renew_quietly(&app.dir, &cfg) {
            Ok(fresh) => Some(fresh),
            // A renewal failure on a still-valid certificate is not fatal —
            // connect on what we have and let the user re-authenticate later.
            Err(e) if r.is_valid() => {
                *app.auth.lock().unwrap() = AuthState::Failed(format!("renewal failed: {e}"));
                Some(r)
            }
            Err(e) => return Err(format!("certificate expired and renewal failed: {e}")),
        },
        None => None,
    };

    let mut relay: Option<tunnel::Relay> = None;
    let transport = if let Some(rec) = record {
        // The server told us where to connect; that beats anything typed in.
        cfg.host = rec.host.clone();
        cfg.port = rec.port;
        cfg.user = rec.user.clone();
        {
            let mut guard = app.cfg.lock().unwrap();
            guard.host = cfg.host.clone();
            guard.port = cfg.port;
            guard.user = cfg.user.clone();
            let _ = guard.save(&app.dir);
        }
        let exe = tunnel::openssh_path();

        // Decide direct vs relay. "auto" probes a direct connection, because
        // it is faster and simpler when it works; the relay exists for the
        // networks where it does not.
        let want_relay = match cfg.transport.as_str() {
            "relay" => true,
            "direct" => false,
            _ => !tunnel::tcp_reachable(&rec.host, rec.port, 5),
        };
        if want_relay && !rec.ws_url.is_empty() {
            let ws_exe = pageant::resolve_tool(&app.bundled_bin, "wstunnel.exe");
            if !ws_exe.exists() {
                return Err(format!(
                    "the server is only reachable through the WebSocket relay, \
                     but wstunnel was not found at {}",
                    ws_exe.display()
                ));
            }
            relay = Some(tunnel::Relay::new(
                ws_exe,
                &rec.ws_url,
                &rec.ws_target,
                cfg.relay_port,
                &net::detect_for(&cfg.proxy, &rec.ws_url).url,
            ));
        } else if want_relay {
            return Err("Cannot reach the tunnel server, and it offers no \
                        WebSocket relay to fall back to."
                .into());
        }

        Transport::OpenSsh {
            exe,
            key: enroll::key_path(&app.dir),
            known_hosts: enroll::known_hosts_path(&app.dir),
        }
    } else {
        // Manual path, unchanged: bring your own key and let Pageant hold it.
        if !cfg.is_complete() {
            return Err("Sign in, or set the server host, port and username.".into());
        }
        if !pageant::is_running() && !cfg.key_path.trim().is_empty() {
            let ag = pageant::resolve_tool(&app.bundled_bin, "pageant.exe");
            let _ = pageant::start(&ag, Some(std::path::Path::new(&cfg.key_path)));
        }
        let plink = pageant::resolve_tool(&app.bundled_bin, "plink.exe");
        if !plink.exists() {
            return Err(format!("plink not found at {}", plink.display()));
        }
        Transport::Plink { exe: plink }
    };

    app.sup.start(transport, cfg.clone(), relay);

    if cfg.manage_spotify {
        let _ = spotify::apply(cfg.local_port);
    }
    Ok(())
}

#[tauri::command(async)]
fn stop_tunnel(app: State<App>) -> Result<(), String> {
    app.sup.stop();
    if app.cfg.lock().unwrap().manage_spotify {
        let _ = spotify::restore();
    }
    Ok(())
}

#[tauri::command(async)]
fn socks_ok(app: State<App>) -> bool {
    tunnel::socks_healthy(app.cfg.lock().unwrap().local_port)
}

#[tauri::command(async)]
fn set_autostart(enabled: bool) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if enabled {
        autostart::enable(&exe)?;
    } else {
        autostart::disable()?;
    }
    Ok(autostart::is_enabled())
}

#[tauri::command(async)]
fn autostart_enabled() -> bool {
    autostart::is_enabled()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let dir = app
                .path()
                .app_config_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            let bundled_bin = app
                .path()
                .resource_dir()
                .map(|r| r.join("bin"))
                .unwrap_or_else(|_| PathBuf::from("bin"));
            let cfg = Config::load(&dir);
            // Seed the remembered proxy before anything makes a request.
            net::remember(&cfg.proxy_last_good);

            // Reflect any certificate already on disk, so a restart does not
            // present a signed-in user with a "Sign in" button.
            let initial = match Enrollment::load(&dir) {
                Some(r) if r.is_valid() => AuthState::SignedIn {
                    email: r.identity.clone(),
                    expires_at: r.expires_at,
                },
                _ => AuthState::SignedOut,
            };

            app.manage(App {
                sup: Supervisor::new(),
                dir,
                bundled_bin,
                cfg: Mutex::new(cfg),
                auth: Arc::new(Mutex::new(initial)),
                cancel_signin: Arc::new(AtomicBool::new(false)),
            });

            // A tunnel is a background job: closing the window must not kill it.
            // The tray is how you get back to it.
            let show = MenuItem::with_id(app, "show", "Open SplitStream", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("SplitStream")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            tray.build(app)?;

            // Launched by the logon Scheduled Task: come up silently in the tray.
            if std::env::args().any(|a| a == "--minimised") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close button hides to tray instead of exiting, so the tunnel
            // survives. Quit is explicit, from the tray menu.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            get_status,
            start_tunnel,
            stop_tunnel,
            socks_ok,
            pageant_running,
            tool_paths,
            set_autostart,
            autostart_enabled,
            discover,
            check_server,
            diagnostics,
            app_version,
            copy_text,
            network_test,
            check_update,
            install_update,
            spotify_state,
            spotify_apply,
            spotify_restore,
            connected_apps,
            system_accent,
            reset_all,
            sign_in,
            cancel_sign_in,
            sign_out,
            auth_state,
            enrollment,
            renew
        ])
        .run(tauri::generate_context!())
        .expect("failed to start SplitStream");
}
