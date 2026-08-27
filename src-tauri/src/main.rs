// Windows GUI app: no console window on launch.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod autostart;
mod config;
mod enroll;
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

#[tauri::command]
fn get_config(app: State<App>) -> Config {
    app.cfg.lock().unwrap().clone()
}

#[tauri::command]
fn save_config(app: State<App>, cfg: Config) -> Result<(), String> {
    cfg.save(&app.dir)?;
    *app.cfg.lock().unwrap() = cfg;
    Ok(())
}

#[tauri::command]
fn get_status(app: State<App>) -> Status {
    app.sup.status()
}

#[tauri::command]
fn pageant_running() -> bool {
    pageant::is_running()
}

/// Which SSH tools will actually be used — surfaced in the UI so it is obvious
/// whether the user's own PuTTY, the bundled copy, or Windows' own OpenSSH is
/// in play.
#[tauri::command]
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
#[tauri::command]
fn discover(app: State<App>, base: String) -> Result<OidcSettings, String> {
    let mut cfg = app.cfg.lock().unwrap().clone();
    cfg.enroll_base = base.trim().to_string();
    let url = cfg.discovery_url();
    if url.is_empty() {
        return Err("Enter the tunnel server address first.".into());
    }

    let v: serde_json::Value = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
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
    issuer: String,
    cert_ttl: String,
}

/// Probe `<base>/config`. Deliberately reports *why* it failed: "unreachable"
/// with no reason is the thing that makes people re-type a correct address.
#[tauri::command]
fn check_server(app: State<App>, base: String) -> ServerProbe {
    let mut cfg = app.cfg.lock().unwrap().clone();
    cfg.enroll_base = base.trim().to_string();
    let url = cfg.discovery_url();

    let fail = |detail: String| ServerProbe {
        reachable: false,
        detail,
        issuer: String::new(),
        cert_ttl: String::new(),
    };

    if url.is_empty() {
        return fail("No address entered".into());
    }

    match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
    {
        Ok(r) => match r.into_json::<serde_json::Value>() {
            Ok(v) => {
                let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                if s("client_id").is_empty() || s("issuer").is_empty() {
                    return fail("Reachable, but not configured for sign-in".into());
                }
                ServerProbe {
                    reachable: true,
                    detail: "Online".into(),
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
            Err(_) => fail("Something answered, but it is not a tunnel server".into()),
        },
        Err(ureq::Error::Status(404, _)) => {
            fail("Reached the host, but no tunnel server there (404)".into())
        }
        Err(ureq::Error::Status(code, _)) => fail(format!("Server answered HTTP {code}")),
        Err(ureq::Error::Transport(t)) => {
            // ureq folds DNS, TCP and TLS problems into one type; the message
            // is the only thing that distinguishes them for the user.
            let m = t.to_string();
            let hint = if m.contains("dns") || m.contains("resolve") {
                "Address not found — check the spelling"
            } else if m.contains("certificate") || m.contains("tls") {
                "HTTPS certificate problem"
            } else if m.contains("timed out") || m.contains("timeout") {
                "No response — the server may be down, or blocked by this network"
            } else {
                "Cannot connect"
            };
            fail(hint.to_string())
        }
    }
}

#[tauri::command]
fn auth_state(app: State<App>) -> AuthState {
    app.auth.lock().unwrap().clone()
}

/// Start a device-flow sign-in, then enrol, all on a background thread.
#[tauri::command]
fn sign_in(app: State<App>) -> Result<DevicePrompt, String> {
    let cfg = app.cfg.lock().unwrap().clone();
    if !cfg.oidc.is_complete() {
        return Err("Enter the tunnel server address and press Connect account first.".into());
    }

    let prompt = auth::begin(&cfg.oidc)?;
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
        let tokens = match auth::poll(&cfg.oidc, &p, &cancelled) {
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
        match enroll::enroll(&dir, &cfg.enroll_url(), &tokens) {
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

#[tauri::command]
fn cancel_sign_in(app: State<App>) {
    app.cancel_signin.store(true, Ordering::SeqCst);
    *app.auth.lock().unwrap() = AuthState::SignedOut;
}

#[tauri::command]
fn sign_out(app: State<App>) {
    app.cancel_signin.store(true, Ordering::SeqCst);
    app.sup.stop();
    Tokens::forget(&app.dir);
    enroll::clear(&app.dir);
    *app.auth.lock().unwrap() = AuthState::SignedOut;
}

#[tauri::command]
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
    let fresh = auth::refresh(&cfg.oidc, &stored.refresh_token)?;
    fresh.save(dir)?;
    enroll::enroll(dir, &cfg.enroll_url(), &fresh)
}

#[tauri::command]
fn renew(app: State<App>) -> Result<Enrollment, String> {
    let cfg = app.cfg.lock().unwrap().clone();
    renew_quietly(&app.dir, &cfg)
}

// ── Tunnel ────────────────────────────────────────────────────────────────

#[tauri::command]
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

    app.sup.start(transport, cfg.clone());

    if cfg.manage_spotify {
        let _ = spotify::apply(cfg.local_port);
    }
    Ok(())
}

#[tauri::command]
fn stop_tunnel(app: State<App>) -> Result<(), String> {
    app.sup.stop();
    if app.cfg.lock().unwrap().manage_spotify {
        let _ = spotify::restore();
    }
    Ok(())
}

#[tauri::command]
fn socks_ok(app: State<App>) -> bool {
    tunnel::socks_healthy(app.cfg.lock().unwrap().local_port)
}

#[tauri::command]
fn set_autostart(enabled: bool) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if enabled {
        autostart::enable(&exe)?;
    } else {
        autostart::disable()?;
    }
    Ok(autostart::is_enabled())
}

#[tauri::command]
fn autostart_enabled() -> bool {
    autostart::is_enabled()
}

fn main() {
    tauri::Builder::default()
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
            let show = MenuItem::with_id(app, "show", "Open SplitTunnel", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("SplitTunnel")
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
            sign_in,
            cancel_sign_in,
            sign_out,
            auth_state,
            enrollment,
            renew
        ])
        .run(tauri::generate_context!())
        .expect("failed to start SplitTunnel");
}
