// Windows GUI app: no console window on launch.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod config;
mod pageant;
mod spotify;
mod tunnel;

use config::Config;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State, WindowEvent};
use tunnel::{Status, Supervisor};

struct App {
    sup: Supervisor,
    dir: PathBuf,
    bundled_bin: PathBuf,
    cfg: Mutex<Config>,
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

/// Which plink will actually be used — surfaced in the UI so it is obvious
/// whether the user's own PuTTY or the bundled copy is in play.
#[tauri::command]
fn tool_paths(app: State<App>) -> serde_json::Value {
    serde_json::json!({
        "plink": pageant::resolve_tool(&app.bundled_bin, "plink.exe").display().to_string(),
        "pageant": pageant::resolve_tool(&app.bundled_bin, "pageant.exe").display().to_string(),
    })
}

#[tauri::command]
fn start_tunnel(app: State<App>) -> Result<(), String> {
    let cfg = app.cfg.lock().unwrap().clone();
    if !cfg.is_complete() {
        return Err("Set the server host, port and username first.".into());
    }

    // Reuse the user's Pageant when it is already up — they may well have other
    // tunnels loaded in it. Only fall back to the bundled agent otherwise.
    if !pageant::is_running() && !cfg.key_path.trim().is_empty() {
        let ag = pageant::resolve_tool(&app.bundled_bin, "pageant.exe");
        let _ = pageant::start(&ag, Some(std::path::Path::new(&cfg.key_path)));
    }

    let plink = pageant::resolve_tool(&app.bundled_bin, "plink.exe");
    if !plink.exists() {
        return Err(format!("plink not found at {}", plink.display()));
    }
    app.sup.start(plink, cfg.clone());

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
            app.manage(App {
                sup: Supervisor::new(),
                dir,
                bundled_bin,
                cfg: Mutex::new(cfg),
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
            autostart_enabled
        ])
        .run(tauri::generate_context!())
        .expect("failed to start SplitTunnel");
}
