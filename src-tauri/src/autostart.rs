//! Start-with-Windows via a Scheduled Task rather than a Run-key.
//!
//! A Run-key entry is silently dropped by some cleanup tools and cannot be
//! given restart-on-failure semantics. A Scheduled Task survives both.

use std::path::Path;
use std::process::Command;

const TASK: &str = "SplitStream";

// The app was called SplitTunnel until 0.9.0. Its start-up entry points at an
// executable the rename removed, so leaving it behind means Windows tries to
// launch a missing program at every logon. Cleared whenever start-up is
// touched, which is the only moment we can be sure the user is not mid-boot.
const LEGACY_TASK: &str = "SplitTunnel";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn quiet(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Remove the pre-rename start-up entry, wherever it ended up. Neither of
/// these existing is the normal case, so failures are ignored.
fn purge_legacy() {
    let _ = quiet(&mut Command::new("schtasks"))
        .args(["/Delete", "/F", "/TN", LEGACY_TASK])
        .output();
    let _ = quiet(&mut Command::new("reg"))
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", LEGACY_TASK, "/f",
        ])
        .output();
}

pub fn enable(exe: &Path) -> Result<(), String> {
    purge_legacy();
    let out = quiet(&mut Command::new("schtasks"))
        .args([
            "/Create", "/F",
            "/SC", "ONLOGON",
            "/TN", TASK,
            "/TR", &format!("\"{}\" --minimised", exe.display()),
            "/RL", "LIMITED",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }

    // A managed machine commonly forbids creating scheduled tasks outright, and
    // bare "ERROR: Access is denied." tells the user nothing about what to do.
    // Fall back to the per-user Run key, which usually is permitted.
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if err.to_lowercase().contains("access is denied") {
        let run = quiet(&mut Command::new("reg"))
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v", TASK,
                "/t", "REG_SZ",
                "/d", &format!("\"{}\" --minimised", exe.display()),
                "/f",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if run.status.success() {
            return Ok(());
        }
        return Err(
            "This PC does not allow adding start-up items (both the Task \
             Scheduler and the Run key were refused). Start SplitStream \
             manually, or ask IT."
                .into(),
        );
    }
    Err(err)
}

pub fn disable() -> Result<(), String> {
    purge_legacy();
    // Remove both possible homes; neither existing is not an error.
    let _ = quiet(&mut Command::new("schtasks"))
        .args(["/Delete", "/F", "/TN", TASK])
        .output();
    let _ = quiet(&mut Command::new("reg"))
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", TASK, "/f",
        ])
        .output();
    Ok(())
}

pub fn is_enabled() -> bool {
    let task = quiet(&mut Command::new("schtasks"))
        .args(["/Query", "/TN", TASK])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if task {
        return true;
    }
    quiet(&mut Command::new("reg"))
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", TASK,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
