//! Start-with-Windows via a Scheduled Task rather than a Run-key.
//!
//! A Run-key entry is silently dropped by some cleanup tools and cannot be
//! given restart-on-failure semantics. A Scheduled Task survives both.

use std::path::Path;
use std::process::Command;

const TASK: &str = "SplitTunnel";

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

pub fn enable(exe: &Path) -> Result<(), String> {
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
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn disable() -> Result<(), String> {
    let out = quiet(&mut Command::new("schtasks"))
        .args(["/Delete", "/F", "/TN", TASK])
        .output()
        .map_err(|e| e.to_string())?;
    // Deleting a task that was never created is not an error worth surfacing.
    let _ = out;
    Ok(())
}

pub fn is_enabled() -> bool {
    quiet(&mut Command::new("schtasks"))
        .args(["/Query", "/TN", TASK])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
