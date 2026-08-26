//! Pageant (PuTTY's SSH agent) integration.
//!
//! plink talks to Pageant natively, which is why this app drives plink rather
//! than Windows' built-in ssh.exe — OpenSSH uses a different agent and cannot
//! read keys already loaded in Pageant. If Pageant is running for other
//! tunnels we simply reuse it; nothing is disturbed.

use std::path::{Path, PathBuf};
use std::process::Command;

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

/// True when a Pageant process is already running for the current user.
pub fn is_running() -> bool {
    let out = quiet(&mut Command::new("tasklist"))
        .args(["/FI", "IMAGENAME eq pageant.exe", "/NH"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_lowercase().contains("pageant.exe"),
        Err(_) => false,
    }
}

/// Start the bundled Pageant, optionally loading a key. Only called when the
/// user has no Pageant of their own running.
pub fn start(pageant_exe: &Path, key: Option<&Path>) -> Result<(), String> {
    if !pageant_exe.exists() {
        return Err(format!("bundled Pageant missing at {}", pageant_exe.display()));
    }
    let mut cmd = Command::new(pageant_exe);
    if let Some(k) = key {
        cmd.arg(k);
    }
    quiet(&mut cmd).spawn().map(|_| ()).map_err(|e| e.to_string())
}

/// Prefer a plink already on PATH (the user's own PuTTY install) and fall back
/// to the copy shipped beside the executable.
pub fn resolve_tool(bundled_dir: &Path, exe: &str) -> PathBuf {
    if let Ok(out) = quiet(&mut Command::new("where")).arg(exe).output() {
        if out.status.success() {
            if let Some(first) = String::from_utf8_lossy(&out.stdout).lines().next() {
                let p = PathBuf::from(first.trim());
                if p.exists() {
                    return p;
                }
            }
        }
    }
    bundled_dir.join(exe)
}
