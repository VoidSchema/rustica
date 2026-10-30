use std::fs;
use std::path::{Path, PathBuf};

use winapi::um::sysinfoapi::GetLocalTime;
use winapi::um::minwinbase::SYSTEMTIME;

pub fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn temp_dir() -> PathBuf {
    env_path("TEMP")
        .or_else(|| env_path("TMP"))
        .unwrap_or_else(|| PathBuf::from("C:\\Windows\\Temp"))
}

pub fn user_profile() -> PathBuf {
    env_path("USERPROFILE").unwrap_or_else(|| PathBuf::from("C:\\Users\\Public"))
}

/// xorshift64 seeded from the clock and the pid. Enough for filenames; this is
/// not used for anything cryptographic.
pub fn random_hex(len: usize) -> String {
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        ^ ((std::process::id() as u64) << 32)
        ^ (&len as *const usize as u64);
    if seed == 0 {
        seed = 0x2545_f491_4f6c_dd1d;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.push(HEX[((seed >> 33) as usize) & 0xf] as char);
    }
    out
}

pub fn timestamp() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Strips characters Windows rejects in a filename component.
pub fn sanitize(name: &str, fallback: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').to_string();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

/// Copies a SQLite database together with its journal siblings into a temp
/// path, so a browser holding a write lock does not block us.
pub fn stage_sqlite(db: &Path, into: &Path) -> bool {
    if fs::copy(db, into).is_err() {
        return false;
    }
    for suffix in ["-wal", "-shm"] {
        let side = PathBuf::from(format!("{}{}", db.to_string_lossy(), suffix));
        if side.is_file() {
            let _ = fs::copy(&side, format!("{}{}", into.to_string_lossy(), suffix));
        }
    }
    true
}

pub fn cleanup_sqlite(staged: &Path) {
    let _ = fs::remove_file(staged);
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{}", staged.to_string_lossy(), suffix));
    }
}

pub fn sleep_secs(secs: u64) {
    if secs > 0 {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// Reads a file, returning None instead of an error for anything unreadable.
pub fn read(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

pub fn read_text(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

pub fn debug(msg: &str) {
    #[cfg(feature = "console")]
    println!("{msg}");
    #[cfg(not(feature = "console"))]
    let _ = msg;
}
