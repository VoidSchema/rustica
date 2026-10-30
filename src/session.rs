use std::fs;
use std::path::{Path, PathBuf};

use crate::util;

/// Staging area plus the text report that ends up as `summary.txt`.
pub struct Session {
    pub root: PathBuf,
    pub summary: Vec<String>,
    pub log: Vec<String>,
    pub files: usize,
    pub bytes: u64,
}

impl Session {
    pub fn new() -> Self {
        let root = util::temp_dir().join(format!("s{}", util::random_hex(12)));
        let _ = fs::create_dir_all(&root);
        Session {
            root,
            summary: Vec::new(),
            log: Vec::new(),
            files: 0,
            bytes: 0,
        }
    }

    pub fn note(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        util::debug(&msg);
        self.log.push(msg);
    }

    pub fn line(&mut self, msg: impl Into<String>) {
        self.summary.push(msg.into());
    }

    pub fn put(&mut self, rel: &str, data: &[u8]) -> bool {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::write(&path, data) {
            Ok(()) => {
                self.files += 1;
                self.bytes += data.len() as u64;
                true
            }
            Err(_) => false,
        }
    }

    pub fn put_text(&mut self, rel: &str, text: &str) -> bool {
        self.put(rel, text.as_bytes())
    }

    /// Copies an existing file into the staging tree, optionally renaming it.
    pub fn copy(&mut self, src: &Path, rel: &str) -> bool {
        if !src.is_file() {
            return false;
        }
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::copy(src, &path) {
            Ok(size) => {
                self.files += 1;
                self.bytes += size;
                true
            }
            Err(_) => false,
        }
    }

    /// Copies a whole directory tree, capped by file count and total size.
    pub fn copy_tree(&mut self, src: &Path, rel: &str, max_files: usize, max_bytes: u64) -> usize {
        if !src.is_dir() {
            return 0;
        }
        let mut copied = 0;
        let mut spent = 0u64;
        for entry in walkdir::WalkDir::new(src)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            if copied >= max_files || spent >= max_bytes {
                break;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() == 0 || meta.len() > 8 * 1024 * 1024 {
                continue;
            }
            let Ok(sub) = entry.path().strip_prefix(src) else {
                continue;
            };
            let target = format!("{}/{}", rel.trim_end_matches('/'), sub.to_string_lossy().replace('\\', "/"));
            if self.copy(entry.path(), &target) {
                copied += 1;
                spent += meta.len();
            }
        }
        copied
    }

    /// Writes the summary and returns its path.
    pub fn finish(&mut self) -> PathBuf {
        let mut out = String::new();
        out.push_str(&self.summary.join("\n"));
        out.push_str("\n\n--- collector log ---\n");
        out.push_str(&self.log.join("\n"));
        out.push('\n');
        let _ = self.put("summary.txt", out.as_bytes());
        self.root.join("summary.txt")
    }

    pub fn destroy(&self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
