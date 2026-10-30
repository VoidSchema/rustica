use std::path::Path;
use std::ptr;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use winapi::shared::minwindef::DWORD;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::winbase::LocalFree;
use winapi::um::wincrypt::DATA_BLOB;

use crate::util;

/// CryptUnprotectData under the current user. Returns None for blobs owned by
/// another account or protected with an app-bound key.
pub fn dpapi(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    unsafe {
        let mut input = DATA_BLOB {
            cbData: data.len() as DWORD,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output: DATA_BLOB = std::mem::zeroed();
        let ok = CryptUnprotectData(
            &mut input,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output,
        );
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        let plain = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut _);
        Some(plain)
    }
}

/// Reads `os_crypt.encrypted_key` out of a Chromium `Local State` file.
pub fn local_state_key(local_state: &Path) -> Option<Vec<u8>> {
    let text = util::read_text(local_state)?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let encoded = json.get("os_crypt")?.get("encrypted_key")?.as_str()?;
    let raw = B64.decode(encoded).ok()?;
    let payload = raw.strip_prefix(b"DPAPI").unwrap_or(&raw);
    dpapi(payload)
}

/// AES-256-GCM blob as written by Chromium 80+:
/// `v10` | 12-byte nonce | ciphertext | 16-byte tag.
pub fn gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 || tag.len() != 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            b"",
            &mut buffer,
            aes_gcm::Tag::from_slice(tag),
        )
        .ok()?;
    Some(buffer)
}

/// Decrypts a Chromium `password_value` / `encrypted_value` blob.
pub fn chromium_decrypt(blob: &[u8], key: Option<&[u8]>) -> Option<Vec<u8>> {
    if blob.is_empty() {
        return None;
    }
    if blob.len() > 3 && (&blob[..3] == b"v10" || &blob[..3] == b"v11") {
        let key = key?;
        if blob.len() < 3 + 12 + 16 {
            return None;
        }
        let nonce = &blob[3..15];
        let tag = &blob[blob.len() - 16..];
        let ciphertext = &blob[15..blob.len() - 16];
        return gcm_decrypt(key, nonce, ciphertext, tag);
    }
    if blob.len() > 3 && &blob[..3] == b"v20" {
        // Chrome 127+ app-bound encryption: the key lives in a service that
        // only releases it to a verified Chrome binary.
        return None;
    }
    dpapi(blob)
}

/// Cookie values on Chromium 80+ carry a 32-byte SHA-256 of the host key in
/// front of the plaintext.
pub fn chromium_cookie(blob: &[u8], key: Option<&[u8]>, host_key: &str) -> Option<String> {
    let plain = chromium_decrypt(blob, key)?;
    let host = host_key.as_bytes();
    if plain.len() > 32 {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(host);
        if plain[..32] == digest[..] {
            return Some(String::from_utf8_lossy(&plain[32..]).into_owned());
        }
    }
    Some(String::from_utf8_lossy(&plain).into_owned())
}

