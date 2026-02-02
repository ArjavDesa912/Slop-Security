//! Cryptographic Operations Module
//! 
//! Provides secure primitives: Argon2id, AES-256-GCM, HMAC, secure random.

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
use argon2::{password_hash::{rand_core::RngCore, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::prelude::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

type HmacSha256 = Hmac<Sha256>;

/// Hash password with Argon2id
#[wasm_bindgen]
pub fn hash_password(password: &str) -> Result<String, JsValue> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify password against hash
#[wasm_bindgen]
pub fn verify_password(password: &str, hash: &str) -> Result<bool, JsValue> {
    let parsed = PasswordHash::new(hash).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Encrypt with AES-256-GCM
#[wasm_bindgen]
pub fn encrypt(plaintext: &str, key_b64: &str) -> Result<String, JsValue> {
    let key_bytes = BASE64.decode(key_b64).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if key_bytes.len() != 32 { return Err(JsValue::from_str("Key must be 32 bytes")); }
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut result = nonce_bytes.to_vec();
    result.extend(ct);
    Ok(BASE64.encode(&result))
}

/// Decrypt with AES-256-GCM
#[wasm_bindgen]
pub fn decrypt(ct_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let key_bytes = BASE64.decode(key_b64).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let data = BASE64.decode(ct_b64).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if key_bytes.len() != 32 || data.len() < 12 { return Err(JsValue::from_str("Invalid input")); }
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let pt = cipher.decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    String::from_utf8(pt).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate AES-256 key
#[wasm_bindgen]
pub fn generate_key() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    BASE64.encode(&key)
}

/// Generate random bytes
#[wasm_bindgen]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random hex string
#[wasm_bindgen]
pub fn random_hex(len: usize) -> String {
    let bytes = random_bytes(len / 2 + 1);
    hex::encode(&bytes)[..len].to_string()
}

/// SHA-256 hash
#[wasm_bindgen]
pub fn sha256(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

/// SHA-512 hash
#[wasm_bindgen]
pub fn sha512(data: &str) -> String {
    hex::encode(Sha512::digest(data.as_bytes()))
}

/// HMAC-SHA256
#[wasm_bindgen]
pub fn hmac_sha256(data: &str, key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Generate UUID v4
#[wasm_bindgen]
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Detect hardcoded secrets
#[wasm_bindgen]
pub fn detect_hardcoded_secret(value: &str) -> bool {
    let patterns = ["sk_live_", "sk_test_", "AKIA", "ghp_", "AIza", "-----BEGIN", "password=", "secret="];
    patterns.iter().any(|p| value.contains(p)) || (value.len() >= 20 && entropy(value) > 4.5)
}

fn entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    freq.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / s.len() as f64; -p * p.log2() }).sum()
}
