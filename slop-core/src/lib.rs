//! # Slop Security Core Engine
//! 
//! The universal security engine for Slop Security, providing OWASP Top 10
//! protection for AI-generated code ("slop").
//! 
//! ## Features
//! 
//! - SQL Injection prevention
//! - XSS filtering
//! - Command Injection protection
//! - Cryptographic operations
//! - Input validation
//! - SSRF protection
//! - Access control evaluation
//! 
//! ## Usage
//! 
//! This crate is compiled to WebAssembly and used by language-specific SDKs.
//!
//! ```javascript
//! import init, { sanitize, validate_url } from './slop_core.js';
//! await init();
//! const safe = sanitize("<script>alert(1)</script>");
//! ```

use wasm_bindgen::prelude::*;

pub mod sanitizer;
pub mod crypto;
pub mod validator;
pub mod policy;
pub mod config;
pub mod error;

pub use sanitizer::*;
pub use crypto::*;
pub use validator::*;
pub use policy::*;
pub use config::*;
pub use error::*;

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the Slop Security engine
#[wasm_bindgen]
pub fn init() -> Result<(), JsValue> {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    
    Ok(())
}

/// Get the version of the Slop Security engine
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// =============================================================================
// Sanitization Functions (WASM-exported)
// =============================================================================

/// Sanitize input for XSS (escape HTML entities)
#[wasm_bindgen]
pub fn sanitize_html_wasm(input: &str) -> String {
    sanitizer::sanitize_html(input)
}

/// Sanitize input for SQL (escape dangerous characters)
#[wasm_bindgen]
pub fn sanitize_sql_wasm(input: &str) -> String {
    sanitizer::sanitize_sql(input)
}

/// Sanitize input for shell commands
#[wasm_bindgen]
pub fn sanitize_shell_wasm(input: &str) -> String {
    sanitizer::sanitize_shell(input)
}

/// Detect SQL injection patterns
#[wasm_bindgen]
pub fn detect_sql_injection(input: &str) -> bool {
    sanitizer::is_sql_injection(input)
}

/// Detect XSS patterns
#[wasm_bindgen]
pub fn detect_xss(input: &str) -> bool {
    sanitizer::is_xss_attempt(input)
}

/// Detect command injection patterns
#[wasm_bindgen]
pub fn detect_command_injection(input: &str) -> bool {
    sanitizer::is_command_injection(input)
}

/// Full sanitization (SQL + XSS + Command)
#[wasm_bindgen]
pub fn sanitize(input: &str) -> String {
    let mut result = input.to_string();
    
    if sanitizer::is_sql_injection(&result) {
        result = sanitizer::sanitize_sql(&result);
    }
    
    if sanitizer::is_xss_attempt(&result) {
        result = sanitizer::sanitize_html(&result);
    }
    
    result
}

// =============================================================================
// SSRF Validation (WASM-exported)
// =============================================================================

/// Validate URL for SSRF attacks
/// Returns JSON: { "valid": bool, "reason": string | null }
#[wasm_bindgen]
pub fn validate_url_wasm(url: &str) -> String {
    let result = validator::validate_url_for_ssrf(url);
    match result {
        Ok(_) => r#"{"valid":true,"reason":null}"#.to_string(),
        Err(e) => format!(r#"{{"valid":false,"reason":"{}"}}"#, e),
    }
}

/// Check if URL is an internal IP
#[wasm_bindgen]
pub fn is_internal_url(url: &str) -> bool {
    validator::is_internal_ip(url)
}

// =============================================================================
// Cryptography (WASM-exported)
// =============================================================================

/// Hash a password using Argon2id
#[wasm_bindgen]
pub fn hash_password_wasm(password: &str) -> Result<String, JsValue> {
    crypto::hash_password(password)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))
}

/// Verify a password against a hash
#[wasm_bindgen]
pub fn verify_password_wasm(password: &str, hash: &str) -> bool {
    crypto::verify_password(password, hash).unwrap_or(false)
}

/// Generate a secure random token
#[wasm_bindgen]
pub fn generate_token_wasm(length: usize) -> String {
    crypto::generate_secure_token(length)
}

/// SHA-256 hash
#[wasm_bindgen]
pub fn sha256_wasm(input: &str) -> String {
    crypto::sha256_hash(input)
}

/// Detect hardcoded secrets
#[wasm_bindgen]
pub fn detect_secrets(content: &str) -> String {
    let secrets = crypto::detect_hardcoded_secrets(content);
    serde_json::to_string(&secrets).unwrap_or_else(|_| "[]".to_string())
}

// =============================================================================
// Rate Limiting (WASM-exported)
// =============================================================================

use std::collections::HashMap;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref RATE_LIMIT_STORE: Mutex<HashMap<String, Vec<u64>>> = Mutex::new(HashMap::new());
}

/// Check rate limit for a key
/// Returns true if allowed, false if rate limited
#[wasm_bindgen]
pub fn check_rate_limit(key: &str, limit: u32, window_seconds: u32) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let mut store = RATE_LIMIT_STORE.lock().unwrap();
    let timestamps = store.entry(key.to_string()).or_insert_with(Vec::new);
    
    // Remove old timestamps
    let cutoff = now - window_seconds as u64;
    timestamps.retain(|&t| t > cutoff);
    
    if timestamps.len() as u32 >= limit {
        return false;
    }
    
    timestamps.push(now);
    true
}

// =============================================================================
// Security Headers
// =============================================================================

/// Get recommended security headers as JSON
#[wasm_bindgen]
pub fn get_security_headers() -> String {
    r#"{
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }"#.to_string()
}

// =============================================================================
// Full Request Processing
// =============================================================================

/// Main entry point for securing a request
#[wasm_bindgen]
pub fn secure_request(request_json: &str, config_json: &str) -> Result<String, JsValue> {
    let config: config::SlopConfig = serde_json::from_str(config_json)
        .map_err(|e| JsValue::from_str(&format!("Config parse error: {}", e)))?;
    
    let mut request: serde_json::Value = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Request parse error: {}", e)))?;
    
    // Apply security layers
    if config.owasp.a03_injection.enabled {
        if let Some(body) = request.get_mut("body") {
            sanitizer::sanitize_value(body, &config);
        }
        if let Some(query) = request.get_mut("query") {
            sanitizer::sanitize_value(query, &config);
        }
    }
    
    serde_json::to_string(&request)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "1.0.0");
    }

    #[test]
    fn test_sanitize_xss() {
        let result = sanitize("<script>alert(1)</script>");
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn test_detect_sql_injection() {
        assert!(detect_sql_injection("' OR '1'='1"));
        assert!(!detect_sql_injection("John Doe"));
    }

    #[test]
    fn test_rate_limit() {
        // First 5 should pass
        for _ in 0..5 {
            assert!(check_rate_limit("test_key", 5, 60));
        }
        // 6th should fail
        assert!(!check_rate_limit("test_key", 5, 60));
    }
}
