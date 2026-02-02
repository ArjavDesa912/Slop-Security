//! Input Validation Module - SSRF protection, schema validation

use regex::Regex;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::net::IpAddr;
use url::Url;

/// SSRF validation result
#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq)]
pub enum UrlValidation {
    Safe,
    BlockedInternal,
    BlockedMetadata,
    BlockedProtocol,
    Invalid,
}

/// Internal IP ranges that should be blocked
const INTERNAL_RANGES: &[(&str, &str)] = &[
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("0.0.0.0", "0.255.255.255"),
];

/// Cloud metadata endpoints
const METADATA_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "169.254.170.2",
];

/// Validate URL for SSRF attacks
#[wasm_bindgen]
pub fn validate_url_ssrf(url_str: &str) -> UrlValidation {
    let url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return UrlValidation::Invalid,
    };

    // Check protocol
    match url.scheme() {
        "http" | "https" => {}
        _ => return UrlValidation::BlockedProtocol,
    }

    let host = match url.host_str() {
        Some(h) => h,
        None => return UrlValidation::Invalid,
    };

    // Check metadata hosts
    if METADATA_HOSTS.iter().any(|&m| host == m) {
        return UrlValidation::BlockedMetadata;
    }

    // Check localhost
    if host == "localhost" || host.ends_with(".localhost") {
        return UrlValidation::BlockedInternal;
    }

    // Try to parse as IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_ip(&ip) {
            return UrlValidation::BlockedInternal;
        }
    }

    UrlValidation::Safe
}

fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Input validation schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSchema {
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: Option<bool>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

/// Validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Validate input against schema
#[wasm_bindgen]
pub fn validate_input(value: &str, schema_json: &str) -> Result<bool, JsValue> {
    let schema: ValidationSchema = serde_json::from_str(schema_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    match schema.field_type.as_str() {
        "string" => validate_string(value, &schema),
        "number" => validate_number(value, &schema),
        "email" => validate_email(value),
        "url" => validate_url(value),
        _ => Ok(true),
    }
    .map_err(|e| JsValue::from_str(&e))
}

fn validate_string(value: &str, schema: &ValidationSchema) -> Result<bool, String> {
    if let Some(min) = schema.min_length {
        if value.len() < min {
            return Err(format!("Must be at least {} characters", min));
        }
    }
    if let Some(max) = schema.max_length {
        if value.len() > max {
            return Err(format!("Must be at most {} characters", max));
        }
    }
    if let Some(ref pattern) = schema.pattern {
        let re = Regex::new(pattern).map_err(|e| e.to_string())?;
        if !re.is_match(value) {
            return Err("Does not match pattern".to_string());
        }
    }
    Ok(true)
}

fn validate_number(value: &str, schema: &ValidationSchema) -> Result<bool, String> {
    let num: f64 = value.parse().map_err(|_| "Not a valid number")?;
    if let Some(min) = schema.min {
        if num < min {
            return Err(format!("Must be at least {}", min));
        }
    }
    if let Some(max) = schema.max {
        if num > max {
            return Err(format!("Must be at most {}", max));
        }
    }
    Ok(true)
}

fn validate_email(value: &str) -> Result<bool, String> {
    let re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if re.is_match(value) { Ok(true) } else { Err("Invalid email".to_string()) }
}

fn validate_url(value: &str) -> Result<bool, String> {
    Url::parse(value).map(|_| true).map_err(|_| "Invalid URL".to_string())
}

/// Validate password against NIST 800-63B
#[wasm_bindgen]
pub fn validate_password_nist(password: &str) -> Result<bool, JsValue> {
    if password.len() < 8 {
        return Err(JsValue::from_str("Password must be at least 8 characters"));
    }
    if password.len() > 64 {
        return Err(JsValue::from_str("Password must be at most 64 characters"));
    }
    // Check common passwords
    let common = ["password", "12345678", "qwerty", "letmein", "admin"];
    if common.iter().any(|&c| password.to_lowercase().contains(c)) {
        return Err(JsValue::from_str("Password is too common"));
    }
    Ok(true)
}

/// Validate JWT structure
#[wasm_bindgen]
pub fn validate_jwt_structure(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}
