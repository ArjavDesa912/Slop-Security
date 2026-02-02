//! Error types for Slop Security

use thiserror::Error;
use wasm_bindgen::prelude::*;

/// Custom error types for Slop Security operations
#[derive(Error, Debug)]
pub enum SlopError {
    #[error("SQL injection attempt detected: {0}")]
    SqlInjection(String),
    
    #[error("XSS attempt detected: {0}")]
    XssAttempt(String),
    
    #[error("Command injection attempt detected: {0}")]
    CommandInjection(String),
    
    #[error("SSRF attempt detected: {0}")]
    SsrfAttempt(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl From<SlopError> for JsValue {
    fn from(error: SlopError) -> Self {
        JsValue::from_str(&error.to_string())
    }
}

/// Result type for Slop Security operations
pub type SlopResult<T> = Result<T, SlopError>;
