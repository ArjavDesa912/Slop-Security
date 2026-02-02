//! Configuration structures for Slop Security
//! 
//! This module defines the `slop.json` schema as Rust structures.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Main configuration structure matching slop.json schema
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlopConfig {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub version: String,
    pub project: ProjectConfig,
    pub owasp: OwaspConfig,
    pub patching: PatchingConfig,
    pub sandbox: SandboxConfig,
    pub reporting: ReportingConfig,
}

impl Default for SlopConfig {
    fn default() -> Self {
        Self {
            schema: Some("https://slopsecurity.io/schema/v1.json".to_string()),
            version: "1.0.0".to_string(),
            project: ProjectConfig::default(),
            owasp: OwaspConfig::default(),
            patching: PatchingConfig::default(),
            sandbox: SandboxConfig::default(),
            reporting: ReportingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default = "default_framework")]
    pub framework: String,
}

fn default_environment() -> String {
    "production".to_string()
}

fn default_framework() -> String {
    "auto-detect".to_string()
}

/// OWASP Top 10 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OwaspConfig {
    pub a01_access_control: AccessControlConfig,
    pub a02_cryptographic_failures: CryptoConfig,
    pub a03_injection: InjectionConfig,
    pub a04_insecure_design: InsecureDesignConfig,
    pub a05_security_misconfiguration: MisconfigConfig,
    pub a06_vulnerable_components: VulnerableComponentsConfig,
    pub a07_auth_failures: AuthConfig,
    pub a08_integrity_failures: IntegrityConfig,
    pub a09_logging_failures: LoggingConfig,
    pub a10_ssrf: SsrfConfig,
}

impl Default for OwaspConfig {
    fn default() -> Self {
        Self {
            a01_access_control: AccessControlConfig::default(),
            a02_cryptographic_failures: CryptoConfig::default(),
            a03_injection: InjectionConfig::default(),
            a04_insecure_design: InsecureDesignConfig::default(),
            a05_security_misconfiguration: MisconfigConfig::default(),
            a06_vulnerable_components: VulnerableComponentsConfig::default(),
            a07_auth_failures: AuthConfig::default(),
            a08_integrity_failures: IntegrityConfig::default(),
            a09_logging_failures: LoggingConfig::default(),
            a10_ssrf: SsrfConfig::default(),
        }
    }
}

// A01: Access Control
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessControlConfig {
    pub enabled: bool,
    pub rbac: bool,
    pub audit_logging: bool,
    pub rate_limiting: RateLimitConfig,
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rbac: true,
            audit_logging: true,
            rate_limiting: RateLimitConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 100,
        }
    }
}

// A02: Cryptographic Failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    pub enabled: bool,
    pub minimum_algorithm: String,
    pub password_hashing: String,
    pub enforce_tls: bool,
    pub detect_hardcoded_secrets: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_algorithm: "aes-256-gcm".to_string(),
            password_hashing: "argon2id".to_string(),
            enforce_tls: true,
            detect_hardcoded_secrets: true,
        }
    }
}

// A03: Injection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InjectionConfig {
    pub enabled: bool,
    pub sqli_protection: bool,
    pub xss_filter: bool,
    pub command_injection: bool,
    pub nosql_injection: bool,
    pub template_injection: bool,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sqli_protection: true,
            xss_filter: true,
            command_injection: true,
            nosql_injection: true,
            template_injection: true,
        }
    }
}

// A04: Insecure Design
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InsecureDesignConfig {
    pub enabled: bool,
    pub rate_limit_auth: bool,
    pub require_mfa_prompt: bool,
    pub business_logic_checks: bool,
}

impl Default for InsecureDesignConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_auth: true,
            require_mfa_prompt: false,
            business_logic_checks: true,
        }
    }
}

// A05: Security Misconfiguration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MisconfigConfig {
    pub enabled: bool,
    pub secure_headers: bool,
    pub disable_debug: bool,
    pub cookie_security: bool,
    pub cors_policy: String,
}

impl Default for MisconfigConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            secure_headers: true,
            disable_debug: true,
            cookie_security: true,
            cors_policy: "strict".to_string(),
        }
    }
}

// A06: Vulnerable Components
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnerableComponentsConfig {
    pub enabled: bool,
    pub auto_patch: bool,
    pub severity_threshold: String,
    pub block_critical: bool,
}

impl Default for VulnerableComponentsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_patch: true,
            severity_threshold: "medium".to_string(),
            block_critical: true,
        }
    }
}

// A07: Authentication Failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub enabled: bool,
    pub brute_force_protection: BruteForceConfig,
    pub password_policy: String,
    pub session_security: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            brute_force_protection: BruteForceConfig::default(),
            password_policy: "nist-800-63b".to_string(),
            session_security: "strict".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BruteForceConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub lockout_minutes: u32,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 5,
            lockout_minutes: 15,
        }
    }
}

// A08: Integrity Failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrityConfig {
    pub enabled: bool,
    pub sri_enforcement: bool,
    pub update_verification: bool,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sri_enforcement: true,
            update_verification: true,
        }
    }
}

// A09: Logging Failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub security_events: Vec<String>,
    pub pii_redaction: bool,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            security_events: vec![
                "auth".to_string(),
                "access".to_string(),
                "injection".to_string(),
                "rate-limit".to_string(),
            ],
            pii_redaction: true,
            format: "json".to_string(),
        }
    }
}

// A10: SSRF
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SsrfConfig {
    pub enabled: bool,
    pub block_internal: bool,
    pub block_metadata: bool,
    pub dns_rebinding_protection: bool,
    pub allowlist: Vec<String>,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_internal: true,
            block_metadata: true,
            dns_rebinding_protection: true,
            allowlist: vec![],
        }
    }
}

// Patching Config
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PatchingConfig {
    pub auto_patch: bool,
    pub hardcoded_secrets: String,
    pub weak_crypto: String,
    pub eval_usage: String,
    pub open_redirects: String,
}

impl Default for PatchingConfig {
    fn default() -> Self {
        Self {
            auto_patch: true,
            hardcoded_secrets: "warn-and-move".to_string(),
            weak_crypto: "upgrade".to_string(),
            eval_usage: "sandbox".to_string(),
            open_redirects: "block".to_string(),
        }
    }
}

// Sandbox Config
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub timeout_ms: u32,
    pub memory_limit_mb: u32,
    pub allowed_permissions: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
            memory_limit_mb: 128,
            allowed_permissions: vec!["network".to_string(), "filesystem:read".to_string()],
        }
    }
}

// Reporting Config
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    pub realtime_alerts: bool,
    pub weekly_digest: bool,
    pub siem_integration: Option<String>,
    pub webhook_url: Option<String>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            realtime_alerts: true,
            weekly_digest: true,
            siem_integration: None,
            webhook_url: None,
        }
    }
}

/// Parse a slop.json configuration string
#[wasm_bindgen]
pub fn parse_config(json: &str) -> Result<JsValue, JsValue> {
    let config: SlopConfig = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("Config parse error: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&config)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

/// Get default configuration as JSON
#[wasm_bindgen]
pub fn get_default_config() -> String {
    serde_json::to_string_pretty(&SlopConfig::default()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SlopConfig::default();
        assert!(config.owasp.a03_injection.enabled);
        assert!(config.owasp.a03_injection.sqli_protection);
        assert!(config.owasp.a03_injection.xss_filter);
    }

    #[test]
    fn test_parse_config() {
        let json = r#"{"version": "1.0.0"}"#;
        let config: SlopConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.version, "1.0.0");
    }
}
