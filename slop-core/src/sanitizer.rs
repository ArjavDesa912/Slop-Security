//! Input Sanitization Module
//! 
//! Provides comprehensive protection against injection attacks including:
//! - SQL Injection (A03)
//! - XSS (A03)
//! - Command Injection (A03)
//! - NoSQL Injection (A03)
//! - Template Injection (A03)

use regex::Regex;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use crate::config::SlopConfig;
use crate::error::{SlopError, SlopResult};

// ============================================================================
// SQL INJECTION PREVENTION
// ============================================================================

/// SQL injection patterns to detect
const SQL_INJECTION_PATTERNS: &[&str] = &[
    r"(?i)(\bUNION\b.*\bSELECT\b)",
    r"(?i)(\bSELECT\b.*\bFROM\b)",
    r"(?i)(\bINSERT\b.*\bINTO\b)",
    r"(?i)(\bUPDATE\b.*\bSET\b)",
    r"(?i)(\bDELETE\b.*\bFROM\b)",
    r"(?i)(\bDROP\b.*\bTABLE\b)",
    r"(?i)(\bOR\b.*=.*\bOR\b)",
    r"(?i)(--\s*$)",
    r"(?i)(/\*.*\*/)",
    r"(?i)(\bEXEC\b.*\bXP_)",
    r"(?i)(;\s*\bSHUTDOWN\b)",
    r"(?i)(\bWAITFOR\b.*\bDELAY\b)",
    r"'(\s*OR\s*'1'\s*=\s*'1)",
    r"'\s*OR\s+\d+\s*=\s*\d+",
    r"(?i)(\bHAVING\b.*\d+\s*=\s*\d+)",
    r"(?i)(\bORDER\s+BY\b.*\d+)",
];

/// Represents a safe, parameterized SQL query
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct SafeQuery {
    query: String,
    params: Vec<String>,
}

#[wasm_bindgen]
impl SafeQuery {
    #[wasm_bindgen(getter)]
    pub fn query(&self) -> String {
        self.query.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> Vec<String> {
        self.params.clone()
    }
}

/// Check if input contains SQL injection patterns
#[wasm_bindgen]
pub fn detect_sql_injection(input: &str) -> bool {
    for pattern in SQL_INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Sanitize SQL input by escaping dangerous characters
#[wasm_bindgen]
pub fn sanitize_sql(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('\'', "''")
        .replace('"', "\\\"")
        .replace('\0', "")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\x1a', "\\Z")
}

/// Create a parameterized query from a template
/// Template uses $1, $2, etc. for parameters
#[wasm_bindgen]
pub fn parameterize_query(template: &str, params_json: &str) -> Result<String, JsValue> {
    let params: Vec<String> = serde_json::from_str(params_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid params JSON: {}", e)))?;
    
    let mut result = template.to_string();
    for (i, param) in params.iter().enumerate() {
        let placeholder = format!("${}", i + 1);
        let sanitized = sanitize_sql(param);
        result = result.replace(&placeholder, &format!("'{}'", sanitized));
    }
    
    Ok(result)
}

// ============================================================================
// XSS PREVENTION
// ============================================================================

/// XSS patterns to detect
const XSS_PATTERNS: &[&str] = &[
    r"(?i)<script[^>]*>",
    r"(?i)</script>",
    r"(?i)javascript:",
    r"(?i)vbscript:",
    r"(?i)on\w+\s*=",
    r"(?i)<iframe",
    r"(?i)<object",
    r"(?i)<embed",
    r"(?i)<svg.*onload",
    r"(?i)<img.*onerror",
    r"(?i)expression\s*\(",
    r"(?i)url\s*\(\s*['\"]?\s*javascript",
    r"(?i)data:\s*text/html",
    r"(?i)<meta.*http-equiv",
    r"(?i)<base\s+href",
];

/// HTML context for encoding
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HtmlContext {
    /// Content between HTML tags
    Content,
    /// Inside an HTML attribute (double-quoted)
    Attribute,
    /// Inside a JavaScript context
    JavaScript,
    /// Inside a URL context
    Url,
    /// Inside CSS context
    Css,
}

/// Check if input contains XSS patterns
#[wasm_bindgen]
pub fn detect_xss(input: &str) -> bool {
    for pattern in XSS_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Sanitize HTML content (escape dangerous characters)
#[wasm_bindgen]
pub fn sanitize_html(input: &str) -> String {
    html_escape::encode_text(input).to_string()
}

/// Sanitize for HTML attribute context
#[wasm_bindgen]
pub fn sanitize_html_attribute(input: &str) -> String {
    html_escape::encode_double_quoted_attribute(input).to_string()
}

/// Sanitize for JavaScript context
#[wasm_bindgen]
pub fn sanitize_javascript(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("\\'"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '<' => result.push_str("\\x3c"),
            '>' => result.push_str("\\x3e"),
            '&' => result.push_str("\\x26"),
            '/' => result.push_str("\\/"),
            _ if c.is_control() => {
                result.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ => result.push(c),
        }
    }
    result
}

/// Sanitize for URL context
#[wasm_bindgen]
pub fn sanitize_url(input: &str) -> String {
    // Check for dangerous protocols
    let lower = input.to_lowercase();
    if lower.starts_with("javascript:") 
        || lower.starts_with("vbscript:")
        || lower.starts_with("data:text/html")
    {
        return String::new();
    }
    
    // URL encode special characters
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

/// Context-aware HTML sanitization
#[wasm_bindgen]
pub fn sanitize_html_context(input: &str, context: HtmlContext) -> String {
    match context {
        HtmlContext::Content => sanitize_html(input),
        HtmlContext::Attribute => sanitize_html_attribute(input),
        HtmlContext::JavaScript => sanitize_javascript(input),
        HtmlContext::Url => sanitize_url(input),
        HtmlContext::Css => sanitize_css(input),
    }
}

/// Sanitize for CSS context
#[wasm_bindgen]
pub fn sanitize_css(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\'' => result.push_str("\\'"),
            '<' => result.push_str("\\3c "),
            '>' => result.push_str("\\3e "),
            '(' => result.push_str("\\28 "),
            ')' => result.push_str("\\29 "),
            '{' => result.push_str("\\7b "),
            '}' => result.push_str("\\7d "),
            _ if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' => result.push(c),
            _ => result.push_str(&format!("\\{:x} ", c as u32)),
        }
    }
    result
}

// ============================================================================
// COMMAND INJECTION PREVENTION
// ============================================================================

/// Command injection patterns
const COMMAND_INJECTION_PATTERNS: &[&str] = &[
    r"[;&|`$]",
    r"\$\([^)]+\)",
    r"`[^`]+`",
    r"\|\|",
    r"&&",
    r">\s*\w",
    r"<\s*\w",
    r"\d+>\s*&\s*\d+",
    r"(?i)\b(chmod|chown|rm|mv|cp|wget|curl|bash|sh|zsh|powershell)\b",
];

/// Check if input contains command injection patterns
#[wasm_bindgen]
pub fn detect_command_injection(input: &str) -> bool {
    for pattern in COMMAND_INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Sanitize shell command arguments
#[wasm_bindgen]
pub fn sanitize_shell(input: &str) -> String {
    // For shell safety, we use single quotes and escape any existing single quotes
    let escaped = input.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

// ============================================================================
// NOSQL INJECTION PREVENTION
// ============================================================================

/// NoSQL injection patterns (MongoDB-style)
const NOSQL_INJECTION_PATTERNS: &[&str] = &[
    r"\$where",
    r"\$gt",
    r"\$lt",
    r"\$gte",
    r"\$lte",
    r"\$ne",
    r"\$in",
    r"\$nin",
    r"\$or",
    r"\$and",
    r"\$not",
    r"\$regex",
    r"\$exists",
    r"\$type",
    r"\$expr",
    r"\$jsonSchema",
];

/// Check if input contains NoSQL injection patterns
#[wasm_bindgen]
pub fn detect_nosql_injection(input: &str) -> bool {
    for pattern in NOSQL_INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Sanitize NoSQL input by removing MongoDB operators
#[wasm_bindgen]
pub fn sanitize_nosql(input: &str) -> String {
    let mut result = input.to_string();
    for pattern in NOSQL_INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            result = re.replace_all(&result, "").to_string();
        }
    }
    result
}

// ============================================================================
// TEMPLATE INJECTION PREVENTION
// ============================================================================

/// Template injection patterns
const TEMPLATE_INJECTION_PATTERNS: &[&str] = &[
    r"\{\{.*\}\}",        // Mustache/Handlebars/Jinja2
    r"\$\{.*\}",          // ES6 template literals
    r"<%.*%>",            // EJS/ERB
    r"#\{.*\}",           // Ruby interpolation
    r"\{#.*#\}",          // Jinja2 comments
    r"\{%.*%\}",          // Jinja2 statements
    r"@\{.*\}",           // Blade
];

/// Check if input contains template injection patterns
#[wasm_bindgen]
pub fn detect_template_injection(input: &str) -> bool {
    for pattern in TEMPLATE_INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Sanitize template input by escaping template syntax
#[wasm_bindgen]
pub fn sanitize_template(input: &str) -> String {
    input
        .replace('{', "&#123;")
        .replace('}', "&#125;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('$', "&#36;")
        .replace('#', "&#35;")
        .replace('@', "&#64;")
}

// ============================================================================
// GENERIC VALUE SANITIZATION
// ============================================================================

/// Sanitize a JSON value recursively based on config
pub fn sanitize_value(value: &mut Value, config: &SlopConfig) {
    match value {
        Value::String(s) => {
            let mut sanitized = s.clone();
            
            if config.owasp.a03_injection.sqli_protection && detect_sql_injection(&sanitized) {
                sanitized = sanitize_sql(&sanitized);
            }
            
            if config.owasp.a03_injection.xss_filter && detect_xss(&sanitized) {
                sanitized = sanitize_html(&sanitized);
            }
            
            if config.owasp.a03_injection.command_injection && detect_command_injection(&sanitized) {
                sanitized = sanitize_shell(&sanitized);
            }
            
            if config.owasp.a03_injection.nosql_injection && detect_nosql_injection(&sanitized) {
                sanitized = sanitize_nosql(&sanitized);
            }
            
            if config.owasp.a03_injection.template_injection && detect_template_injection(&sanitized) {
                sanitized = sanitize_template(&sanitized);
            }
            
            *s = sanitized;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_value(item, config);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                sanitize_value(v, config);
            }
        }
        _ => {}
    }
}

/// Comprehensive sanitization of a string
#[wasm_bindgen]
pub fn sanitize_all(input: &str) -> String {
    let mut result = input.to_string();
    
    // Apply all sanitizations
    if detect_sql_injection(&result) {
        result = sanitize_sql(&result);
    }
    if detect_xss(&result) {
        result = sanitize_html(&result);
    }
    if detect_command_injection(&result) {
        // For command injection, we just escape rather than wrap
        result = result
            .replace('&', "")
            .replace('|', "")
            .replace(';', "")
            .replace('`', "")
            .replace('$', "");
    }
    if detect_nosql_injection(&result) {
        result = sanitize_nosql(&result);
    }
    if detect_template_injection(&result) {
        result = sanitize_template(&result);
    }
    
    result
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        assert!(detect_sql_injection("' OR '1'='1"));
        assert!(detect_sql_injection("1; DROP TABLE users--"));
        assert!(detect_sql_injection("UNION SELECT * FROM passwords"));
        assert!(!detect_sql_injection("normal input"));
        assert!(!detect_sql_injection("john.doe@example.com"));
    }

    #[test]
    fn test_sql_sanitization() {
        assert_eq!(sanitize_sql("O'Reilly"), "O''Reilly");
        assert_eq!(sanitize_sql("test\\path"), "test\\\\path");
    }

    #[test]
    fn test_xss_detection() {
        assert!(detect_xss("<script>alert('xss')</script>"));
        assert!(detect_xss("javascript:alert(1)"));
        assert!(detect_xss("<img onerror=alert(1)>"));
        assert!(!detect_xss("normal text"));
        assert!(!detect_xss("<p>Hello World</p>")); // Valid HTML, no XSS
    }

    #[test]
    fn test_html_sanitization() {
        assert_eq!(sanitize_html("<script>alert('xss')</script>"), 
                   "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    #[test]
    fn test_command_injection_detection() {
        assert!(detect_command_injection("ls; rm -rf /"));
        assert!(detect_command_injection("echo `whoami`"));
        assert!(detect_command_injection("cat file | grep secret"));
        assert!(!detect_command_injection("normal text"));
    }

    #[test]
    fn test_nosql_injection_detection() {
        assert!(detect_nosql_injection(r#"{"$gt": ""}"#));
        assert!(detect_nosql_injection(r#"{"username": {"$ne": null}}"#));
        assert!(!detect_nosql_injection("normal query"));
    }

    #[test]
    fn test_template_injection_detection() {
        assert!(detect_template_injection("{{constructor.constructor('return this')()}}"));
        assert!(detect_template_injection("${7*7}"));
        assert!(detect_template_injection("<%= system('id') %>"));
        assert!(!detect_template_injection("normal text"));
    }
}
