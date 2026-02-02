"""
🛡️ Slop Security Core Module

Provides core security functions independent of any web framework.
"""

import re
import secrets
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse
import ipaddress

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class RateLimitConfig:
    enabled: bool = True
    requests_per_minute: int = 100


@dataclass
class BruteForceConfig:
    enabled: bool = True
    max_attempts: int = 5
    lockout_minutes: int = 15


@dataclass
class InjectionConfig:
    enabled: bool = True
    sqli_protection: bool = True
    xss_filter: bool = True
    command_injection: bool = True


@dataclass
class SsrfConfig:
    enabled: bool = True
    block_internal: bool = True
    block_metadata: bool = True
    allowlist: List[str] = field(default_factory=list)


@dataclass
class SlopConfig:
    rate_limiting: RateLimitConfig = field(default_factory=RateLimitConfig)
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    injection: InjectionConfig = field(default_factory=InjectionConfig)
    ssrf: SsrfConfig = field(default_factory=SsrfConfig)


# =============================================================================
# SQL Injection Protection
# =============================================================================

SQL_INJECTION_PATTERNS = [
    r"(?i)(\bUNION\b.*\bSELECT\b)",
    r"(?i)(\bSELECT\b.*\bFROM\b)",
    r"(?i)(\bINSERT\b.*\bINTO\b)",
    r"(?i)(\bUPDATE\b.*\bSET\b)",
    r"(?i)(\bDELETE\b.*\bFROM\b)",
    r"(?i)(\bDROP\b.*\bTABLE\b)",
    r"(?i)(--\s*$)",
    r"(?i)(/\*.*\*/)",
    r"'(\s*OR\s*'1'\s*=\s*'1)",
    r"'\s*OR\s+\d+\s*=\s*\d+",
]


def detect_sql_injection(input_str: str) -> bool:
    """Detect SQL injection patterns in input."""
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_str):
            return True
    return False


def sanitize_sql(input_str: str) -> str:
    """Sanitize SQL input by escaping dangerous characters."""
    return (
        input_str
        .replace("\\", "\\\\")
        .replace("'", "''")
        .replace('"', '\\"')
        .replace("\0", "")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


# =============================================================================
# XSS Protection
# =============================================================================

XSS_PATTERNS = [
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
]


def detect_xss(input_str: str) -> bool:
    """Detect XSS patterns in input."""
    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_str):
            return True
    return False


def sanitize_html(input_str: str) -> str:
    """Sanitize HTML by escaping dangerous characters."""
    return (
        input_str
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


# =============================================================================
# Command Injection Protection
# =============================================================================

COMMAND_INJECTION_PATTERNS = [
    r"[;&|`$]",
    r"\$\([^)]+\)",
    r"`[^`]+`",
    r"\|\|",
    r"&&",
]


def detect_command_injection(input_str: str) -> bool:
    """Detect command injection patterns in input."""
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, input_str):
            return True
    return False


def sanitize_shell(input_str: str) -> str:
    """Sanitize shell command arguments."""
    # Use single quotes and escape existing single quotes
    escaped = input_str.replace("'", "'\"'\"'")
    return f"'{escaped}'"


# =============================================================================
# SSRF Protection
# =============================================================================

INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

METADATA_HOSTS = [
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
]


def validate_url(url: str, config: Optional[SsrfConfig] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate URL for SSRF attacks.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    config = config or SsrfConfig()
    
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"
    
    # Check protocol
    if parsed.scheme not in ("http", "https"):
        return False, "Invalid protocol"
    
    host = parsed.hostname
    if not host:
        return False, "No host specified"
    
    # Check allowlist
    if config.allowlist and host in config.allowlist:
        return True, None
    
    # Check metadata hosts
    if config.block_metadata and host in METADATA_HOSTS:
        return False, "Metadata endpoint blocked"
    
    # Check localhost
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
        return False, "Localhost blocked"
    
    # Check internal IPs
    if config.block_internal:
        try:
            ip = ipaddress.ip_address(host)
            for network in INTERNAL_RANGES:
                if ip in network:
                    return False, "Internal IP blocked"
        except ValueError:
            # Not an IP address, might be a domain
            pass
    
    return True, None


# =============================================================================
# Cryptography
# =============================================================================

def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    if ARGON2_AVAILABLE:
        ph = PasswordHasher()
        return ph.hash(password)
    else:
        # Fallback to PBKDF2
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return f"pbkdf2:{salt.hex()}:{key.hex()}"


def verify_password(password: str, hash_str: str) -> bool:
    """Verify password against hash."""
    if ARGON2_AVAILABLE and hash_str.startswith("$argon2"):
        try:
            ph = PasswordHasher()
            ph.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False
    elif hash_str.startswith("pbkdf2:"):
        # PBKDF2 fallback
        parts = hash_str.split(":")
        if len(parts) != 3:
            return False
        salt = bytes.fromhex(parts[1])
        stored_key = bytes.fromhex(parts[2])
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return hmac.compare_digest(key, stored_key)
    return False


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def generate_key() -> bytes:
    """Generate a random 256-bit key."""
    return secrets.token_bytes(32)


# =============================================================================
# Main Slop Class
# =============================================================================

class Slop:
    """Main Slop Security class."""
    
    def __init__(self, config: Optional[SlopConfig] = None):
        self.config = config or SlopConfig()
        self._rate_limit_store: Dict[str, List[float]] = {}
        self._brute_force_store: Dict[str, Tuple[int, float]] = {}
    
    def sanitize(self, input_str: str) -> str:
        """Sanitize input string for all injection types."""
        result = input_str
        
        if self.config.injection.sqli_protection and detect_sql_injection(result):
            result = sanitize_sql(result)
        
        if self.config.injection.xss_filter and detect_xss(result):
            result = sanitize_html(result)
        
        if self.config.injection.command_injection and detect_command_injection(result):
            result = sanitize_shell(result)
        
        return result
    
    def check_rate_limit(self, key: str) -> bool:
        """Check if request is within rate limit."""
        if not self.config.rate_limiting.enabled:
            return True
        
        import time
        now = time.time()
        window = 60  # 1 minute
        
        timestamps = self._rate_limit_store.get(key, [])
        timestamps = [t for t in timestamps if now - t < window]
        
        if len(timestamps) >= self.config.rate_limiting.requests_per_minute:
            return False
        
        timestamps.append(now)
        self._rate_limit_store[key] = timestamps
        return True
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL for SSRF attacks."""
        return validate_url(url, self.config.ssrf)
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to add to responses."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }


# Module-level convenience functions
_default_slop = Slop()


def sanitize(input_str: str) -> str:
    """Sanitize input string using default configuration."""
    return _default_slop.sanitize(input_str)
