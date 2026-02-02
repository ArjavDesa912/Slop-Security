"""
Tests for Slop Security Python SDK
"""

import pytest
from slop.core import (
    detect_sql_injection,
    detect_xss,
    detect_command_injection,
    sanitize_sql,
    sanitize_html,
    sanitize_shell,
    validate_url,
    hash_password,
    verify_password,
    generate_token,
    Slop,
    SlopConfig,
    SsrfConfig,
)


class TestSQLInjection:
    def test_detects_union_select(self):
        assert detect_sql_injection("' UNION SELECT * FROM users --")
    
    def test_detects_or_1_equals_1(self):
        assert detect_sql_injection("' OR '1'='1")
    
    def test_detects_drop_table(self):
        assert detect_sql_injection("'; DROP TABLE users; --")
    
    def test_no_false_positive_on_normal_input(self):
        assert not detect_sql_injection("John Doe")
        assert not detect_sql_injection("user@example.com")
    
    def test_sanitize_escapes_quotes(self):
        result = sanitize_sql("O'Brien")
        assert "''" in result


class TestXSS:
    def test_detects_script_tags(self):
        assert detect_xss("<script>alert(1)</script>")
    
    def test_detects_javascript_protocol(self):
        assert detect_xss("javascript:alert(1)")
    
    def test_detects_event_handlers(self):
        assert detect_xss('<img onerror="alert(1)">')
    
    def test_detects_iframe(self):
        assert detect_xss('<iframe src="evil.com">')
    
    def test_no_false_positive_on_normal_html(self):
        assert not detect_xss("<p>Hello World</p>")
    
    def test_sanitize_escapes_html(self):
        result = sanitize_html("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result


class TestCommandInjection:
    def test_detects_semicolon(self):
        assert detect_command_injection("file.txt; rm -rf /")
    
    def test_detects_pipe(self):
        assert detect_command_injection("file | cat /etc/passwd")
    
    def test_detects_backticks(self):
        assert detect_command_injection("echo `whoami`")
    
    def test_detects_dollar_paren(self):
        assert detect_command_injection("$(cat /etc/passwd)")
    
    def test_sanitize_wraps_in_quotes(self):
        result = sanitize_shell("file.txt")
        assert result.startswith("'")
        assert result.endswith("'")


class TestSSRF:
    def test_blocks_localhost(self):
        valid, reason = validate_url("http://localhost:8080/admin")
        assert not valid
        assert "blocked" in reason.lower()
    
    def test_blocks_127_0_0_1(self):
        valid, reason = validate_url("http://127.0.0.1/")
        assert not valid
    
    def test_blocks_internal_ips(self):
        valid, reason = validate_url("http://192.168.1.1/")
        assert not valid
        assert "Internal" in reason
    
    def test_blocks_cloud_metadata(self):
        valid, reason = validate_url("http://169.254.169.254/latest/meta-data/")
        assert not valid
        assert "Metadata" in reason
    
    def test_allows_external_urls(self):
        valid, reason = validate_url("https://api.example.com/data")
        assert valid
    
    def test_blocks_invalid_protocol(self):
        valid, reason = validate_url("file:///etc/passwd")
        assert not valid
        assert "protocol" in reason.lower()
    
    def test_respects_allowlist(self):
        config = SsrfConfig(allowlist=["internal.company.com"])
        valid, _ = validate_url("http://internal.company.com/api", config)
        assert valid


class TestPasswordHashing:
    def test_hash_produces_different_output(self):
        hash1 = hash_password("password123")
        assert hash1 != "password123"
    
    def test_verify_correct_password(self):
        hashed = hash_password("correctpassword")
        assert verify_password("correctpassword", hashed)
    
    def test_verify_wrong_password(self):
        hashed = hash_password("correctpassword")
        assert not verify_password("wrongpassword", hashed)


class TestTokenGeneration:
    def test_generates_unique_tokens(self):
        token1 = generate_token()
        token2 = generate_token()
        assert token1 != token2
    
    def test_generates_correct_length(self):
        token = generate_token(16)
        assert len(token) >= 16


class TestSlop:
    def test_rate_limiting(self):
        from slop.core import RateLimitConfig
        config = SlopConfig(
            rate_limiting=RateLimitConfig(enabled=True, requests_per_minute=5)
        )
        slop = Slop(config)
        
        # Should allow first 5 requests
        for _ in range(5):
            assert slop.check_rate_limit("test_user_unique")
        
        # Should block 6th request
        assert not slop.check_rate_limit("test_user_unique")
    
    def test_sanitize_combined(self):
        slop = Slop()
        
        # SQL injection input
        result = slop.sanitize("' OR '1'='1")
        assert result != "' OR '1'='1"
    
    def test_security_headers(self):
        slop = Slop()
        headers = slop.get_security_headers()
        
        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in headers
        assert "Strict-Transport-Security" in headers
