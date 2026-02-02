# 🛡️ Slop Security - Python SDK

> **One line to secure, zero lines to worry.**

The official Python SDK for Slop Security, providing automatic OWASP Top 10 protection for AI-generated code.

## Installation

```bash
pip install slop-security

# With framework support
pip install slop-security[flask]
pip install slop-security[fastapi]
pip install slop-security[django]
```

## Quick Start

### Flask

```python
from flask import Flask
from slop import secure

app = Flask(__name__)
secure(app)  # 🛡️ One line. That's it.

@app.route('/')
def hello():
    return {'message': 'Protected by Slop Security!'}

if __name__ == '__main__':
    app.run()
```

### FastAPI

```python
from fastapi import FastAPI
from slop.fastapi import SlopMiddleware

app = FastAPI()
app.add_middleware(SlopMiddleware)  # 🛡️ One line

@app.get('/')
async def root():
    return {'message': 'Protected by Slop Security!'}
```

### Django

Add to your `settings.py`:

```python
MIDDLEWARE = [
    'slop.django.SlopSecurityMiddleware',  # 🛡️ Add at top
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware
]
```

## What's Protected?

| OWASP ID | Vulnerability | Protection |
|----------|---------------|------------|
| A01 | Broken Access Control | Rate limiting |
| A02 | Cryptographic Failures | Argon2id passwords, secure tokens |
| A03 | Injection | SQL, XSS, Command sanitization |
| A05 | Security Misconfiguration | Secure headers |
| A07 | Auth Failures | Brute force protection |
| A10 | SSRF | URL validation, internal IP blocking |

## Core Functions

```python
from slop import (
    sanitize,
    sanitize_sql,
    sanitize_html,
    detect_sql_injection,
    detect_xss,
    validate_url,
    hash_password,
    verify_password,
    generate_token,
)

# Sanitize user input
safe_input = sanitize(user_input)

# Detect SQL injection
if detect_sql_injection(query_param):
    raise SecurityError("SQL injection detected")

# Validate URL for SSRF
valid, reason = validate_url(url)
if not valid:
    raise SecurityError(f"Invalid URL: {reason}")

# Password hashing (Argon2id)
hashed = hash_password("user_password")
is_valid = verify_password("user_password", hashed)

# Generate secure tokens
token = generate_token(32)
```

## Decorators

### Rate Limiting

```python
from flask import Flask
from slop.flask import rate_limit

app = Flask(__name__)

@app.route('/api/expensive')
@rate_limit(requests_per_minute=10)
def expensive_operation():
    return {'result': 'ok'}
```

### Brute Force Protection

```python
from flask import Flask, request, g
from slop.flask import brute_force_protection

app = Flask(__name__)

@app.route('/login', methods=['POST'])
@brute_force_protection(max_attempts=5, lockout_minutes=15)
def login():
    user = authenticate(request.json)
    
    if not user:
        g.auth_failure()  # Record failed attempt
        return {'error': 'Invalid credentials'}, 401
    
    g.auth_success()  # Clear failed attempts
    return {'token': generate_token()}
```

## Configuration

```python
from slop import Slop, SlopConfig

config = SlopConfig(
    rate_limiting={"enabled": True, "requests_per_minute": 100},
    brute_force={"max_attempts": 5, "lockout_minutes": 15},
    injection={"sqli_protection": True, "xss_filter": True},
    ssrf={"block_internal": True, "allowlist": ["api.trusted.com"]},
)

slop = Slop(config)
```

## License

MIT
