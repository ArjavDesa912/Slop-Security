<p align="center">
  <img src="./assets/mascot and title.png" alt="Slop Security - Zero-Cognitive-Load Security" width="500"/>
</p>

<h1 align="center">🛡️ Slop Security</h1>

<p align="center">
  <strong>Zero-Cognitive-Load Security for AI-Generated Code</strong>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-vibe-check-cli">Vibe-Check CLI</a> •
  <a href="#-sdks">SDKs</a> •
  <a href="#-features">Features</a> •
  <a href="#-documentation">Docs</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-red?style=for-the-badge" alt="OWASP Top 10"/>
  <img src="https://img.shields.io/badge/Patterns-106+-blue?style=for-the-badge" alt="106+ Patterns"/>
  <img src="https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"/>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/@slop/vibe-check?label=vibe-check&style=flat-square" alt="npm"/>
  <img src="https://img.shields.io/npm/v/@slop/security?label=node-sdk&style=flat-square" alt="npm"/>
  <img src="https://img.shields.io/pypi/v/slop-security?label=python-sdk&style=flat-square" alt="PyPI"/>
  <img src="https://img.shields.io/crates/v/slop-core?label=rust-core&style=flat-square" alt="crates.io"/>
</p>

---

## 🎯 What is Slop Security?

**Slop Security** is a comprehensive security framework designed specifically for **AI-generated code** (a.k.a. "slop"). It provides:

- 🔍 **Vibe-Check CLI** - AI-powered security scanner with 106+ vulnerability patterns
- 📦 **Multi-Language SDKs** - Drop-in security for Node.js, Python, Go, Ruby, PHP
- 🦀 **Rust WASM Core** - High-performance security primitives

> **Why "Slop"?** AI-generated code often contains security vulnerabilities that look correct but are dangerously flawed. Slop Security catches these "vibes-based" mistakes before they reach production.

---

## 🚀 Quick Start

### Install the Scanner

```bash
# npm (recommended)
npm install -g @slop/vibe-check

# or run directly
npx @slop/vibe-check .
```

### Scan Your Code

```bash
# Basic scan
vibe-check .

# With AI-powered detection
OPENAI_API_KEY=sk-xxx vibe-check . --ai

# CI/CD mode (exit code on findings)
vibe-check . --ci --fail-on critical,high
```

### Example Output

```
🔍 Vibe-Check Security Scanner v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] A02: Hardcoded AWS access key ID
  📁 src/config.js:15
  const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
  ⚡ Fix available: Run with --fix

[HIGH] A03: SQL Injection via template literal
  📁 src/db.js:42
  `SELECT * FROM users WHERE id = ${userId}`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Critical: 2  │  High: 1  │  Medium: 0  │  Low: 0
Auto-fixable: 1/3
```

---

## 🔍 Vibe-Check CLI

The **Vibe-Check** scanner combines pattern matching with AI analysis to detect security vulnerabilities in AI-generated code.

### Features

| Feature | Description |
|---------|-------------|
| **106+ Patterns** | Covers OWASP Top 10, hardcoded secrets, injection attacks |
| **AI Detection** | OpenAI, Anthropic, Ollama integration for context-aware analysis |
| **Auto-Fix** | Automatically patch common vulnerabilities |
| **CI/CD Ready** | Exit codes, JSON output, fail thresholds |
| **Multi-Language** | JavaScript, TypeScript, Python, Ruby, PHP, Go |

### CLI Options

```bash
vibe-check [path] [options]

Options:
  --include <glob>      Files to include (default: **/*.{js,ts,py,rb,php,go})
  --exclude <glob>      Files to exclude (default: node_modules, dist, .git)
  --fix                 Auto-fix detected issues
  --ci                  CI mode with exit codes
  --fail-on <levels>    Fail on severity levels (critical,high,medium,low)
  --report <format>     Output format: text, json, html
  --ai                  Enable AI-powered detection (hybrid mode)
  --ai-only             Use only AI detection (no patterns)
  --ai-provider         AI provider: openai, anthropic, ollama
  --patterns <file>     Load custom patterns from JSON file

Commands:
  vibe-check patterns   List all available vulnerability patterns
```

### Vulnerability Categories (106+ Patterns)

<details>
<summary><strong>🔐 A02: Cryptographic Failures (40+ patterns)</strong></summary>

- Hardcoded API keys (Stripe, AWS, GitHub, GitLab, Slack, Discord, SendGrid, Twilio, Google, Firebase, OpenAI, Shopify, Azure, Heroku, npm, DigitalOcean)
- Database connection strings with credentials (MongoDB, MySQL, PostgreSQL, Redis)
- Private keys (RSA, EC, OpenSSH, PGP)
- JWT secrets and weak algorithms
- Weak hashing (MD5, SHA1)
- Insecure random (Math.random, Python random)
- SSL/TLS verification disabled

</details>

<details>
<summary><strong>💉 A03: Injection (35+ patterns)</strong></summary>

- **SQL Injection**: Template literals, f-strings, string concatenation, Ruby interpolation, PHP variables
- **NoSQL Injection**: MongoDB $where, $eval
- **XSS**: innerHTML, outerHTML, document.write, React dangerouslySetInnerHTML, Vue v-html, Angular bypass, jQuery .html(), Jinja2 safe, Django autoescape off
- **Command Injection**: exec, spawn with shell, subprocess, os.system, PHP exec/system/passthru
- **Code Injection**: eval, Function constructor, setTimeout/setInterval with strings, Python exec
- **Other**: LDAP injection, XPath injection, XXE, SSTI, ReDoS

</details>

<details>
<summary><strong>🔓 A01: Broken Access Control (6 patterns)</strong></summary>

- Path traversal in file operations
- Open redirects
- Mass assignment vulnerabilities
- Missing CSRF protection

</details>

<details>
<summary><strong>⚙️ A05: Security Misconfiguration (8 patterns)</strong></summary>

- Debug mode enabled
- CORS wildcard or open configuration
- Environment variable exposure
- Error/stack trace exposure
- Insecure cookie settings

</details>

<details>
<summary><strong>🔑 A07: Authentication Failures (3 patterns)</strong></summary>

- Weak password requirements
- Timing attacks in password comparison
- Hardcoded admin credentials

</details>

<details>
<summary><strong>📦 A08: Data Integrity Failures (4 patterns)</strong></summary>

- Insecure deserialization (pickle, yaml.load, Marshal.load, unserialize)

</details>

<details>
<summary><strong>📝 A09: Logging Failures (3 patterns)</strong></summary>

- Logging passwords, tokens, or credit card data

</details>

<details>
<summary><strong>🌐 A10: SSRF (6 patterns)</strong></summary>

- Dynamic URLs in axios, fetch, request, urllib, requests, cURL

</details>

---

## 📦 SDKs

Drop-in security for your favorite framework. Zero configuration required.

### Node.js / TypeScript

```bash
npm install @slop/security
```

```typescript
import { Slop } from '@slop/security';

const slop = new Slop();

// Express middleware
app.use(slop.middleware());

// Or use individual functions
if (slop.detectSQLi(userInput)) {
  throw new Error('SQL injection detected');
}

const sanitized = slop.sanitizeHTML(userContent);
const { valid, reason } = slop.validateURL(url);
const hash = await slop.hashPassword(password);
```

### Python

```bash
pip install slop-security
```

```python
from slop import Slop

slop = Slop()

# Flask middleware
app = slop.flask_middleware(app)

# FastAPI middleware
app.add_middleware(slop.fastapi_middleware())

# Django middleware - add to MIDDLEWARE in settings.py
# 'slop.DjangoMiddleware'

# Individual functions
if slop.detect_sqli(user_input):
    raise ValueError("SQL injection detected")

sanitized = slop.sanitize_html(content)
valid, reason = slop.validate_url(url)
hashed = slop.hash_password(password)
```

### Go

```bash
go get github.com/slop-security/slop-go
```

```go
import "github.com/slop-security/slop-go/slop"

s := slop.New(slop.DefaultConfig())

// net/http middleware
http.Handle("/", s.Middleware(handler))

// Gin middleware
router.Use(s.GinMiddleware())

// Individual functions
if s.DetectSQLi(input) {
    return errors.New("SQL injection detected")
}

sanitized := s.SanitizeHTML(content)
valid, reason := s.ValidateURL(url)
hash, _ := s.HashPassword(password)
```

### Ruby

```bash
gem install slop-security
```

```ruby
require 'slop'

# Rack/Sinatra middleware
use Slop::RackMiddleware

# Rails middleware - add to application.rb
# config.middleware.use Slop::RailsMiddleware

# Individual functions
slop = Slop.new

if slop.detect_sqli?(input)
  raise "SQL injection detected"
end

sanitized = slop.sanitize_html(content)
valid, reason = slop.validate_url(url)
hash = slop.hash_password(password)
```

### PHP

```bash
composer require slop/security
```

```php
use Slop\Security;

$slop = new Security();

// Laravel middleware - add to Kernel.php
// \Slop\Laravel\SlopMiddleware::class

// Individual functions
if ($slop->detectSQLi($input)) {
    throw new Exception("SQL injection detected");
}

$sanitized = $slop->sanitizeHTML($content);
[$valid, $reason] = $slop->validateURL($url);
$hash = $slop->hashPassword($password);
```

---

## ✨ Features

### 🔒 Security Functions

| Function | Description |
|----------|-------------|
| `detectSQLi(input)` | Detect SQL injection patterns |
| `detectXSS(input)` | Detect XSS attack patterns |
| `detectCommandInjection(input)` | Detect shell command injection |
| `sanitizeSQL(input)` | Escape SQL special characters |
| `sanitizeHTML(input)` | Escape HTML entities |
| `sanitizeShell(input)` | Quote and escape shell arguments |
| `validateURL(url)` | SSRF-safe URL validation |
| `hashPassword(password)` | Argon2id password hashing |
| `verifyPassword(password, hash)` | Verify password against hash |
| `generateToken(length)` | Generate cryptographic random token |
| `checkRateLimit(key)` | Rate limiting |
| `checkBruteForce(key)` | Brute force protection |
| `getSecurityHeaders()` | Security headers for responses |

### 🛡️ Middleware Protection

All SDK middlewares automatically provide:

- ✅ Rate limiting (configurable)
- ✅ Brute force protection
- ✅ SQL injection detection
- ✅ XSS detection
- ✅ Security headers (X-Content-Type-Options, X-Frame-Options, HSTS, etc.)
- ✅ Request logging

### 📊 SSRF Validation

The `validateURL` function protects against Server-Side Request Forgery:

```javascript
const { valid, reason } = slop.validateURL("http://169.254.169.254/latest/meta-data/");
// valid: false
// reason: "Blocked: Cloud metadata endpoint"
```

**Blocked by default:**
- `localhost`, `127.0.0.1`, `::1`
- Private IP ranges (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`)
- Cloud metadata endpoints (`169.254.169.254`)
- Link-local addresses
- Non-HTTP protocols

---

## 🦀 Rust WASM Core

High-performance security primitives compiled to WebAssembly.

### Build

```bash
cd slop-core

# Linux/macOS
./build-wasm.sh

# Windows
.\build-wasm.ps1
```

### Features

- 🚀 Near-native performance
- 📦 Works in browsers and Node.js
- 🔒 Memory-safe Rust implementation
- ⚡ Zero-copy string operations

---

## 🔧 Configuration

### slop.json

```json
{
  "$schema": "https://slopsecurity.io/schema/slop.json",
  "version": "1.0",
  "rateLimiting": {
    "enabled": true,
    "requestsPerMinute": 100,
    "burstLimit": 20
  },
  "ssrf": {
    "blockedHosts": ["internal.company.com"],
    "allowedHosts": ["api.trusted.com"],
    "allowPrivateIPs": false
  },
  "headers": {
    "hsts": true,
    "contentTypeOptions": true,
    "frameOptions": "DENY",
    "xssProtection": true
  }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for AI detection |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI detection |
| `SLOP_RATE_LIMIT` | Override rate limit (requests/min) |
| `SLOP_LOG_LEVEL` | Log level: debug, info, warn, error |

---

## 🤖 AI-Powered Detection

Vibe-Check can use LLMs to detect vulnerabilities that pattern matching might miss.

### Supported Providers

| Provider | Model | Environment Variable |
|----------|-------|---------------------|
| OpenAI | gpt-4, gpt-3.5-turbo | `OPENAI_API_KEY` |
| Anthropic | claude-3-opus, claude-3-sonnet | `ANTHROPIC_API_KEY` |
| Ollama | llama2, codellama, mistral | (local) |
| Custom | Any OpenAI-compatible API | `SLOP_AI_BASE_URL` |

### Usage

```bash
# Hybrid mode (patterns + AI)
OPENAI_API_KEY=sk-xxx vibe-check . --ai

# AI only mode
ANTHROPIC_API_KEY=sk-xxx vibe-check . --ai-only --ai-provider anthropic

# Local Ollama
vibe-check . --ai --ai-provider ollama --ai-model codellama
```

---

## 📈 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Vibe-Check
        run: npx @slop/vibe-check . --ci --fail-on critical,high
        
      - name: Upload Report
        if: always()
        run: npx @slop/vibe-check . --report html > security-report.html
```

### GitLab CI

```yaml
security:
  image: node:20
  script:
    - npx @slop/vibe-check . --ci --fail-on critical,high
  artifacts:
    reports:
      codequality: vibe-check-report.json
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
npx @slop/vibe-check . --ci --fail-on critical
```

---

## 📖 Why Slop Security?

### The Problem

AI coding assistants (Copilot, ChatGPT, Claude, Cursor) generate code that often contains:

- 🔓 Hardcoded secrets and API keys
- 💉 SQL injection vulnerabilities
- 🌐 SSRF vulnerabilities
- 📝 XSS in dynamic content
- ⚡ Command injection in shell commands
- 🔐 Weak cryptographic practices

These issues look syntactically correct but are security disasters waiting to happen.

### The Solution

**Slop Security** provides:

1. **Vibe-Check Scanner** - Catch vulnerabilities before commit
2. **SDK Middleware** - Runtime protection with zero config
3. **AI Analysis** - Context-aware detection of subtle issues

---

## 🏗️ Project Structure

```
slop-security/
├── slop-core/           # Rust WASM core
├── vibe-check/          # CLI scanner
│   ├── src/
│   │   ├── cli.ts       # CLI entry point
│   │   ├── index.ts     # Scanner with 106+ patterns
│   │   └── ai-detection.ts  # LLM integration
│   └── patterns/
│       └── comprehensive.json  # Extended patterns
├── sdks/
│   ├── node/            # Node.js/TypeScript SDK
│   ├── python/          # Python SDK
│   ├── go/              # Go SDK
│   ├── ruby/            # Ruby SDK
│   └── php/             # PHP SDK
└── examples/            # Usage examples
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone the repo
git clone https://github.com/slop-security/slop.git

# Install dependencies
cd slop/vibe-check && npm install

# Run tests
npm test

# Build
npm run build
```

---

## 📜 License

MIT License - see [LICENSE](LICENSE)

---

## 🔗 Links

- [Documentation](https://docs.slopsecurity.io)
- [npm: @slop/vibe-check](https://www.npmjs.com/package/@slop/vibe-check)
- [npm: @slop/security](https://www.npmjs.com/package/@slop/security)
- [PyPI: slop-security](https://pypi.org/project/slop-security)
- [crates.io: slop-core](https://crates.io/crates/slop-core)
- [GitHub](https://github.com/slop-security/slop)
- [Discord](https://discord.gg/slopsecurity)

---

<p align="center">
  <strong>🛡️ Secure your AI-generated code with Slop Security</strong>
</p>

<p align="center">
  <sub>Built with ❤️ for the AI coding revolution</sub>
</p>

---

## 🏷️ Keywords

<!-- SEO and discoverability keywords -->

`security` `vulnerability-scanner` `static-analysis` `sast` `code-security` `ai-security` `llm-security` `copilot-security` `chatgpt-security` `cursor-security` `owasp` `owasp-top-10` `sql-injection` `xss` `ssrf` `command-injection` `secret-detection` `api-key-detection` `hardcoded-secrets` `security-scanner` `code-scanner` `devsecops` `appsec` `application-security` `web-security` `api-security` `nodejs-security` `python-security` `typescript-security` `javascript-security` `rust-security` `wasm` `webassembly` `middleware` `express-security` `fastapi-security` `flask-security` `django-security` `rails-security` `laravel-security` `gin-security` `security-headers` `rate-limiting` `brute-force-protection` `input-validation` `sanitization` `password-hashing` `argon2` `cryptography` `vibe-check` `slop` `ai-generated-code` `code-quality` `ci-cd` `github-actions` `pre-commit` `linter` `security-linter`
