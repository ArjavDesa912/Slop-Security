<p align="center">
  <img src="../assets/just mascot.png" alt="Slop Security Mascot" width="120"/>
</p>

# 🔍 Vibe-Check

<p align="center">
  <strong>AI-Powered Security Scanner for AI-Generated Code</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/@slop/vibe-check?style=for-the-badge&color=blue" alt="npm"/>
  <img src="https://img.shields.io/badge/Patterns-106+-purple?style=for-the-badge" alt="106+ Patterns"/>
  <img src="https://img.shields.io/badge/AI-OpenAI%20%7C%20Anthropic%20%7C%20Ollama-green?style=for-the-badge" alt="AI Providers"/>
</p>

---

**Vibe-Check** is a security scanner that catches vulnerabilities in AI-generated code ("slop") before they reach production. It combines **106+ pattern-based rules** with **AI-powered analysis** to detect secrets, injection attacks, and misconfigurations.

## ⚡ Quick Start

```bash
# Install globally
npm install -g @slop/vibe-check

# Scan current directory
vibe-check .

# With AI detection
OPENAI_API_KEY=sk-xxx vibe-check . --ai
```

## 🎯 What It Detects

| Category | Patterns | Examples |
|----------|----------|----------|
| **Hardcoded Secrets** | 40+ | AWS keys, Stripe, GitHub tokens, OpenAI keys, database URIs |
| **SQL Injection** | 10+ | Template literals, f-strings, string concatenation |
| **XSS** | 10+ | innerHTML, React dangerouslySetInnerHTML, Vue v-html |
| **Command Injection** | 10+ | exec, spawn, subprocess, os.system |
| **SSRF** | 6+ | axios, fetch, requests with dynamic URLs |
| **Deserialization** | 4+ | pickle, yaml.load, Marshal.load, unserialize |
| **Misconfigurations** | 10+ | Debug mode, CORS wildcards, insecure cookies |

**Total: 106+ vulnerability patterns covering OWASP Top 10**

## 📋 Usage

### Basic Scanning

```bash
# Scan directory
vibe-check ./src

# Scan with specific file patterns
vibe-check . --include "**/*.{js,ts,py}"

# Exclude directories
vibe-check . --exclude "vendor/**,tests/**"
```

### AI-Powered Detection

```bash
# Hybrid mode (patterns + AI)
OPENAI_API_KEY=sk-xxx vibe-check . --ai

# AI-only mode
ANTHROPIC_API_KEY=sk-xxx vibe-check . --ai-only --ai-provider anthropic

# Local Ollama
vibe-check . --ai --ai-provider ollama --ai-model codellama
```

### Auto-Fix

```bash
# Preview fixable issues
vibe-check .

# Apply automatic fixes
vibe-check . --fix
```

### CI/CD Mode

```bash
# Exit with error code on findings
vibe-check . --ci

# Fail only on critical/high severity
vibe-check . --ci --fail-on critical,high

# JSON output for parsing
vibe-check . --report json > results.json

# HTML report
vibe-check . --report html > report.html
```

### Custom Patterns

```bash
# Load additional patterns from JSON file
vibe-check . --patterns custom-patterns.json
```

## 🔧 CLI Options

```
Usage: vibe-check [options] [command] [path]

Arguments:
  path                      Path to scan (default: ".")

Options:
  --include <glob>          Include files matching glob pattern
  --exclude <glob>          Exclude files matching glob pattern  
  --fix                     Auto-fix detected issues
  --ci                      CI mode with exit codes
  --fail-on <levels>        Fail on severity levels (critical,high,medium,low)
  --report <format>         Output format: text, json, html
  --ai                      Enable AI-powered detection (hybrid)
  --ai-only                 Use only AI detection
  --ai-provider <provider>  AI provider: openai, anthropic, ollama
  --ai-model <model>        AI model to use
  --patterns <file>         Load custom patterns from JSON file
  -V, --version             Show version
  -h, --help                Show help

Commands:
  patterns                  List all available vulnerability patterns
```

## 📊 Example Output

```
🔍 Vibe-Check Security Scanner v1.0.0
🤖 AI Detection: Enabled (OpenAI gpt-4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✔ Scanned 42 files

[CRITICAL] A02: Hardcoded AWS access key ID
  📁 src/config.js:15
  const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
  ⚡ Fix: Replace with process.env.AWS_ACCESS_KEY_ID

[CRITICAL] A03: SQL Injection via template literal
  📁 src/db.js:42
  const query = `SELECT * FROM users WHERE id = ${userId}`;

[HIGH] A03: XSS: React dangerouslySetInnerHTML
  📁 src/components/Content.tsx:28
  <div dangerouslySetInnerHTML={{ __html: userContent }} />

[HIGH] A10: SSRF: Variable URL in fetch [AI]
  📁 src/api.js:55
  const response = await fetch(url);
  💡 Validate URL against allowlist before fetching

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Critical: 2  │  High: 2  │  Medium: 1  │  Low: 0
Auto-fixable: 1/5

Run 'vibe-check . --fix' to auto-patch 1 issue
```

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vibe-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Vibe-Check
        run: npx @slop/vibe-check . --ci --fail-on critical,high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx @slop/vibe-check . --ci --fail-on critical
```

### GitLab CI

```yaml
security:
  image: node:20
  script:
    - npx @slop/vibe-check . --ci --fail-on critical,high --report json > gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

## 📁 Custom Patterns

Create a JSON file with your own patterns:

```json
{
  "patterns": [
    {
      "id": "internal-api-key",
      "pattern": "INTERNAL_[A-Z0-9]{32}",
      "severity": "critical",
      "owaspId": "A02",
      "owaspName": "Cryptographic Failures",
      "message": "Internal API key detected"
    }
  ]
}
```

Then run:

```bash
vibe-check . --patterns custom-patterns.json
```

## 🧠 AI Detection

AI detection uses LLMs to catch vulnerabilities that pattern matching might miss:

- **Context-aware**: Understands code flow and data handling
- **Novel vulnerabilities**: Detects issues without predefined patterns
- **Explanations**: Provides human-readable explanations
- **Suggestions**: Offers remediation guidance

### Supported Providers

| Provider | Models | Setup |
|----------|--------|-------|
| **OpenAI** | gpt-4, gpt-4-turbo, gpt-3.5-turbo | `OPENAI_API_KEY` |
| **Anthropic** | claude-3-opus, claude-3-sonnet | `ANTHROPIC_API_KEY` |
| **Ollama** | llama2, codellama, mistral | Local install |
| **Custom** | Any OpenAI-compatible API | `SLOP_AI_BASE_URL` |

## 🛠️ Programmatic API

```typescript
import { scanWithPatterns, scanContent, DEFAULT_PATTERNS } from '@slop/vibe-check';

// Pattern-based scanning
const results = scanWithPatterns(code, 'file.js');

// AI + Pattern scanning
const results = await scanContent(code, 'file.js', { 
  aiMode: 'hybrid' 
});

// Access all 106 patterns
console.log(`Loaded ${DEFAULT_PATTERNS.length} patterns`);
```

## 📜 License

MIT

---

<p align="center">
  <strong>Part of the <a href="https://github.com/slop-security/slop">Slop Security</a> project</strong>
</p>

<p align="center">
  <code>npm install -g @slop/vibe-check</code>
</p>
