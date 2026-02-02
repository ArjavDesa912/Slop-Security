<p align="center">
  <img src="../../assets/just mascot.png" alt="Slop Security Mascot" width="120"/>
</p>

# 🛡️ Slop Security - Node.js SDK

> **One line to secure, zero lines to worry.**

The official Node.js SDK for Slop Security, providing automatic OWASP Top 10 protection for AI-generated code.

## Installation

```bash
npm install @slop/security
```

## Quick Start

### Express.js

```javascript
const express = require('express');
const { secure } = require('@slop/security/express');

const app = express();
secure(app);  // 🛡️ One line. That's it.

app.get('/', (req, res) => {
  res.json({ message: 'Protected by Slop Security!' });
});

app.listen(3000);
```

### Fastify

```javascript
const fastify = require('fastify')();
const { slopPlugin } = require('@slop/security/fastify');

fastify.register(slopPlugin);

fastify.get('/', async () => {
  return { message: 'Protected by Slop Security!' };
});

fastify.listen({ port: 3000 });
```

### Next.js

```typescript
// middleware.ts
import { slopMiddleware } from '@slop/security/next';

export default slopMiddleware();

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

## What's Protected?

| OWASP ID | Vulnerability | Protection |
|----------|---------------|------------|
| A01 | Broken Access Control | Rate limiting, RBAC validation |
| A02 | Cryptographic Failures | Secret detection, secure hashing |
| A03 | Injection | SQL, XSS, Command sanitization |
| A05 | Security Misconfiguration | Secure headers via Helmet |
| A07 | Auth Failures | Brute force protection |
| A10 | SSRF | URL validation, internal IP blocking |

## API Reference

### Core Functions

```javascript
const slop = require('@slop/security');

// Sanitize input (removes XSS, SQL injection patterns)
const safe = slop.sanitize(userInput);

// Check rate limit
if (!slop.checkRateLimit(userId)) {
  return res.status(429).json({ error: 'Too many requests' });
}

// Validate URL for SSRF
const { valid, reason } = slop.validateUrl(url);

// Sandbox execution
const result = await slop.secure(async () => {
  // Untrusted code runs here with timeout protection
  return await riskyOperation();
}, { timeout: 5000 });
```

### Express Middleware Options

```javascript
const { secure } = require('@slop/security/express');

secure(app, {
  trustProxy: true,  // Enable if behind load balancer
  owasp: {
    a01_access_control: {
      rate_limiting: {
        enabled: true,
        requests_per_minute: 100
      }
    },
    a07_auth_failures: {
      brute_force_protection: {
        max_attempts: 5,
        lockout_minutes: 15
      }
    }
  }
});
```

### Brute Force Protection

```javascript
const { bruteForceProtection } = require('@slop/security/express');

app.post('/login', bruteForceProtection(), async (req, res) => {
  const user = await authenticate(req.body);
  
  if (!user) {
    req.authFailure();  // Record failed attempt
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  req.authSuccess();  // Clear failed attempts
  res.json({ token: generateToken(user) });
});
```

## Configuration

Create a `slop.json` file in your project root:

```json
{
  "$schema": "https://slopsecurity.io/schema/v1.json",
  "version": "1.0.0",
  "owasp": {
    "a03_injection": {
      "sqli_protection": true,
      "xss_filter": true
    },
    "a10_ssrf": {
      "block_internal": true,
      "allowlist": ["api.trusted-service.com"]
    }
  }
}
```

## License

MIT
