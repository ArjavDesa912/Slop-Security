/**
 * 🔍 Vibe-Check - Security Scanner for AI-Generated Code
 * 
 * Combines pattern-based detection with AI-powered analysis
 * for comprehensive security scanning.
 */

export interface ScanResult {
    file: string;
    line: number;
    column?: number;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    owaspId: string;
    owaspName: string;
    message: string;
    snippet: string;
    fix?: { before: string; after: string };
    suggestion?: string;
    confidence?: number;
    source: 'pattern' | 'ai';
}

export interface ScanOptions {
    fix?: boolean;
    ci?: boolean;
    failOn?: ('critical' | 'high' | 'medium' | 'low')[];
    include?: string[];
    exclude?: string[];
    aiMode?: 'off' | 'only' | 'hybrid';
}

export interface VulnerabilityPattern {
    id: string;
    pattern: RegExp;
    severity: ScanResult['severity'];
    owaspId: string;
    owaspName: string;
    message: string;
    getFix?: (match: string, context: string) => { before: string; after: string } | undefined;
}

// =============================================================================
// CONFIGURABLE VULNERABILITY PATTERNS
// These can be extended or overridden via configuration files
// =============================================================================

export const DEFAULT_PATTERNS: VulnerabilityPattern[] = [
    // ===========================================================================
    // A02: CRYPTOGRAPHIC FAILURES - Hardcoded Secrets (40+ patterns)
    // ===========================================================================
    {
        id: 'hardcoded-stripe-key',
        pattern: /["']sk_live_[a-zA-Z0-9]{24,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Stripe live secret key',
        getFix: (match) => ({ before: match, after: 'process.env.STRIPE_SECRET_KEY' }),
    },
    {
        id: 'hardcoded-stripe-test',
        pattern: /["']sk_test_[a-zA-Z0-9]{24,}["']/g,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Stripe test key (use env vars)',
    },
    {
        id: 'hardcoded-aws-key',
        pattern: /["']AKIA[A-Z0-9]{12,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded AWS access key ID',
        getFix: (match) => ({ before: match, after: 'process.env.AWS_ACCESS_KEY_ID' }),
    },
    {
        id: 'hardcoded-github-pat',
        pattern: /["']ghp_[a-zA-Z0-9]{36,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded GitHub personal access token',
        getFix: (match) => ({ before: match, after: 'process.env.GITHUB_TOKEN' }),
    },
    {
        id: 'hardcoded-github-oauth',
        pattern: /["']gho_[a-zA-Z0-9]{36,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded GitHub OAuth token',
    },
    {
        id: 'hardcoded-gitlab-pat',
        pattern: /["']glpat-[a-zA-Z0-9_-]{20,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded GitLab personal access token',
    },
    {
        id: 'hardcoded-slack-token',
        pattern: /["']xox[baprs]-[a-zA-Z0-9-]{10,}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Slack token',
    },
    {
        id: 'hardcoded-slack-webhook',
        pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Slack webhook URL',
    },
    {
        id: 'hardcoded-discord-token',
        pattern: /["'][MN][A-Za-z0-9]{23,}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Discord bot token',
    },
    {
        id: 'hardcoded-discord-webhook',
        pattern: /discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Discord webhook URL',
    },
    {
        id: 'hardcoded-sendgrid-key',
        pattern: /["']SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded SendGrid API key',
    },
    {
        id: 'hardcoded-mailgun-key',
        pattern: /["']key-[a-zA-Z0-9]{32}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Mailgun API key',
    },
    {
        id: 'hardcoded-twilio-sid',
        pattern: /["']AC[a-f0-9]{32}["']/g,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Twilio Account SID',
    },
    {
        id: 'hardcoded-twilio-key',
        pattern: /["']SK[a-f0-9]{32}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Twilio API key',
    },
    {
        id: 'hardcoded-google-api',
        pattern: /["']AIza[A-Za-z0-9_-]{35}["']/g,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Google API key',
    },
    {
        id: 'hardcoded-firebase-key',
        pattern: /["']AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Firebase Cloud Messaging key',
    },
    {
        id: 'hardcoded-digitalocean',
        pattern: /["']dop_v1_[a-f0-9]{64}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded DigitalOcean access token',
    },
    {
        id: 'hardcoded-npm-token',
        pattern: /["']npm_[A-Za-z0-9]{36}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded npm access token',
    },
    {
        id: 'hardcoded-private-key-rsa',
        pattern: /-----BEGIN RSA PRIVATE KEY-----/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded RSA private key',
    },
    {
        id: 'hardcoded-private-key-ec',
        pattern: /-----BEGIN EC PRIVATE KEY-----/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded EC private key',
    },
    {
        id: 'hardcoded-private-key-openssh',
        pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded OpenSSH private key',
    },
    {
        id: 'hardcoded-mongodb-uri',
        pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded MongoDB connection with credentials',
    },
    {
        id: 'hardcoded-mysql-uri',
        pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded MySQL connection with credentials',
    },
    {
        id: 'hardcoded-postgres-uri',
        pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded PostgreSQL connection with credentials',
    },
    {
        id: 'hardcoded-redis-uri',
        pattern: /redis:\/\/[^:]*:[^@]+@[^/]+/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Redis connection with credentials',
    },
    {
        id: 'hardcoded-jwt-secret',
        pattern: /(jwt[_-]?secret|JWT_SECRET)\s*[:=]\s*["'][^"']{16,}["']/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded JWT secret',
    },
    {
        id: 'hardcoded-password',
        pattern: /(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/gi,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Potential hardcoded password',
    },
    {
        id: 'hardcoded-secret',
        pattern: /(secret|api[_-]?key|apikey|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}["']/gi,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Potential hardcoded secret or API key',
    },
    // ===========================================================================
    // A02: CRYPTOGRAPHIC FAILURES - Weak Crypto
    // ===========================================================================
    {
        id: 'weak-hash-md5',
        pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'MD5 is cryptographically broken - use SHA-256+',
        getFix: (match) => ({ before: match, after: "createHash('sha256')" }),
    },
    {
        id: 'weak-hash-sha1',
        pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'SHA1 is deprecated for security - use SHA-256+',
    },
    {
        id: 'insecure-random-js',
        pattern: /Math\.random\s*\(\s*\)/g,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Math.random() is not cryptographically secure',
        getFix: () => ({ before: 'Math.random()', after: 'crypto.randomBytes(16).toString("hex")' }),
    },
    {
        id: 'insecure-random-python',
        pattern: /import random[^_]|from random import/g,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Python random is not secure - use secrets module',
    },
    {
        id: 'jwt-none-algorithm',
        pattern: /algorithm\s*[:=]\s*["']none["']/gi,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'JWT with none algorithm allows auth bypass',
    },
    {
        id: 'ssl-verify-false',
        pattern: /(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized\s*:\s*false)/gi,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'SSL/TLS verification disabled',
    },
    {
        id: 'weak-crypto-mode',
        pattern: /(ECB|DES|3DES|RC4|BLOWFISH)/g,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Weak cryptographic algorithm or mode',
    },
    // ===========================================================================
    // A03: INJECTION - SQL Injection (10+ patterns)
    // ===========================================================================
    {
        id: 'sql-template-literal',
        pattern: /`SELECT[^`]*\$\{[^}]+\}[^`]*`/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: Template literal with variables',
    },
    {
        id: 'sql-concat-js',
        pattern: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^;]*\+\s*[a-zA-Z_]/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: String concatenation in query',
    },
    {
        id: 'sql-fstring-python',
        pattern: /f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: Python f-string in SQL',
    },
    {
        id: 'sql-format-python',
        pattern: /\.format\s*\([^)]*\)[^;]*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: Python .format() in SQL',
    },
    {
        id: 'sql-interp-ruby',
        pattern: /["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*#\{[^}]+\}/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: Ruby interpolation in SQL',
    },
    {
        id: 'sql-interp-php',
        pattern: /["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\$[a-zA-Z_]/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'SQL Injection: PHP variable in SQL',
    },
    {
        id: 'nosql-where',
        pattern: /\$where\s*:\s*["'][^"']*\+/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'NoSQL Injection: Dynamic $where clause',
    },
    {
        id: 'nosql-eval',
        pattern: /\$eval\s*:|db\.eval\s*\(/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'NoSQL Injection: MongoDB $eval',
    },
    // ===========================================================================
    // A03: INJECTION - XSS (15+ patterns)
    // ===========================================================================
    {
        id: 'xss-innerhtml',
        pattern: /\.innerHTML\s*=/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Unsafe innerHTML assignment',
    },
    {
        id: 'xss-outerhtml',
        pattern: /\.outerHTML\s*=/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Unsafe outerHTML assignment',
    },
    {
        id: 'xss-document-write',
        pattern: /document\.write\s*\(/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: document.write() can execute scripts',
    },
    {
        id: 'xss-insertadjacenthtml',
        pattern: /\.insertAdjacentHTML\s*\(/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: insertAdjacentHTML can execute scripts',
    },
    {
        id: 'xss-react-dangerously',
        pattern: /dangerouslySetInnerHTML/g,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: React dangerouslySetInnerHTML bypasses escaping',
    },
    {
        id: 'xss-vue-vhtml',
        pattern: /v-html\s*=/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Vue v-html bypasses escaping',
    },
    {
        id: 'xss-angular-bypass',
        pattern: /bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Angular security bypass',
    },
    {
        id: 'xss-jquery-html',
        pattern: /\$\([^)]+\)\.html\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: jQuery .html() with dynamic content',
    },
    {
        id: 'xss-jinja-safe',
        pattern: /\|\s*safe\s*\}\}/g,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Jinja2 safe filter bypasses escaping',
    },
    {
        id: 'xss-django-autoescape',
        pattern: /\{%\s*autoescape\s+off\s*%\}/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XSS: Django autoescape disabled',
    },
    // ===========================================================================
    // A03: INJECTION - Code Injection (10+ patterns)
    // ===========================================================================
    {
        id: 'eval-js',
        pattern: /\beval\s*\(/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Code Injection: eval() allows arbitrary execution',
    },
    {
        id: 'function-constructor',
        pattern: /new\s+Function\s*\(/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Code Injection: Function constructor',
    },
    {
        id: 'settimeout-string',
        pattern: /setTimeout\s*\(\s*["']/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Code Injection: setTimeout with string',
    },
    {
        id: 'setinterval-string',
        pattern: /setInterval\s*\(\s*["']/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Code Injection: setInterval with string',
    },
    {
        id: 'exec-python',
        pattern: /\bexec\s*\(/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Code Injection: Python exec()',
    },
    // ===========================================================================
    // A03: INJECTION - Command Injection (10+ patterns)
    // ===========================================================================
    {
        id: 'cmd-exec-template',
        pattern: /exec\s*\(\s*`[^`]*\$\{/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: Template literal in exec()',
    },
    {
        id: 'cmd-exec-concat',
        pattern: /exec\s*\([^)]*\+[^)]*\)/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: Concatenation in exec()',
    },
    {
        id: 'cmd-spawn-shell',
        pattern: /spawn\s*\([^)]*,\s*\{[^}]*shell\s*:\s*true/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: spawn with shell=true',
    },
    {
        id: 'cmd-subprocess-shell',
        pattern: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: Python subprocess shell=True',
    },
    {
        id: 'cmd-os-system',
        pattern: /os\.system\s*\(/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: Python os.system()',
    },
    {
        id: 'cmd-php-exec',
        pattern: /\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Command Injection: PHP shell function',
    },
    {
        id: 'ldap-injection',
        pattern: /ldap_(search|bind|compare)\s*\([^)]*\+/gi,
        severity: 'critical',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'LDAP Injection: Dynamic query',
    },
    {
        id: 'xpath-injection',
        pattern: /(xpath|selectNodes|evaluate)\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XPath Injection: Dynamic query',
    },
    {
        id: 'xxe-parser',
        pattern: /(XMLParser|lxml\.etree|xml\.sax)/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'XXE: XML parser may allow external entities',
    },
    // ===========================================================================
    // A01: BROKEN ACCESS CONTROL
    // ===========================================================================
    {
        id: 'path-traversal-read',
        pattern: /(readFile|readFileSync|createReadStream)\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'Path Traversal: Dynamic path in file read',
    },
    {
        id: 'path-traversal-write',
        pattern: /(writeFile|writeFileSync|createWriteStream)\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'Path Traversal: Dynamic path in file write',
    },
    {
        id: 'open-redirect-location',
        pattern: /(location\.href|window\.location)\s*=\s*[a-zA-Z_]/gi,
        severity: 'medium',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'Open Redirect: Variable in location',
    },
    {
        id: 'open-redirect-response',
        pattern: /(res\.redirect|redirect)\s*\(\s*[a-zA-Z_]/gi,
        severity: 'medium',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'Open Redirect: Variable in redirect',
    },
    {
        id: 'mass-assignment',
        pattern: /\.update\s*\(\s*req\.(body|query|params)\s*\)/gi,
        severity: 'high',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'Mass Assignment: Whitelist allowed fields',
    },
    {
        id: 'missing-csrf',
        pattern: /app\.(post|put|patch|delete)\s*\([^)]+\)(?![^{]*csrf)/gi,
        severity: 'medium',
        owaspId: 'A01',
        owaspName: 'Broken Access Control',
        message: 'State-changing endpoint may need CSRF',
    },
    // ===========================================================================
    // A05: SECURITY MISCONFIGURATION
    // ===========================================================================
    {
        id: 'debug-enabled',
        pattern: /(debug|DEBUG)\s*[:=]\s*[Tt]rue/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'Debug mode enabled - disable in production',
    },
    {
        id: 'cors-wildcard',
        pattern: /Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'CORS allows all origins',
    },
    {
        id: 'cors-open',
        pattern: /cors\s*\(\s*\)/g,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'CORS with no restriction',
    },
    {
        id: 'env-exposure',
        pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)/gi,
        severity: 'critical',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'All env vars exposed - may leak secrets',
    },
    {
        id: 'error-exposure',
        pattern: /(res\.(send|json)|response\.(send|json))\s*\(\s*(err|error|e)(\.message)?\s*\)/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'Error details exposed to client',
    },
    {
        id: 'stack-trace-exposure',
        pattern: /(err|error|e)\.stack/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'Stack trace may leak info',
    },
    // ===========================================================================
    // A07: AUTH FAILURES
    // ===========================================================================
    {
        id: 'weak-password-length',
        pattern: /minlength\s*[:=]\s*["']?[1-7]["']?/gi,
        severity: 'medium',
        owaspId: 'A07',
        owaspName: 'Authentication Failures',
        message: 'Password min length too short (use 8+)',
    },
    {
        id: 'timing-attack',
        pattern: /password\s*===|===\s*password|password\s*==|==\s*password/gi,
        severity: 'medium',
        owaspId: 'A07',
        owaspName: 'Authentication Failures',
        message: 'Use constant-time comparison for passwords',
    },
    {
        id: 'hardcoded-admin',
        pattern: /(admin|root|administrator)\s*[:=]\s*["'][^"']+["']/gi,
        severity: 'critical',
        owaspId: 'A07',
        owaspName: 'Authentication Failures',
        message: 'Potential hardcoded admin credentials',
    },
    // ===========================================================================
    // A08: DATA INTEGRITY - Deserialization
    // ===========================================================================
    {
        id: 'deser-pickle',
        pattern: /pickle\.(loads?|Unpickler)/g,
        severity: 'critical',
        owaspId: 'A08',
        owaspName: 'Software and Data Integrity Failures',
        message: 'Insecure Deserialization: pickle RCE risk',
    },
    {
        id: 'deser-yaml',
        pattern: /yaml\.load\s*\([^)]*\)(?![^)]*Loader\s*=\s*yaml\.SafeLoader)/gi,
        severity: 'high',
        owaspId: 'A08',
        owaspName: 'Software and Data Integrity Failures',
        message: 'Insecure Deserialization: Use yaml.safe_load()',
    },
    {
        id: 'deser-marshal',
        pattern: /Marshal\.load/g,
        severity: 'critical',
        owaspId: 'A08',
        owaspName: 'Software and Data Integrity Failures',
        message: 'Insecure Deserialization: Ruby Marshal',
    },
    {
        id: 'deser-unserialize',
        pattern: /\bunserialize\s*\(/gi,
        severity: 'critical',
        owaspId: 'A08',
        owaspName: 'Software and Data Integrity Failures',
        message: 'Insecure Deserialization: PHP unserialize',
    },
    // ===========================================================================
    // A09: LOGGING FAILURES
    // ===========================================================================
    {
        id: 'log-password',
        pattern: /(console\.(log|info|warn|error)|logger\.|log\.)[^;]*password/gi,
        severity: 'high',
        owaspId: 'A09',
        owaspName: 'Security Logging Failures',
        message: 'Password may be logged in cleartext',
    },
    {
        id: 'log-token',
        pattern: /(console\.(log|info|warn|error)|logger\.|log\.)[^;]*(token|api[_-]?key|secret)/gi,
        severity: 'high',
        owaspId: 'A09',
        owaspName: 'Security Logging Failures',
        message: 'Sensitive data may be logged',
    },
    {
        id: 'log-credit-card',
        pattern: /(console\.(log|info|warn|error)|logger\.|log\.)[^;]*(card|credit|cvv)/gi,
        severity: 'critical',
        owaspId: 'A09',
        owaspName: 'Security Logging Failures',
        message: 'Credit card data logged (PCI violation)',
    },
    // ===========================================================================
    // A10: SSRF
    // ===========================================================================
    {
        id: 'ssrf-axios',
        pattern: /axios\.(get|post|put|patch|delete|request)\s*\(\s*[a-zA-Z_]/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Variable URL in axios',
    },
    {
        id: 'ssrf-fetch',
        pattern: /\bfetch\s*\(\s*[a-zA-Z_]/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Variable URL in fetch()',
    },
    {
        id: 'ssrf-request',
        pattern: /request\s*\(\s*[a-zA-Z_]/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Variable URL in request()',
    },
    {
        id: 'ssrf-urllib',
        pattern: /urllib\.(request\.)?urlopen\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Dynamic URL in Python urllib',
    },
    {
        id: 'ssrf-requests',
        pattern: /requests\.(get|post|put|patch|delete)\s*\([^)]*\+/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Dynamic URL in Python requests',
    },
    {
        id: 'ssrf-curl',
        pattern: /curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$/gi,
        severity: 'high',
        owaspId: 'A10',
        owaspName: 'SSRF',
        message: 'SSRF: Variable URL in PHP cURL',
    },
    // ===========================================================================
    // MISC VULNERABILITIES
    // ===========================================================================
    {
        id: 'prototype-pollution',
        pattern: /Object\.assign\s*\([^,]+,\s*[a-zA-Z_]+\)|\[\s*[a-zA-Z_]+\s*\]\s*=/gi,
        severity: 'high',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Potential prototype pollution',
    },
    {
        id: 'regex-dos',
        pattern: /\(\[\^\s*\]\s*\)\s*[*+]|\(\s*\.\s*\)\s*[*+]/g,
        severity: 'medium',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'ReDoS: Regex may cause backtracking',
    },
    {
        id: 'hardcoded-heroku-key',
        pattern: /["'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']/g,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Potential Heroku API key (UUID format)',
    },
    {
        id: 'hardcoded-azure-key',
        pattern: /["'][A-Za-z0-9+/]{86}==["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Potential Azure Storage account key',
    },
    {
        id: 'hardcoded-shopify-key',
        pattern: /["']shpat_[a-fA-F0-9]{32}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded Shopify access token',
    },
    {
        id: 'hardcoded-openai-key',
        pattern: /["']sk-[a-zA-Z0-9]{48}["']/g,
        severity: 'critical',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded OpenAI API key',
    },
    {
        id: 'cookie-no-secure',
        pattern: /cookie\s*\([^)]+\)(?![^)]*secure)/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'Cookie without secure flag',
    },
    {
        id: 'cookie-no-httponly',
        pattern: /cookie\s*\([^)]+\)(?![^)]*httpOnly)/gi,
        severity: 'medium',
        owaspId: 'A05',
        owaspName: 'Security Misconfiguration',
        message: 'Cookie without httpOnly flag (XSS risk)',
    },
    {
        id: 'unsafe-header-injection',
        pattern: /(res\.setHeader|response\.addHeader)\s*\([^,]+,\s*[a-zA-Z_]+\s*\)/gi,
        severity: 'medium',
        owaspId: 'A03',
        owaspName: 'Injection',
        message: 'Header Injection: Validate header values',
    },
    {
        id: 'hardcoded-iv',
        pattern: /iv\s*[:=]\s*["'][0-9a-fA-F]{16,}["']/gi,
        severity: 'high',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'Hardcoded IV - use random IV per encryption',
    },
    {
        id: 'insecure-bcrypt-rounds',
        pattern: /bcrypt\.(hash|genSalt)\s*\([^,)]*,\s*([1-9]|10)\s*[,)]/gi,
        severity: 'medium',
        owaspId: 'A02',
        owaspName: 'Cryptographic Failures',
        message: 'bcrypt cost factor too low (use 12+)',
    },
];

// =============================================================================
// PATTERN-BASED SCANNING
// =============================================================================

/**
 * Scan file content using pattern matching
 */
export function scanWithPatterns(
    content: string,
    filename: string,
    patterns: VulnerabilityPattern[] = DEFAULT_PATTERNS
): ScanResult[] {
    const results: ScanResult[] = [];
    const lines = content.split('\n');

    for (const vuln of patterns) {
        // Create fresh regex to avoid state issues
        const pattern = new RegExp(vuln.pattern.source, vuln.pattern.flags);
        let match: RegExpExecArray | null;

        while ((match = pattern.exec(content)) !== null) {
            const beforeMatch = content.substring(0, match.index);
            const lineNumber = beforeMatch.split('\n').length;
            const lineContent = lines[lineNumber - 1] || '';
            const column = match.index - beforeMatch.lastIndexOf('\n');

            const result: ScanResult = {
                file: filename,
                line: lineNumber,
                column,
                severity: vuln.severity,
                owaspId: vuln.owaspId,
                owaspName: vuln.owaspName,
                message: vuln.message,
                snippet: lineContent.trim(),
                source: 'pattern',
                confidence: 1.0,
            };

            if (vuln.getFix) {
                result.fix = vuln.getFix(match[0], lineContent);
            }

            results.push(result);

            if (!vuln.pattern.global) break;
        }
    }

    return results;
}

/**
 * Load custom patterns from a configuration file
 */
export function loadCustomPatterns(configPath: string): VulnerabilityPattern[] {
    try {
        const fs = require('fs');
        const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

        if (!config.patterns || !Array.isArray(config.patterns)) {
            return [];
        }

        return config.patterns.map((p: any) => ({
            id: p.id || 'custom',
            pattern: new RegExp(p.pattern, p.flags || 'gi'),
            severity: p.severity || 'medium',
            owaspId: p.owaspId || 'A00',
            owaspName: p.owaspName || 'Custom',
            message: p.message || 'Custom pattern match',
        }));
    } catch (error) {
        return [];
    }
}

// =============================================================================
// COMBINED SCANNING (PATTERNS + AI)
// =============================================================================

/**
 * Scan content for vulnerabilities using both patterns and AI
 */
export async function scanContent(
    content: string,
    filename: string,
    options: ScanOptions = {}
): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const aiMode = options.aiMode || 'off';

    // Pattern-based scanning
    if (aiMode !== 'only') {
        const patternResults = scanWithPatterns(content, filename);
        results.push(...patternResults);
    }

    // AI-based scanning
    if (aiMode === 'only' || aiMode === 'hybrid') {
        try {
            const { analyzeWithAI, getDefaultLLMConfig } = await import('./ai-detection.js');
            const llmConfig = getDefaultLLMConfig();

            if (llmConfig) {
                const aiResults = await analyzeWithAI(content, filename, llmConfig);

                // Convert AI results to ScanResult format
                for (const ai of aiResults) {
                    results.push({
                        file: filename,
                        line: ai.line || 0,
                        severity: ai.severity as ScanResult['severity'],
                        owaspId: ai.owaspId,
                        owaspName: ai.owaspName,
                        message: ai.description,
                        snippet: ai.snippet || '',
                        suggestion: ai.suggestion,
                        confidence: ai.confidence,
                        source: 'ai',
                    });
                }
            }
        } catch (error) {
            // AI detection not available or failed
            if (aiMode === 'only') {
                console.warn('AI detection failed, no results available');
            }
        }
    }

    // Deduplicate results (same line + same OWASP ID)
    const seen = new Set<string>();
    return results.filter(r => {
        const key = `${r.file}:${r.line}:${r.owaspId}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

/**
 * Apply fixes to content
 */
export function applyFixes(content: string, results: ScanResult[]): string {
    let fixed = content;
    const fixable = results.filter(r => r.fix).sort((a, b) => b.line - a.line);

    for (const result of fixable) {
        if (result.fix) {
            fixed = fixed.replace(result.fix.before, result.fix.after);
        }
    }

    return fixed;
}

/**
 * Generate report
 */
export function generateReport(results: ScanResult[], format: 'text' | 'json' | 'html' = 'text'): string {
    if (format === 'json') {
        return JSON.stringify(results, null, 2);
    }

    if (format === 'html') {
        return `<!DOCTYPE html>
<html><head><title>Vibe-Check Security Report</title>
<style>
body{font-family:system-ui;max-width:1000px;margin:0 auto;padding:20px;background:#1a1a2e;color:#eee}
h1{color:#00d4ff}
.critical{background:#dc2626;color:white}.high{background:#ea580c;color:white}
.medium{background:#ca8a04;color:white}.low{background:#16a34a;color:white}
.severity{padding:4px 8px;border-radius:4px;font-size:0.8em;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-top:20px}
th{background:#2a2a4e;padding:12px;text-align:left}
td{padding:12px;border-bottom:1px solid #333}
.snippet{font-family:monospace;background:#2a2a4e;padding:8px;border-radius:4px;font-size:0.9em}
.ai-badge{background:#7c3aed;padding:2px 6px;border-radius:4px;font-size:0.7em;margin-left:8px}
</style>
</head><body>
<h1>🔍 Vibe-Check Security Report</h1>
<p>Found ${results.length} issues</p>
<table>
<tr><th>Severity</th><th>OWASP</th><th>File</th><th>Line</th><th>Issue</th></tr>
${results.map(r => `<tr>
<td><span class="severity ${r.severity}">${r.severity.toUpperCase()}</span>${r.source === 'ai' ? '<span class="ai-badge">AI</span>' : ''}</td>
<td>${r.owaspId}</td>
<td>${r.file}</td>
<td>${r.line}</td>
<td>${r.message}<br><span class="snippet">${r.snippet}</span></td>
</tr>`).join('\n')}
</table>
</body></html>`;
    }

    // Text format
    const grouped = { critical: [] as ScanResult[], high: [] as ScanResult[], medium: [] as ScanResult[], low: [] as ScanResult[], info: [] as ScanResult[] };
    for (const r of results) grouped[r.severity]?.push(r);

    let output = '';
    for (const [severity, items] of Object.entries(grouped)) {
        if (!items || items.length === 0) continue;
        output += `\n${severity.toUpperCase()} (${items.length})\n${'━'.repeat(50)}\n`;
        for (const r of items) {
            const aiTag = r.source === 'ai' ? ' [AI]' : '';
            output += `${r.owaspId}:${r.owaspName} - ${r.message}${aiTag}\n  ${r.file}:${r.line}\n  ${r.snippet}\n`;
            if (r.suggestion) {
                output += `  💡 ${r.suggestion}\n`;
            }
            output += '\n';
        }
    }

    const summary = `\nSUMMARY: Critical: ${grouped.critical.length} | High: ${grouped.high.length} | Medium: ${grouped.medium.length} | Low: ${grouped.low.length}\n`;
    return output + summary;
}

// Export default patterns for extension
export { DEFAULT_PATTERNS as VULNERABILITY_PATTERNS };
