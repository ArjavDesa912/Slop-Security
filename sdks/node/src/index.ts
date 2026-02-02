/**
 * 🛡️ Slop Security - Node.js SDK
 * 
 * One line to secure, zero lines to worry.
 * 
 * @example
 * ```javascript
 * const slop = require('@slop/security');
 * slop.secure(app);
 * ```
 */

import { v4 as uuidv4 } from 'uuid';
import xss from 'xss';

// ============================================================================
// Types
// ============================================================================

export interface SlopConfig {
  owasp?: OwaspConfig;
  patching?: PatchingConfig;
  sandbox?: SandboxConfig;
  reporting?: ReportingConfig;
}

export interface OwaspConfig {
  a01_access_control?: { enabled?: boolean; rate_limiting?: { enabled?: boolean; requests_per_minute?: number } };
  a02_cryptographic_failures?: { enabled?: boolean; detect_hardcoded_secrets?: boolean };
  a03_injection?: { enabled?: boolean; sqli_protection?: boolean; xss_filter?: boolean };
  a05_security_misconfiguration?: { enabled?: boolean; secure_headers?: boolean };
  a07_auth_failures?: { enabled?: boolean; brute_force_protection?: { enabled?: boolean; max_attempts?: number; lockout_minutes?: number } };
  a10_ssrf?: { enabled?: boolean; block_internal?: boolean };
}

export interface PatchingConfig {
  auto_patch?: boolean;
}

export interface SandboxConfig {
  enabled?: boolean;
  timeout_ms?: number;
  memory_limit_mb?: number;
  allowed_permissions?: string[];
}

export interface ReportingConfig {
  realtime_alerts?: boolean;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'auth' | 'access' | 'injection' | 'rate-limit' | 'xss' | 'ssrf';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  ip?: string;
  userId?: string;
  payload?: string;
  blocked: boolean;
}

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_CONFIG: SlopConfig = {
  owasp: {
    a01_access_control: { enabled: true, rate_limiting: { enabled: true, requests_per_minute: 100 } },
    a02_cryptographic_failures: { enabled: true, detect_hardcoded_secrets: true },
    a03_injection: { enabled: true, sqli_protection: true, xss_filter: true },
    a05_security_misconfiguration: { enabled: true, secure_headers: true },
    a07_auth_failures: { enabled: true, brute_force_protection: { enabled: true, max_attempts: 5, lockout_minutes: 15 } },
    a10_ssrf: { enabled: true, block_internal: true },
  },
  patching: { auto_patch: true },
  sandbox: { enabled: true, timeout_ms: 5000, memory_limit_mb: 128, allowed_permissions: ['network'] },
  reporting: { realtime_alerts: true },
};

// ============================================================================
// SQL Injection Protection
// ============================================================================

const SQL_INJECTION_PATTERNS = [
  /(\bUNION\b.*\bSELECT\b)/i,
  /(\bSELECT\b.*\bFROM\b)/i,
  /(\bINSERT\b.*\bINTO\b)/i,
  /(\bUPDATE\b.*\bSET\b)/i,
  /(\bDELETE\b.*\bFROM\b)/i,
  /(\bDROP\b.*\bTABLE\b)/i,
  /(--\s*$)/,
  /(\/\*.*\*\/)/,
  /'(\s*OR\s*'1'\s*=\s*'1)/i,
  /'\s*OR\s+\d+\s*=\s*\d+/i,
];

export function detectSqlInjection(input: string): boolean {
  return SQL_INJECTION_PATTERNS.some(pattern => pattern.test(input));
}

export function sanitizeSql(input: string): string {
  return input.replace(/\\/g, '\\\\').replace(/'/g, "''").replace(/"/g, '\\"').replace(/\0/g, '');
}

// ============================================================================
// XSS Protection
// ============================================================================

export function detectXss(input: string): boolean {
  const patterns = [/<script[^>]*>/i, /javascript:/i, /on\w+\s*=/i, /<iframe/i, /<svg.*onload/i];
  return patterns.some(pattern => pattern.test(input));
}

export function sanitizeHtml(input: string): string {
  return xss(input);
}

// ============================================================================
// SSRF Protection
// ============================================================================

const INTERNAL_RANGES = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
  '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.',
  '172.31.', '192.168.', '127.', '0.', '169.254.'];

const METADATA_HOSTS = ['169.254.169.254', 'metadata.google.internal', 'metadata.goog'];

export function validateUrlSsrf(urlString: string): { valid: boolean; reason?: string } {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, reason: 'Invalid protocol' };
    }
    if (url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) {
      return { valid: false, reason: 'Localhost blocked' };
    }
    if (METADATA_HOSTS.includes(url.hostname)) {
      return { valid: false, reason: 'Metadata endpoint blocked' };
    }
    if (INTERNAL_RANGES.some(range => url.hostname.startsWith(range))) {
      return { valid: false, reason: 'Internal IP blocked' };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: 'Invalid URL' };
  }
}

// ============================================================================
// Rate Limiting
// ============================================================================

class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  constructor(private limit: number, private windowMs: number) {}

  check(key: string): boolean {
    const now = Date.now();
    const timestamps = this.requests.get(key) || [];
    const valid = timestamps.filter(t => now - t < this.windowMs);
    if (valid.length >= this.limit) return false;
    valid.push(now);
    this.requests.set(key, valid);
    return true;
  }

  reset(key: string): void {
    this.requests.delete(key);
  }
}

// ============================================================================
// Brute Force Protection
// ============================================================================

class BruteForceProtector {
  private attempts: Map<string, { count: number; lastAttempt: number }> = new Map();
  constructor(private maxAttempts: number, private lockoutMs: number) {}

  recordFailure(key: string): boolean {
    const now = Date.now();
    const entry = this.attempts.get(key);
    if (!entry || now - entry.lastAttempt > this.lockoutMs) {
      this.attempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }
    entry.count++;
    entry.lastAttempt = now;
    return entry.count < this.maxAttempts;
  }

  isLocked(key: string): boolean {
    const entry = this.attempts.get(key);
    if (!entry) return false;
    return entry.count >= this.maxAttempts && Date.now() - entry.lastAttempt < this.lockoutMs;
  }

  recordSuccess(key: string): void {
    this.attempts.delete(key);
  }
}

// ============================================================================
// Security Logger
// ============================================================================

class SecurityLogger {
  private events: SecurityEvent[] = [];

  log(event: Omit<SecurityEvent, 'id' | 'timestamp'>): void {
    const fullEvent: SecurityEvent = { ...event, id: uuidv4(), timestamp: new Date().toISOString() };
    this.events.push(fullEvent);
    if (event.severity === 'critical' || event.severity === 'high') {
      console.warn(`🛡️ SLOP SECURITY [${event.severity.toUpperCase()}]:`, event.message);
    }
  }

  getEvents(): SecurityEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events = [];
  }
}

// ============================================================================
// Sandbox Execution
// ============================================================================

export interface SandboxOptions {
  timeout?: number;
  permissions?: string[];
}

export async function sandbox<T>(fn: () => T | Promise<T>, options: SandboxOptions = {}): Promise<T> {
  const timeout = options.timeout ?? 5000;
  return Promise.race([
    Promise.resolve().then(fn),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Sandbox timeout')), timeout)),
  ]);
}

// ============================================================================
// Main Slop Class
// ============================================================================

class Slop {
  private config: SlopConfig;
  private rateLimiter: RateLimiter;
  private bruteForce: BruteForceProtector;
  public logger: SecurityLogger;

  constructor(config: Partial<SlopConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    const rl = this.config.owasp?.a01_access_control?.rate_limiting;
    this.rateLimiter = new RateLimiter(rl?.requests_per_minute ?? 100, 60000);
    const bf = this.config.owasp?.a07_auth_failures?.brute_force_protection;
    this.bruteForce = new BruteForceProtector(bf?.max_attempts ?? 5, (bf?.lockout_minutes ?? 15) * 60000);
    this.logger = new SecurityLogger();
  }

  // Sanitize input
  sanitize(input: string): string {
    let result = input;
    if (this.config.owasp?.a03_injection?.sqli_protection && detectSqlInjection(result)) {
      this.logger.log({ type: 'injection', severity: 'high', message: 'SQL injection attempt', payload: input.slice(0, 100), blocked: true });
      result = sanitizeSql(result);
    }
    if (this.config.owasp?.a03_injection?.xss_filter && detectXss(result)) {
      this.logger.log({ type: 'xss', severity: 'high', message: 'XSS attempt', payload: input.slice(0, 100), blocked: true });
      result = sanitizeHtml(result);
    }
    return result;
  }

  // Check rate limit
  checkRateLimit(key: string): boolean {
    if (!this.config.owasp?.a01_access_control?.rate_limiting?.enabled) return true;
    const allowed = this.rateLimiter.check(key);
    if (!allowed) {
      this.logger.log({ type: 'rate-limit', severity: 'medium', message: `Rate limit exceeded for ${key}`, blocked: true });
    }
    return allowed;
  }

  // Brute force check
  recordAuthFailure(key: string): boolean {
    if (!this.config.owasp?.a07_auth_failures?.brute_force_protection?.enabled) return true;
    return this.bruteForce.recordFailure(key);
  }

  isAuthLocked(key: string): boolean {
    return this.bruteForce.isLocked(key);
  }

  recordAuthSuccess(key: string): void {
    this.bruteForce.recordSuccess(key);
  }

  // Validate URL for SSRF
  validateUrl(url: string): { valid: boolean; reason?: string } {
    if (!this.config.owasp?.a10_ssrf?.enabled) return { valid: true };
    const result = validateUrlSsrf(url);
    if (!result.valid) {
      this.logger.log({ type: 'ssrf', severity: 'critical', message: `SSRF attempt: ${result.reason}`, payload: url, blocked: true });
    }
    return result;
  }

  // Sandbox execution
  async secure<T>(fn: () => T | Promise<T>, options?: SandboxOptions): Promise<T> {
    return sandbox(fn, options);
  }

  // Get security headers
  getSecurityHeaders(): Record<string, string> {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    };
  }
}

// ============================================================================
// Exports
// ============================================================================

export const slop = new Slop();
export { Slop, RateLimiter, BruteForceProtector, SecurityLogger };
export default slop;
