import { describe, it, expect } from 'vitest';
import {
    scanWithPatterns,
    applyFixes,
    generateReport,
    DEFAULT_PATTERNS
} from '../src/index';

describe('Vibe-Check Scanner', () => {
    describe('Hardcoded Secrets Detection', () => {
        it('should detect Stripe live keys', () => {
            const code = 'const key = "sk_live_abc123def456ghi789";';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.length).toBeGreaterThan(0);
            expect(results[0].owaspId).toBe('A02');
            expect(results[0].severity).toBe('critical');
        });

        it('should detect AWS access keys', () => {
            const code = 'const aws = "AKIAIOSFODNN7EXAMPLE";';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.length).toBeGreaterThan(0);
            expect(results[0].owaspId).toBe('A02');
        });

        it('should detect GitHub tokens', () => {
            const code = 'const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.length).toBeGreaterThan(0);
            expect(results[0].message).toContain('GitHub');
        });
    });

    describe('SQL Injection Detection', () => {
        it('should detect template literal SQL injection', () => {
            const code = 'const query = `SELECT * FROM users WHERE id = ${userId}`;';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.owaspId === 'A03' && r.message.includes('SQL'))).toBe(true);
        });
    });

    describe('XSS Detection', () => {
        it('should detect innerHTML assignments', () => {
            const code = 'element.innerHTML = userInput;';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.owaspId === 'A03' && r.message.includes('XSS'))).toBe(true);
        });

        it('should detect document.write', () => {
            const code = 'document.write("<h1>" + title + "</h1>");';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.message.includes('document.write'))).toBe(true);
        });
    });

    describe('Command Injection Detection', () => {
        it('should detect exec with template literals', () => {
            const code = 'exec(`ping -c 4 ${host}`);';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.owaspId === 'A03' && r.message.includes('Command'))).toBe(true);
        });
    });

    describe('Dangerous Functions', () => {
        it('should detect eval usage', () => {
            const code = 'const result = eval(userCode);';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.message.includes('eval'))).toBe(true);
        });

        it('should detect new Function constructor', () => {
            const code = 'const fn = new Function("return " + code);';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.message.includes('Function constructor'))).toBe(true);
        });
    });

    describe('Crypto Issues', () => {
        it('should detect MD5 usage', () => {
            const code = "crypto.createHash('md5').update(data).digest('hex')";
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.message.includes('MD5'))).toBe(true);
        });

        it('should detect Math.random for security', () => {
            const code = 'const token = Math.random().toString(36);';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.message.includes('Math.random'))).toBe(true);
        });
    });

    describe('SSRF Detection', () => {
        it('should detect axios with variable URL', () => {
            const code = 'const response = await axios.get(url);';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.owaspId === 'A10')).toBe(true);
        });

        it('should detect fetch with variable URL', () => {
            const code = 'fetch(userUrl).then(r => r.json());';
            const results = scanWithPatterns(code, 'test.js');
            expect(results.some(r => r.owaspId === 'A10')).toBe(true);
        });
    });

    describe('Report Generation', () => {
        it('should generate text report', () => {
            const results = [
                {
                    file: 'test.js',
                    line: 1,
                    severity: 'critical' as const,
                    owaspId: 'A02',
                    owaspName: 'Cryptographic Failures',
                    message: 'Hardcoded secret',
                    snippet: 'const key = "sk_live_xxx"',
                    source: 'pattern' as const,
                }
            ];
            const report = generateReport(results, 'text');
            expect(report).toContain('CRITICAL');
            expect(report).toContain('A02');
        });

        it('should generate JSON report', () => {
            const results = [
                {
                    file: 'test.js',
                    line: 1,
                    severity: 'high' as const,
                    owaspId: 'A03',
                    owaspName: 'Injection',
                    message: 'XSS detected',
                    snippet: 'innerHTML = x',
                    source: 'pattern' as const,
                }
            ];
            const report = generateReport(results, 'json');
            const parsed = JSON.parse(report);
            expect(parsed).toHaveLength(1);
            expect(parsed[0].severity).toBe('high');
        });
    });

    describe('Auto-fix', () => {
        it('should provide fix for Stripe key', () => {
            const code = 'const key = "sk_live_abc123";';
            const results = scanWithPatterns(code, 'test.js');
            expect(results[0].fix).toBeDefined();
            expect(results[0].fix?.after).toBe('process.env.STRIPE_SECRET_KEY');
        });

        it('should apply fixes correctly', () => {
            const code = 'const n = Math.random();';
            const results = scanWithPatterns(code, 'test.js');
            const fixed = applyFixes(code, results);
            expect(fixed).toContain('crypto.randomBytes');
        });
    });
});
