import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import from the main SDK
import Slop from '../src/index';

// Create instance for testing
const slop = new Slop();

describe('Slop Security - Node.js SDK', () => {
    describe('SQL Injection Detection', () => {
        it('should detect UNION SELECT attack', () => {
            const result = slop.detectSqlInjection("' UNION SELECT * FROM users --");
            expect(result).toBe(true);
        });

        it('should detect OR 1=1 attack', () => {
            const result = slop.detectSqlInjection("' OR '1'='1");
            expect(result).toBe(true);
        });

        it('should not flag normal input', () => {
            const result = slop.detectSqlInjection("John Doe");
            expect(result).toBe(false);
        });
    });

    describe('XSS Detection', () => {
        it('should detect script tags', () => {
            const result = slop.detectXss('<script>alert(1)</script>');
            expect(result).toBe(true);
        });

        it('should detect javascript: protocol', () => {
            const result = slop.detectXss('javascript:alert(1)');
            expect(result).toBe(true);
        });

        it('should detect event handlers', () => {
            const result = slop.detectXss('<img onerror="alert(1)">');
            expect(result).toBe(true);
        });

        it('should not flag normal HTML', () => {
            const result = slop.detectXss('<p>Hello World</p>');
            expect(result).toBe(false);
        });
    });

    describe('Input Sanitization', () => {
        it('should escape XSS in HTML', () => {
            const result = slop.sanitize('<script>alert(1)</script>');
            expect(result).not.toContain('<script>');
        });
    });

    describe('SSRF Protection', () => {
        it('should block localhost', () => {
            const result = slop.validateUrl('http://localhost:8080/admin');
            expect(result.valid).toBe(false);
        });

        it('should block 127.0.0.1', () => {
            const result = slop.validateUrl('http://127.0.0.1/');
            expect(result.valid).toBe(false);
        });

        it('should block internal IPs', () => {
            const result = slop.validateUrl('http://192.168.1.1/');
            expect(result.valid).toBe(false);
        });

        it('should block cloud metadata', () => {
            const result = slop.validateUrl('http://169.254.169.254/latest/meta-data/');
            expect(result.valid).toBe(false);
        });

        it('should allow external URLs', () => {
            const result = slop.validateUrl('https://api.example.com/data');
            expect(result.valid).toBe(true);
        });
    });

    describe('Rate Limiting', () => {
        beforeEach(() => {
            // Reset for each test
        });

        it('should allow requests within limit', () => {
            const newSlop = new Slop({ requestsPerMinute: 10 });
            for (let i = 0; i < 5; i++) {
                expect(newSlop.checkRateLimit('user1')).toBe(true);
            }
        });
    });

    describe('Password Hashing', () => {
        it('should hash passwords', async () => {
            const hash = await slop.hashPassword('mypassword123');
            expect(hash).toBeTruthy();
            expect(hash).not.toBe('mypassword123');
        });

        it('should verify correct passwords', async () => {
            const hash = await slop.hashPassword('correctpassword');
            const isValid = await slop.verifyPassword('correctpassword', hash);
            expect(isValid).toBe(true);
        });

        it('should reject incorrect passwords', async () => {
            const hash = await slop.hashPassword('correctpassword');
            const isValid = await slop.verifyPassword('wrongpassword', hash);
            expect(isValid).toBe(false);
        });
    });

    describe('Token Generation', () => {
        it('should generate unique tokens', () => {
            const token1 = slop.generateToken();
            const token2 = slop.generateToken();
            expect(token1).not.toBe(token2);
        });

        it('should generate tokens of specified length', () => {
            const token = slop.generateToken(16);
            expect(token.length).toBeGreaterThanOrEqual(16);
        });
    });
});
