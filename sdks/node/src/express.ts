/**
 * 🛡️ Slop Security - Express.js Integration
 * 
 * @example
 * ```javascript
 * const express = require('express');
 * const { secure } = require('@slop/security/express');
 * 
 * const app = express();
 * secure(app);
 * ```
 */

import type { Application, Request, Response, NextFunction, RequestHandler } from 'express';
import helmet from 'helmet';
import hpp from 'hpp';
import { Slop, SlopConfig, sanitizeHtml, detectSqlInjection, detectXss } from './index';

// ============================================================================
// Express Middleware
// ============================================================================

export interface SecureOptions extends SlopConfig {
    /** Trust proxy headers (required behind load balancer) */
    trustProxy?: boolean;
    /** Custom error handler */
    onError?: (err: Error, req: Request, res: Response) => void;
}

/**
 * Secure an Express application with Slop Security
 * 
 * @example
 * ```javascript
 * const app = express();
 * secure(app);
 * ```
 */
export function secure(app: Application, options: SecureOptions = {}): Application {
    const slop = new Slop(options);

    // Trust proxy if configured
    if (options.trustProxy) {
        app.set('trust proxy', 1);
    }

    // Security headers via Helmet
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: true,
        crossOriginResourcePolicy: { policy: 'same-origin' },
        dnsPrefetchControl: { allow: false },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: { maxAge: 31536000, includeSubDomains: true },
        ieNoOpen: true,
        noSniff: true,
        originAgentCluster: true,
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        xssFilter: true,
    }));

    // HTTP Parameter Pollution protection
    app.use(hpp());

    // Rate limiting middleware
    app.use(((req: Request, res: Response, next: NextFunction) => {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        if (!slop.checkRateLimit(ip)) {
            slop.logger.log({ type: 'rate-limit', severity: 'medium', message: `Rate limit exceeded`, ip, blocked: true });
            return res.status(429).json({ error: 'Too many requests' });
        }
        next();
    }) as RequestHandler);

    // Input sanitization middleware
    app.use(((req: Request, res: Response, next: NextFunction) => {
        // Sanitize query parameters
        if (req.query) {
            for (const [key, value] of Object.entries(req.query)) {
                if (typeof value === 'string') {
                    (req.query as Record<string, unknown>)[key] = slop.sanitize(value);
                }
            }
        }
        // Sanitize body
        if (req.body && typeof req.body === 'object') {
            sanitizeObject(req.body, slop);
        }
        next();
    }) as RequestHandler);

    // SSRF protection for URL parameters
    app.use(((req: Request, res: Response, next: NextFunction) => {
        const urlParams = ['url', 'redirect', 'next', 'return', 'callback', 'target', 'dest', 'destination'];
        for (const param of urlParams) {
            const value = req.query[param] || req.body?.[param];
            if (typeof value === 'string' && value.startsWith('http')) {
                const result = slop.validateUrl(value);
                if (!result.valid) {
                    slop.logger.log({ type: 'ssrf', severity: 'critical', message: result.reason || 'SSRF blocked', ip: req.ip, blocked: true });
                    return res.status(400).json({ error: 'Invalid URL' });
                }
            }
        }
        next();
    }) as RequestHandler);

    // Security context
    app.use(((req: Request, res: Response, next: NextFunction) => {
        (req as any).slop = slop;
        next();
    }) as RequestHandler);

    // Error handling
    app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
        slop.logger.log({ type: 'access', severity: 'high', message: `Error: ${err.message}`, ip: req.ip, blocked: false });
        if (options.onError) {
            return options.onError(err, req, res);
        }
        // Don't leak error details in production
        const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
        res.status(500).json({ error: message });
    });

    console.log('🛡️ Slop Security initialized for Express');
    return app;
}

function sanitizeObject(obj: Record<string, any>, slop: Slop): void {
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            obj[key] = slop.sanitize(value);
        } else if (typeof value === 'object' && value !== null) {
            sanitizeObject(value, slop);
        }
    }
}

/**
 * Brute force protection middleware for authentication routes
 */
export function bruteForceProtection(options: { keyExtractor?: (req: Request) => string } = {}): RequestHandler {
    const slop = new Slop();
    const getKey = options.keyExtractor || ((req: Request) => req.ip || 'unknown');

    return (req: Request, res: Response, next: NextFunction) => {
        const key = getKey(req);
        if (slop.isAuthLocked(key)) {
            return res.status(429).json({ error: 'Too many failed attempts. Please try again later.' });
        }
        // Attach helpers to request
        (req as any).authSuccess = () => slop.recordAuthSuccess(key);
        (req as any).authFailure = () => slop.recordAuthFailure(key);
        next();
    };
}

/**
 * CSRF protection middleware
 */
export function csrfProtection(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
            const token = req.headers['x-csrf-token'] || req.body?._csrf;
            const sessionToken = (req as any).session?.csrfToken;
            if (!token || token !== sessionToken) {
                return res.status(403).json({ error: 'Invalid CSRF token' });
            }
        }
        next();
    };
}

export { Slop, SlopConfig };
export default secure;
