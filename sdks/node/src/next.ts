/**
 * 🛡️ Slop Security - Next.js Integration
 */

import { Slop, SlopConfig, validateUrlSsrf } from './index';

export interface NextSecureOptions extends SlopConfig { }

/**
 * Next.js middleware for Slop Security
 */
export function slopMiddleware(options: NextSecureOptions = {}) {
    const slop = new Slop(options);

    return async function middleware(request: any) {
        // Dynamic import for Next.js
        const { NextResponse } = await import('next/server');
        const response = NextResponse.next();

        // Add security headers
        const headers = slop.getSecurityHeaders();
        for (const [key, value] of Object.entries(headers)) {
            response.headers.set(key, value);
        }

        // Rate limiting
        const ip = request.ip || request.headers.get?.('x-forwarded-for') || 'unknown';
        if (!slop.checkRateLimit(ip)) {
            return new NextResponse(JSON.stringify({ error: 'Too many requests' }), {
                status: 429,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // SSRF protection for redirects
        const url = request.nextUrl?.searchParams?.get?.('redirect') ||
            request.nextUrl?.searchParams?.get?.('next') ||
            request.nextUrl?.searchParams?.get?.('callback');
        if (url && url.startsWith('http')) {
            const result = validateUrlSsrf(url);
            if (!result.valid) {
                return new NextResponse(JSON.stringify({ error: 'Invalid redirect URL' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
        }

        return response;
    };
}

/**
 * Security headers for Next.js config
 */
export function getSecurityHeaders(): { key: string; value: string }[] {
    const slop = new Slop();
    return Object.entries(slop.getSecurityHeaders()).map(([key, value]) => ({ key, value }));
}

/**
 * CSP configuration for Next.js
 */
export function getContentSecurityPolicy(): string {
    return [
        "default-src 'self'",
        "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
    ].join('; ');
}

export { Slop, SlopConfig };
export default slopMiddleware;
