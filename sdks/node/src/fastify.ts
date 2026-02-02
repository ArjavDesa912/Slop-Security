/**
 * 🛡️ Slop Security - Fastify Integration
 */

import { Slop, SlopConfig } from './index';

export interface FastifySecureOptions extends SlopConfig { }

/**
 * Fastify plugin for Slop Security
 */
export const slopPlugin = (fastify: any, options: FastifySecureOptions, done: () => void) => {
    const slop = new Slop(options);

    // Security headers
    fastify.addHook('onSend', async (request: any, reply: any) => {
        const headers = slop.getSecurityHeaders();
        for (const [key, value] of Object.entries(headers)) {
            reply.header(key, value);
        }
    });

    // Rate limiting
    fastify.addHook('preHandler', async (request: any, reply: any) => {
        const ip = request.ip || 'unknown';
        if (!slop.checkRateLimit(ip)) {
            reply.code(429).send({ error: 'Too many requests' });
            return;
        }
    });

    // Input sanitization
    fastify.addHook('preHandler', async (request: any) => {
        if (request.query && typeof request.query === 'object') {
            for (const [key, value] of Object.entries(request.query as Record<string, unknown>)) {
                if (typeof value === 'string') {
                    (request.query as Record<string, unknown>)[key] = slop.sanitize(value);
                }
            }
        }
        if (request.body && typeof request.body === 'object') {
            sanitizeObject(request.body as Record<string, unknown>, slop);
        }
    });

    // Decorate request with slop instance
    fastify.decorateRequest('slop', null);
    fastify.addHook('preHandler', async (request: any) => {
        request.slop = slop;
    });

    console.log('🛡️ Slop Security initialized for Fastify');
    done();
};

function sanitizeObject(obj: Record<string, unknown>, slop: Slop): void {
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            obj[key] = slop.sanitize(value);
        } else if (typeof value === 'object' && value !== null) {
            sanitizeObject(value as Record<string, unknown>, slop);
        }
    }
}

/**
 * Secure a Fastify instance
 */
export function secure(fastify: any, options: FastifySecureOptions = {}): any {
    fastify.register(slopPlugin, options);
    return fastify;
}

export { Slop, SlopConfig };
export default slopPlugin;
