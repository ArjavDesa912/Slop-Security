<?php
/**
 * 🛡️ Slop Security - Laravel Middleware
 * 
 * Add to app/Http/Kernel.php:
 *   protected $middleware = [
 *       \Slop\Laravel\SlopMiddleware::class,
 *       // ...
 *   ];
 */

namespace Slop\Laravel;

use Closure;
use Illuminate\Http\Request;
use Slop\Security;

class SlopMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Rate limiting
        $clientIp = $request->ip();
        if (!Security::checkRateLimit($clientIp)) {
            return response()->json(['error' => 'Too many requests'], 429);
        }

        // SSRF protection
        $urlParams = ['url', 'redirect', 'next', 'callback', 'return'];
        foreach ($urlParams as $param) {
            $value = $request->input($param);
            if ($value && is_string($value) && str_starts_with($value, 'http')) {
                [$valid, $reason] = Security::validateUrl($value);
                if (!$valid) {
                    return response()->json(['error' => "Invalid URL: $reason"], 400);
                }
            }
        }

        $response = $next($request);

        // Add security headers
        foreach (Security::getSecurityHeaders() as $name => $value) {
            $response->headers->set($name, $value);
        }

        return $response;
    }
}
