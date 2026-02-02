<?php
/**
 * 🛡️ Slop Security - PHP SDK
 * 
 * One line to secure, zero lines to worry.
 * 
 * Usage:
 *   require_once 'vendor/autoload.php';
 *   use Slop\Security;
 *   Security::protect();
 */

namespace Slop;

class Security
{
    private static ?Config $config = null;
    private static array $rateLimitStore = [];
    private static array $bruteForceStore = [];
    
    // =========================================================================
    // Initialization
    // =========================================================================
    
    public static function protect(?Config $config = null): void
    {
        self::$config = $config ?? new Config();
        
        // Apply protections
        self::applyRateLimiting();
        self::applySecurityHeaders();
        self::applySsrfProtection();
        
        error_log("🛡️ Slop Security initialized");
    }
    
    public static function getConfig(): Config
    {
        if (self::$config === null) {
            self::$config = new Config();
        }
        return self::$config;
    }
    
    // =========================================================================
    // Security Headers
    // =========================================================================
    
    public static function getSecurityHeaders(): array
    {
        return [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy' => "default-src 'self'",
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
        ];
    }
    
    public static function applySecurityHeaders(): void
    {
        foreach (self::getSecurityHeaders() as $name => $value) {
            if (!headers_sent()) {
                header("$name: $value");
            }
        }
    }
    
    // =========================================================================
    // SQL Injection Protection
    // =========================================================================
    
    private static array $sqlPatterns = [
        '/\bUNION\b.*\bSELECT\b/i',
        '/\bSELECT\b.*\bFROM\b/i',
        '/--\s*$/',
        '/\/\*.*\*\//',
        '/\'\s*OR\s*\'1\'\s*=\s*\'1/i',
        '/\'\s*OR\s+\d+\s*=\s*\d+/i',
        '/\bDROP\b.*\bTABLE\b/i',
    ];
    
    public static function detectSqlInjection(string $input): bool
    {
        foreach (self::$sqlPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }
    
    public static function sanitizeSql(string $input): string
    {
        return str_replace(
            ['\\', "'", '"', "\0", "\n", "\r"],
            ['\\\\', "''", '\\"', '', '\\n', '\\r'],
            $input
        );
    }
    
    // =========================================================================
    // XSS Protection
    // =========================================================================
    
    private static array $xssPatterns = [
        '/<script[^>]*>/i',
        '/<\/script>/i',
        '/javascript:/i',
        '/on\w+\s*=/i',
        '/<iframe/i',
        '/<object/i',
    ];
    
    public static function detectXss(string $input): bool
    {
        foreach (self::$xssPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }
    
    public static function sanitizeHtml(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    
    // =========================================================================
    // SSRF Protection
    // =========================================================================
    
    private static array $internalRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
    ];
    
    private static array $metadataHosts = [
        '169.254.169.254',
        'metadata.google.internal',
        'metadata.goog',
    ];
    
    public static function validateUrl(string $url): array
    {
        $parsed = parse_url($url);
        
        if ($parsed === false) {
            return [false, 'Invalid URL'];
        }
        
        if (!isset($parsed['scheme']) || !in_array($parsed['scheme'], ['http', 'https'])) {
            return [false, 'Invalid protocol'];
        }
        
        if (!isset($parsed['host']) || empty($parsed['host'])) {
            return [false, 'No host specified'];
        }
        
        $host = $parsed['host'];
        $config = self::getConfig();
        
        // Check allowlist
        if (in_array($host, $config->ssrfAllowlist)) {
            return [true, null];
        }
        
        // Check metadata hosts
        if (in_array($host, self::$metadataHosts)) {
            return [false, 'Metadata endpoint blocked'];
        }
        
        // Check localhost
        if (in_array($host, ['localhost', '127.0.0.1', '::1'])) {
            return [false, 'Localhost blocked'];
        }
        
        // Check internal IPs
        if ($config->ssrfBlockInternal && filter_var($host, FILTER_VALIDATE_IP)) {
            $ip = ip2long($host);
            foreach (self::$internalRanges as $range) {
                if (self::ipInRange($host, $range)) {
                    return [false, 'Internal IP blocked'];
                }
            }
        }
        
        return [true, null];
    }
    
    private static function ipInRange(string $ip, string $range): bool
    {
        [$subnet, $bits] = explode('/', $range);
        $subnet = ip2long($subnet);
        $ip = ip2long($ip);
        $mask = -1 << (32 - (int)$bits);
        return ($ip & $mask) === ($subnet & $mask);
    }
    
    public static function applySsrfProtection(): void
    {
        $urlParams = ['url', 'redirect', 'next', 'callback', 'return'];
        
        foreach ($urlParams as $param) {
            $value = $_GET[$param] ?? $_POST[$param] ?? null;
            if ($value && is_string($value) && str_starts_with($value, 'http')) {
                [$valid, $reason] = self::validateUrl($value);
                if (!$valid) {
                    http_response_code(400);
                    header('Content-Type: application/json');
                    echo json_encode(['error' => "Invalid URL: $reason"]);
                    exit;
                }
            }
        }
    }
    
    // =========================================================================
    // Rate Limiting
    // =========================================================================
    
    public static function checkRateLimit(string $key): bool
    {
        $config = self::getConfig();
        if (!$config->rateLimitEnabled) {
            return true;
        }
        
        $now = time();
        $window = 60; // 1 minute
        
        if (!isset(self::$rateLimitStore[$key])) {
            self::$rateLimitStore[$key] = [];
        }
        
        // Filter old timestamps
        self::$rateLimitStore[$key] = array_filter(
            self::$rateLimitStore[$key],
            fn($t) => $now - $t < $window
        );
        
        if (count(self::$rateLimitStore[$key]) >= $config->requestsPerMinute) {
            return false;
        }
        
        self::$rateLimitStore[$key][] = $now;
        return true;
    }
    
    private static function applyRateLimiting(): void
    {
        $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if (str_contains($clientIp, ',')) {
            $clientIp = trim(explode(',', $clientIp)[0]);
        }
        
        if (!self::checkRateLimit($clientIp)) {
            http_response_code(429);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Too many requests']);
            exit;
        }
    }
    
    // =========================================================================
    // Brute Force Protection
    // =========================================================================
    
    public static function recordAuthFailure(string $key): void
    {
        $config = self::getConfig();
        if (!$config->bruteForceEnabled) {
            return;
        }
        
        if (!isset(self::$bruteForceStore[$key])) {
            self::$bruteForceStore[$key] = ['attempts' => 0, 'lastAttempt' => time()];
        }
        
        self::$bruteForceStore[$key]['attempts']++;
        self::$bruteForceStore[$key]['lastAttempt'] = time();
    }
    
    public static function recordAuthSuccess(string $key): void
    {
        unset(self::$bruteForceStore[$key]);
    }
    
    public static function isLockedOut(string $key): bool
    {
        $config = self::getConfig();
        if (!$config->bruteForceEnabled) {
            return false;
        }
        
        if (!isset(self::$bruteForceStore[$key])) {
            return false;
        }
        
        $entry = self::$bruteForceStore[$key];
        $lockoutSeconds = $config->lockoutMinutes * 60;
        
        if ($entry['attempts'] >= $config->maxAttempts) {
            if (time() - $entry['lastAttempt'] < $lockoutSeconds) {
                return true;
            }
            unset(self::$bruteForceStore[$key]);
        }
        
        return false;
    }
    
    // =========================================================================
    // Cryptography
    // =========================================================================
    
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 4,
        ]);
    }
    
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
    
    public static function generateToken(int $length = 32): string
    {
        return bin2hex(random_bytes($length));
    }
    
    public static function sha256(string $data): string
    {
        return hash('sha256', $data);
    }
    
    // =========================================================================
    // Input Sanitization
    // =========================================================================
    
    public static function sanitize(string $input): string
    {
        $result = $input;
        
        if (self::detectSqlInjection($result)) {
            $result = self::sanitizeSql($result);
        }
        
        if (self::detectXss($result)) {
            $result = self::sanitizeHtml($result);
        }
        
        return $result;
    }
}

class Config
{
    public bool $rateLimitEnabled = true;
    public int $requestsPerMinute = 100;
    public bool $bruteForceEnabled = true;
    public int $maxAttempts = 5;
    public int $lockoutMinutes = 15;
    public bool $ssrfBlockInternal = true;
    public array $ssrfAllowlist = [];
    
    public function __construct(array $options = [])
    {
        foreach ($options as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }
    }
}
