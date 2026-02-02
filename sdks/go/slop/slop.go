package main

// Slop Security - Go SDK
// One line to secure, zero lines to worry.
//
// Example usage:
//   import "github.com/slop-security/slop-security/sdks/go/slop"
//   r := gin.Default()
//   r.Use(slop.Middleware())

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// =============================================================================
// Configuration
// =============================================================================

type SlopConfig struct {
	RateLimitEnabled      bool
	RequestsPerMinute     int
	BruteForceEnabled     bool
	MaxAttempts           int
	LockoutMinutes        int
	SSRFBlockInternal     bool
	SSRFBlockMetadata     bool
	SSRFAllowlist         []string
}

func DefaultConfig() SlopConfig {
	return SlopConfig{
		RateLimitEnabled:      true,
		RequestsPerMinute:     100,
		BruteForceEnabled:     true,
		MaxAttempts:           5,
		LockoutMinutes:        15,
		SSRFBlockInternal:     true,
		SSRFBlockMetadata:     true,
		SSRFAllowlist:         []string{},
	}
}

// =============================================================================
// Slop Instance
// =============================================================================

type Slop struct {
	config         SlopConfig
	rateLimitStore sync.Map // map[string][]time.Time
	bruteForce     sync.Map // map[string]bruteForceEntry
}

type bruteForceEntry struct {
	Attempts   int
	LastAttempt time.Time
}

func New(config ...SlopConfig) *Slop {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return &Slop{config: cfg}
}

// =============================================================================
// SQL Injection Protection
// =============================================================================

var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\bUNION\b.*\bSELECT\b)`),
	regexp.MustCompile(`(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b.*=.*')`),
	regexp.MustCompile(`(?i)(--\s*$)`),
	regexp.MustCompile(`(?i)(/\*.*\*/)`),
	regexp.MustCompile(`'(\s*OR\s*'1'\s*=\s*'1)`),
	regexp.MustCompile(`'\s*OR\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)(\bDROP\b.*\bTABLE\b)`),
	regexp.MustCompile(`(?i)(\bINSERT\b.*\bINTO\b)`),
}

func DetectSQLInjection(input string) bool {
	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func SanitizeSQL(input string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"'", "''",
		"\"", "\\\"",
		"\x00", "",
		"\n", "\\n",
		"\r", "\\r",
	)
	return replacer.Replace(input)
}

// =============================================================================
// XSS Protection
// =============================================================================

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>`),
	regexp.MustCompile(`(?i)</script>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<embed`),
}

func DetectXSS(input string) bool {
	for _, pattern := range xssPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func SanitizeHTML(input string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
	)
	return replacer.Replace(input)
}

// =============================================================================
// SSRF Protection
// =============================================================================

var internalRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"0.0.0.0/8",
}

var metadataHosts = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.goog",
}

func (s *Slop) ValidateURL(rawURL string) (bool, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, "Invalid URL"
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false, "Invalid protocol"
	}

	host := parsed.Hostname()
	if host == "" {
		return false, "No host specified"
	}

	// Check allowlist
	for _, allowed := range s.config.SSRFAllowlist {
		if host == allowed {
			return true, ""
		}
	}

	// Check metadata hosts
	if s.config.SSRFBlockMetadata {
		for _, meta := range metadataHosts {
			if host == meta {
				return false, "Metadata endpoint blocked"
			}
		}
	}

	// Check localhost
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false, "Localhost blocked"
	}

	// Check internal IPs
	if s.config.SSRFBlockInternal {
		ip := net.ParseIP(host)
		if ip != nil {
			for _, cidr := range internalRanges {
				_, network, _ := net.ParseCIDR(cidr)
				if network.Contains(ip) {
					return false, "Internal IP blocked"
				}
			}
		}
	}

	return true, ""
}

// =============================================================================
// Rate Limiting
// =============================================================================

func (s *Slop) CheckRateLimit(key string) bool {
	if !s.config.RateLimitEnabled {
		return true
	}

	now := time.Now()
	window := time.Minute

	val, _ := s.rateLimitStore.LoadOrStore(key, []time.Time{})
	timestamps := val.([]time.Time)

	// Filter old timestamps
	var validTimestamps []time.Time
	for _, t := range timestamps {
		if now.Sub(t) < window {
			validTimestamps = append(validTimestamps, t)
		}
	}

	if len(validTimestamps) >= s.config.RequestsPerMinute {
		return false
	}

	validTimestamps = append(validTimestamps, now)
	s.rateLimitStore.Store(key, validTimestamps)
	return true
}

// =============================================================================
// Brute Force Protection
// =============================================================================

func (s *Slop) RecordAuthFailure(key string) {
	if !s.config.BruteForceEnabled {
		return
	}

	now := time.Now()
	val, loaded := s.bruteForce.LoadOrStore(key, bruteForceEntry{Attempts: 1, LastAttempt: now})
	if loaded {
		entry := val.(bruteForceEntry)
		entry.Attempts++
		entry.LastAttempt = now
		s.bruteForce.Store(key, entry)
	}
}

func (s *Slop) RecordAuthSuccess(key string) {
	s.bruteForce.Delete(key)
}

func (s *Slop) IsLockedOut(key string) bool {
	if !s.config.BruteForceEnabled {
		return false
	}

	val, ok := s.bruteForce.Load(key)
	if !ok {
		return false
	}

	entry := val.(bruteForceEntry)
	lockoutDuration := time.Duration(s.config.LockoutMinutes) * time.Minute

	if entry.Attempts >= s.config.MaxAttempts {
		if time.Since(entry.LastAttempt) < lockoutDuration {
			return true
		}
		// Reset after lockout period
		s.bruteForce.Delete(key)
	}

	return false
}

// =============================================================================
// Cryptography
// =============================================================================

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Argon2id parameters
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(hash)), nil
}

func VerifyPassword(password, encoded string) bool {
	// Parse the encoded hash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}

	salt, _ := hex.DecodeString(parts[4])
	storedHash, _ := hex.DecodeString(parts[5])

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Constant-time comparison
	if len(hash) != len(storedHash) {
		return false
	}
	var result byte
	for i := range hash {
		result |= hash[i] ^ storedHash[i]
	}
	return result == 0
}

func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func SHA256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// Security Headers
// =============================================================================

func (s *Slop) GetSecurityHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
}

// =============================================================================
// HTTP Middleware (net/http)
// =============================================================================

func (s *Slop) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		}

		// Rate limiting
		if !s.CheckRateLimit(clientIP) {
			http.Error(w, `{"error":"Too many requests"}`, http.StatusTooManyRequests)
			return
		}

		// Add security headers
		for key, value := range s.GetSecurityHeaders() {
			w.Header().Set(key, value)
		}

		// SSRF protection for URL parameters
		for _, param := range []string{"url", "redirect", "next", "callback"} {
			if urlValue := r.URL.Query().Get(param); urlValue != "" {
				if strings.HasPrefix(urlValue, "http") {
					if valid, reason := s.ValidateURL(urlValue); !valid {
						http.Error(w, fmt.Sprintf(`{"error":"Invalid URL: %s"}`, reason), http.StatusBadRequest)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Convenience function for creating middleware
func Middleware(config ...SlopConfig) func(http.Handler) http.Handler {
	s := New(config...)
	return s.Middleware
}

// =============================================================================
// Gin Middleware
// =============================================================================

// For use with gin-gonic/gin:
// import "github.com/gin-gonic/gin"
// r := gin.Default()
// r.Use(slop.GinMiddleware())

/*
func GinMiddleware(config ...SlopConfig) gin.HandlerFunc {
	s := New(config...)
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Rate limiting
		if !s.CheckRateLimit(clientIP) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}

		// Add security headers
		for key, value := range s.GetSecurityHeaders() {
			c.Header(key, value)
		}

		c.Next()
	}
}
*/
