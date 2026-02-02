# 🛡️ Slop Security - Go SDK

> **One line to secure, zero lines to worry.**

## Installation

```bash
go get github.com/slop-security/slop-security/sdks/go/slop
```

## Quick Start

### net/http

```go
package main

import (
    "net/http"
    "github.com/slop-security/slop-security/sdks/go/slop"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, secured world!"))
    })

    // 🛡️ One line
    handler := slop.Middleware()(mux)

    http.ListenAndServe(":8080", handler)
}
```

### Gin

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/slop-security/slop-security/sdks/go/slop"
)

func main() {
    r := gin.Default()
    
    // 🛡️ One line
    r.Use(slop.GinMiddleware())

    r.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "secured"})
    })

    r.Run()
}
```

## Features

### SQL Injection Detection

```go
if slop.DetectSQLInjection(userInput) {
    return errors.New("SQL injection detected")
}

safe := slop.SanitizeSQL(userInput)
```

### XSS Protection

```go
if slop.DetectXSS(userInput) {
    return errors.New("XSS detected")
}

safe := slop.SanitizeHTML(userInput)
```

### SSRF Protection

```go
s := slop.New()
valid, reason := s.ValidateURL(url)
if !valid {
    return fmt.Errorf("SSRF blocked: %s", reason)
}
```

### Password Hashing (Argon2id)

```go
hash, err := slop.HashPassword("password123")
if err != nil {
    return err
}

if slop.VerifyPassword("password123", hash) {
    // Password is correct
}
```

### Secure Token Generation

```go
token, err := slop.GenerateToken(32)
```

## Configuration

```go
config := slop.SlopConfig{
    RateLimitEnabled:  true,
    RequestsPerMinute: 100,
    BruteForceEnabled: true,
    MaxAttempts:       5,
    LockoutMinutes:    15,
    SSRFBlockInternal: true,
    SSRFAllowlist:     []string{"api.trusted.com"},
}

s := slop.New(config)
```

## License

MIT
