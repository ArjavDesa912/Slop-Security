# frozen_string_literal: true

require "digest"
require "securerandom"
require "uri"
require "ipaddr"

module Slop
  module Core
    extend self
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
      /\bUNION\b.*\bSELECT\b/i,
      /\bSELECT\b.*\bFROM\b/i,
      /--\s*$/,
      /\/\*.*\*\//,
      /'\s*OR\s*'1'\s*=\s*'1/i,
      /'\s*OR\s+\d+\s*=\s*\d+/i,
      /\bDROP\b.*\bTABLE\b/i,
    ].freeze
    
    # XSS patterns
    XSS_PATTERNS = [
      /<script[^>]*>/i,
      /<\/script>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
    ].freeze
    
    # Internal IP ranges
    INTERNAL_RANGES = [
      IPAddr.new("10.0.0.0/8"),
      IPAddr.new("172.16.0.0/12"),
      IPAddr.new("192.168.0.0/16"),
      IPAddr.new("127.0.0.0/8"),
      IPAddr.new("169.254.0.0/16"),
    ].freeze
    
    METADATA_HOSTS = %w[
      169.254.169.254
      metadata.google.internal
      metadata.goog
    ].freeze
    
    # =========================================================================
    # SQL Injection
    # =========================================================================
    
    def detect_sql_injection?(input)
      return false unless input.is_a?(String)
      SQL_INJECTION_PATTERNS.any? { |pattern| input.match?(pattern) }
    end
    
    def sanitize_sql(input)
      input.to_s
           .gsub("\\", "\\\\")
           .gsub("'", "''")
           .gsub('"', '\\"')
           .gsub("\0", "")
           .gsub("\n", "\\n")
           .gsub("\r", "\\r")
    end
    
    # =========================================================================
    # XSS Protection
    # =========================================================================
    
    def detect_xss?(input)
      return false unless input.is_a?(String)
      XSS_PATTERNS.any? { |pattern| input.match?(pattern) }
    end
    
    def sanitize_html(input)
      input.to_s
           .gsub("&", "&amp;")
           .gsub("<", "&lt;")
           .gsub(">", "&gt;")
           .gsub('"', "&quot;")
           .gsub("'", "&#x27;")
    end
    
    # =========================================================================
    # SSRF Protection
    # =========================================================================
    
    def validate_url(url, config = Slop.config)
      uri = URI.parse(url)
      
      return [false, "Invalid protocol"] unless %w[http https].include?(uri.scheme)
      return [false, "No host"] if uri.host.nil? || uri.host.empty?
      
      host = uri.host
      
      # Check allowlist
      return [true, nil] if config.ssrf_allowlist.include?(host)
      
      # Check metadata hosts
      return [false, "Metadata endpoint blocked"] if METADATA_HOSTS.include?(host)
      
      # Check localhost
      return [false, "Localhost blocked"] if %w[localhost 127.0.0.1 ::1].include?(host)
      
      # Check internal IPs
      if config.ssrf_block_internal
        begin
          ip = IPAddr.new(host)
          INTERNAL_RANGES.each do |range|
            return [false, "Internal IP blocked"] if range.include?(ip)
          end
        rescue IPAddr::InvalidAddressError
          # Not an IP, might be a domain
        end
      end
      
      [true, nil]
    rescue URI::InvalidURIError
      [false, "Invalid URL"]
    end
    
    # =========================================================================
    # Cryptography
    # =========================================================================
    
    def hash_password(password)
      require "bcrypt"
      BCrypt::Password.create(password)
    end
    
    def verify_password(password, hash)
      require "bcrypt"
      BCrypt::Password.new(hash) == password
    rescue BCrypt::Errors::InvalidHash
      false
    end
    
    def generate_token(length = 32)
      SecureRandom.urlsafe_base64(length)
    end
    
    def sha256(data)
      Digest::SHA256.hexdigest(data)
    end
    
    # =========================================================================
    # Security Headers
    # =========================================================================
    
    def security_headers
      {
        "X-Content-Type-Options" => "nosniff",
        "X-Frame-Options" => "DENY",
        "X-XSS-Protection" => "1; mode=block",
        "Strict-Transport-Security" => "max-age=31536000; includeSubDomains",
        "Content-Security-Policy" => "default-src 'self'",
        "Referrer-Policy" => "strict-origin-when-cross-origin",
      }
    end
    
    # =========================================================================
    # Rate Limiting
    # =========================================================================
    
    @rate_limit_store = {}
    @rate_limit_mutex = Mutex.new
    
    def check_rate_limit(key)
      return true unless Slop.config.rate_limit_enabled
      
      @rate_limit_mutex.synchronize do
        now = Time.now
        window = 60 # 1 minute
        
        @rate_limit_store[key] ||= []
        @rate_limit_store[key].reject! { |t| now - t > window }
        
        if @rate_limit_store[key].size >= Slop.config.requests_per_minute
          return false
        end
        
        @rate_limit_store[key] << now
        true
      end
    end
    
    # =========================================================================
    # Brute Force Protection
    # =========================================================================
    
    @brute_force_store = {}
    @brute_force_mutex = Mutex.new
    
    def record_auth_failure(key)
      return unless Slop.config.brute_force_enabled
      
      @brute_force_mutex.synchronize do
        @brute_force_store[key] ||= { attempts: 0, last_attempt: Time.now }
        @brute_force_store[key][:attempts] += 1
        @brute_force_store[key][:last_attempt] = Time.now
      end
    end
    
    def record_auth_success(key)
      @brute_force_mutex.synchronize do
        @brute_force_store.delete(key)
      end
    end
    
    def locked_out?(key)
      return false unless Slop.config.brute_force_enabled
      
      @brute_force_mutex.synchronize do
        entry = @brute_force_store[key]
        return false unless entry
        
        lockout_seconds = Slop.config.lockout_minutes * 60
        
        if entry[:attempts] >= Slop.config.max_attempts
          if Time.now - entry[:last_attempt] < lockout_seconds
            return true
          else
            @brute_force_store.delete(key)
          end
        end
        
        false
      end
    end
  end
end
