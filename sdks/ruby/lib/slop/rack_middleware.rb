# frozen_string_literal: true

module Slop
  class RackMiddleware
    def initialize(app)
      @app = app
      puts "🛡️ Slop Security initialized for Rack"
    end
    
    def call(env)
      request = Rack::Request.new(env)
      
      # Get client IP
      client_ip = request.ip || env["REMOTE_ADDR"] || "unknown"
      
      # Rate limiting
      unless Core.check_rate_limit(client_ip)
        return [429, {"Content-Type" => "application/json"}, ['{"error":"Too many requests"}']]
      end
      
      # SSRF protection for URL parameters
      %w[url redirect next callback].each do |param|
        url_value = request.params[param]
        if url_value && url_value.start_with?("http")
          valid, reason = Core.validate_url(url_value)
          unless valid
            return [400, {"Content-Type" => "application/json"}, [%({"error":"Invalid URL: #{reason}"})]]
          end
        end
      end
      
      # Pass to next middleware
      status, headers, body = @app.call(env)
      
      # Add security headers
      Core.security_headers.each do |key, value|
        headers[key] = value
      end
      
      [status, headers, body]
    end
  end
end
