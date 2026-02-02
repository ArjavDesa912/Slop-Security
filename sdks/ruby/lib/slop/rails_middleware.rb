# frozen_string_literal: true

module Slop
  class RailsMiddleware
    def initialize(app)
      @app = app
      Rails.logger.info "🛡️ Slop Security initialized for Rails" if defined?(Rails)
    end
    
    def call(env)
      request = ActionDispatch::Request.new(env)
      
      # Get client IP
      client_ip = request.remote_ip || "unknown"
      
      # Rate limiting
      unless Core.check_rate_limit(client_ip)
        return [
          429,
          {"Content-Type" => "application/json"},
          ['{"error":"Too many requests"}']
        ]
      end
      
      # SSRF protection for URL parameters
      %w[url redirect next callback].each do |param|
        url_value = request.params[param]
        if url_value.is_a?(String) && url_value.start_with?("http")
          valid, reason = Core.validate_url(url_value)
          unless valid
            return [
              400,
              {"Content-Type" => "application/json"},
              [%({"error":"Invalid URL: #{reason}"})]
            ]
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
