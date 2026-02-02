# frozen_string_literal: true

require_relative "slop/version"
require_relative "slop/core"
require_relative "slop/rack_middleware"
require_relative "slop/rails_middleware"

# 🛡️ Slop Security - Ruby SDK
# One line to secure, zero lines to worry.
#
# Rails:
#   # config/application.rb
#   config.middleware.use Slop::RailsMiddleware
#
# Sinatra:
#   use Slop::RackMiddleware

module Slop
  class Error < StandardError; end
  
  class << self
    attr_accessor :config
    
    def configure
      self.config ||= Configuration.new
      yield(config) if block_given?
    end
    
    def secure(app)
      if defined?(Rails) && app.is_a?(Rails::Application)
        app.config.middleware.use Slop::RailsMiddleware
      else
        app.use Slop::RackMiddleware
      end
      app
    end
  end
  
  class Configuration
    attr_accessor :rate_limit_enabled, :requests_per_minute,
                  :brute_force_enabled, :max_attempts, :lockout_minutes,
                  :ssrf_block_internal, :ssrf_allowlist
    
    def initialize
      @rate_limit_enabled = true
      @requests_per_minute = 100
      @brute_force_enabled = true
      @max_attempts = 5
      @lockout_minutes = 15
      @ssrf_block_internal = true
      @ssrf_allowlist = []
    end
  end
end

Slop.config = Slop::Configuration.new
