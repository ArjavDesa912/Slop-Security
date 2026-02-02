# frozen_string_literal: true

require_relative "lib/slop/version"

Gem::Specification.new do |spec|
  spec.name = "slop-security"
  spec.version = Slop::VERSION
  spec.authors = ["Slop Security Team"]
  spec.email = ["team@slopsecurity.io"]

  spec.summary = "One-line security for AI-generated code"
  spec.description = "OWASP Top 10 protection out of the box for Rails, Sinatra, and Rack applications."
  spec.homepage = "https://slopsecurity.io"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/slop-security/slop-security"
  spec.metadata["changelog_uri"] = "https://github.com/slop-security/slop-security/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "bcrypt", "~> 3.1"
  spec.add_dependency "rack", ">= 2.0"

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end
