<p align="center">
  <img src="./assets/just mascot.png" alt="Slop Security Mascot" width="150"/>
</p>

# Contributing to Slop Security

Thank you for your interest in contributing to Slop Security! 🛡️

## Getting Started

### Prerequisites

- **Rust** (1.70+) with `wasm32-unknown-unknown` target
- **Node.js** (18+) with npm
- **Python** (3.8+)

### Setup

```bash
# Clone the repository
git clone https://github.com/slop-security/slop-security.git
cd slop-security

# Install Rust WASM target
rustup target add wasm32-unknown-unknown

# Install Node.js dependencies
cd sdks/node && npm install && cd ../..
cd vibe-check && npm install && cd ..

# Install Python dependencies
cd sdks/python && pip install -e ".[dev]" && cd ../..
```

## Development

### Rust Core

```bash
cd slop-core

# Format code
cargo fmt

# Lint
cargo clippy

# Run tests
cargo test

# Build WASM
cargo build --target wasm32-unknown-unknown --release
```

### Node.js SDK

```bash
cd sdks/node

# Build
npm run build

# Lint
npm run lint

# Test
npm test
```

### Python SDK

```bash
cd sdks/python

# Lint
ruff check slop/

# Type check
mypy slop/

# Test
pytest
```

### Vibe-Check CLI

```bash
cd vibe-check

# Build
npm run build

# Test
node dist/cli.js ../examples --include "**/*.js"
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Add** tests for new functionality
5. **Run** all tests and linting
6. **Commit** your changes (`git commit -m 'Add amazing feature'`)
7. **Push** to your branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

## Coding Standards

### Rust
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Pass `cargo clippy` without warnings

### TypeScript/JavaScript
- Use TypeScript for all new code
- Follow existing code style
- Use meaningful variable names

### Python
- Follow PEP 8
- Use type hints
- Document public functions

## Adding New Vulnerability Patterns

To add a new vulnerability pattern to vibe-check:

1. Edit `vibe-check/src/index.ts`
2. Add pattern to `VULNERABILITY_PATTERNS` array:

```typescript
{
    pattern: /your-regex-pattern/gi,
    severity: 'critical' | 'high' | 'medium' | 'low',
    owaspId: 'A01-A10',
    owaspName: 'OWASP Category Name',
    message: 'Description of the vulnerability',
    getFix: (match) => ({ before: match, after: 'fixed code' }), // optional
},
```

3. Add a test case in `examples/vulnerable-example.js`
4. Run the scanner to verify detection

## Adding New SDK Framework Support

1. Create a new file (e.g., `sdks/node/src/hono.ts`)
2. Implement framework-specific middleware
3. Export from `package.json` under a new subpath
4. Add documentation to README
5. Add tests

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please email security@slopsecurity.io with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours.

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to make the web more secure! 🛡️

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
