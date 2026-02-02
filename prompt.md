Role: You are a Senior Security Architect and "Vibecoding" Specialist. Goal: Create a comprehensive SLOP_SECURITY_SPEC.md file that defines an open-source security library called "Slop Security" designed specifically for AI-generated code (slop).

The Vision: Vibecoders build apps at lightning speed, but often neglect security. "Slop Security" is a "one-line" integration that automatically applies OWASP Top 10 protections without the developer needing technical depth.

The Output (.md file) must include:

The Slop Philosophy: * Zero-Cognitive-Load principle: "One line to secure, zero lines to worry."

AI-First Design: Optimized for LLM integration.

OWASP Core Integration:

Detail how the library mitigates the OWASP Top 10 by default (e.g., Automatic SQL Injection prevention, XSS filtering, Secure Session management, and Broken Access Control guards).

Explain how the library "patches" common slop mistakes (like hardcoded keys or unvalidated redirects).

The Universal Engine:

Define a core security engine written in Rust (compiled to WASM) or Go.

Identify how this core ensures identical OWASP-compliant behavior across Node.js, Python, Go, Ruby, and PHP.

The Slop Manifest (slop.json):

A schema that an AI can edit to toggle OWASP features (e.g., sqli_protection: true, xss_filter: true).

Language SDK Blueprints:

Show "One-Line" initialization examples for all major languages.

Include the slop.secure() wrapper that provides a "sandbox" for AI-generated code.

The "Vibe-Check" CLI:

A tool that scans AI-generated code for OWASP violations and auto-patches them using Slop Security.

The "System Instructions" Snippet:

A short text block for users to paste into their AI "Custom Instructions" to ensure Slop Security is used correctly every time.

Format Requirements:

Use professional Markdown.

Include Mermaid.js diagrams for the Slop-to-OWASP Mapping.

Maintain a "Vibecoder-friendly" tone.