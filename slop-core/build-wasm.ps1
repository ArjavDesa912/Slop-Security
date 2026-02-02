# 🛡️ Slop Security - WASM Build Script (PowerShell)
# 
# Prerequisites:
#   - Rust toolchain: rustup
#   - wasm-pack: cargo install wasm-pack

$ErrorActionPreference = "Stop"

Write-Host "🛡️ Building Slop Security WASM..." -ForegroundColor Cyan

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Blue

$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustc) {
    Write-Host "Error: Rust not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}

$wasmPack = Get-Command wasm-pack -ErrorAction SilentlyContinue
if (-not $wasmPack) {
    Write-Host "Installing wasm-pack..." -ForegroundColor Blue
    cargo install wasm-pack
}

# Ensure wasm32 target is installed
Write-Host "Ensuring wasm32 target..." -ForegroundColor Blue
rustup target add wasm32-unknown-unknown

# Navigate to slop-core directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "Building WASM package..." -ForegroundColor Blue

# Build for web (ESM)
Write-Host "Building for web (ESM)..." -ForegroundColor Blue
wasm-pack build --target web --release --out-dir pkg/web

# Build for Node.js (CommonJS)
Write-Host "Building for Node.js..." -ForegroundColor Blue
wasm-pack build --target nodejs --release --out-dir pkg/node

# Build for bundlers (webpack, etc.)
Write-Host "Building for bundlers..." -ForegroundColor Blue
wasm-pack build --target bundler --release --out-dir pkg/bundler

Write-Host ""
Write-Host "✅ WASM build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Output directories:"
Write-Host "  - pkg/web     (ESM for browsers)"
Write-Host "  - pkg/node    (CommonJS for Node.js)"
Write-Host "  - pkg/bundler (for webpack/rollup)"
Write-Host ""
Write-Host "Usage:"
Write-Host "  import init, { sanitize, validate_url } from './pkg/web/slop_core.js';"
Write-Host "  await init();"
Write-Host "  const safe = sanitize(userInput);"
