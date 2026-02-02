#!/usr/bin/env bash
# 🛡️ Slop Security - WASM Build Script
# 
# Prerequisites:
#   - Rust toolchain: rustup
#   - wasm-pack: cargo install wasm-pack
#   - wasm-opt (optional): npm install -g wasm-opt

set -e

echo "🛡️ Building Slop Security WASM..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

if ! command -v rustc &> /dev/null; then
    echo -e "${RED}Error: Rust not found. Install from https://rustup.rs${NC}"
    exit 1
fi

if ! command -v wasm-pack &> /dev/null; then
    echo -e "${BLUE}Installing wasm-pack...${NC}"
    cargo install wasm-pack
fi

# Ensure wasm32 target is installed
echo -e "${BLUE}Ensuring wasm32 target...${NC}"
rustup target add wasm32-unknown-unknown

# Build WASM
cd "$(dirname "$0")"
echo -e "${BLUE}Building WASM package...${NC}"

# Build for web (ESM)
wasm-pack build --target web --release --out-dir pkg/web

# Build for Node.js (CommonJS)
wasm-pack build --target nodejs --release --out-dir pkg/node

# Build for bundlers (webpack, etc.)
wasm-pack build --target bundler --release --out-dir pkg/bundler

# Optimize WASM if wasm-opt is available
if command -v wasm-opt &> /dev/null; then
    echo -e "${BLUE}Optimizing WASM...${NC}"
    for wasm_file in pkg/*/slop_core_bg.wasm; do
        wasm-opt -O3 -o "$wasm_file.opt" "$wasm_file"
        mv "$wasm_file.opt" "$wasm_file"
    done
fi

echo -e "${GREEN}✅ WASM build complete!${NC}"
echo ""
echo "Output directories:"
echo "  - pkg/web     (ESM for browsers)"
echo "  - pkg/node    (CommonJS for Node.js)"
echo "  - pkg/bundler (for webpack/rollup)"
echo ""
echo "Usage:"
echo "  import init, { sanitize, validate_url } from './pkg/web/slop_core.js';"
echo "  await init();"
echo "  const safe = sanitize(userInput);"
