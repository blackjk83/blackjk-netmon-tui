#!/bin/bash
# Build script for Network Monitor TUI

set -e

echo "🔧 Building Network Monitor TUI..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Check for system dependencies
echo "📦 Checking system dependencies..."
if ! pkg-config --exists libpcap; then
    echo "⚠️  libpcap-devel not found. Install with:"
    echo "   sudo dnf install libpcap-devel"
    echo "   Continuing anyway (will use fallback mode)..."
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
cargo clean

# Run tests
echo "🧪 Running tests..."
cargo test

# Build release version
echo "🚀 Building release version..."
cargo build --release

# Check if build was successful
if [ -f "./target/release/network-monitor" ]; then
    echo "✅ Build successful!"
    echo "📍 Binary location: ./target/release/network-monitor"
    echo ""
    echo "🔐 To enable packet capture, run:"
    echo "   sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor"
    echo ""
    echo "🏃 To run the application:"
    echo "   ./target/release/network-monitor"
else
    echo "❌ Build failed!"
    exit 1
fi
