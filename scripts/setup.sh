#!/bin/bash
# Setup script for Network Monitor TUI on Rocky Linux

set -e

echo "🚀 Network Monitor TUI Setup Script"
echo "=================================="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "📋 Detected OS: $NAME $VERSION"
else
    echo "⚠️  Could not detect OS version"
fi

# Detect kernel version
KERNEL_VERSION=$(uname -r)
echo "🔧 Kernel version: $KERNEL_VERSION"

# Check if Rocky Linux
if [[ "$NAME" == *"Rocky Linux"* ]]; then
    echo "✅ Rocky Linux detected - optimal compatibility"
else
    echo "⚠️  Not Rocky Linux - some features may be limited"
fi

# Install system dependencies
echo ""
echo "📦 Installing system dependencies..."
if command -v dnf &> /dev/null; then
    sudo dnf install -y libpcap-devel gcc curl
elif command -v yum &> /dev/null; then
    sudo yum install -y libpcap-devel gcc curl
else
    echo "❌ Package manager not found (dnf/yum)"
    exit 1
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo ""
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    echo "✅ Rust installed successfully"
else
    echo "✅ Rust already installed: $(rustc --version)"
fi

# Build the application
echo ""
echo "🔨 Building Network Monitor TUI..."
cargo build --release

# Set up capabilities
echo ""
echo "🔐 Setting up capabilities for packet capture..."
if [ -f "./target/release/network-monitor" ]; then
    sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor
    echo "✅ Capabilities set successfully"
else
    echo "❌ Build failed - binary not found"
    exit 1
fi

# Test the installation
echo ""
echo "🧪 Testing installation..."
if ./target/release/network-monitor --help > /dev/null 2>&1; then
    echo "✅ Installation test passed"
else
    echo "❌ Installation test failed"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📖 Usage:"
echo "  ./target/release/network-monitor           # Run with auto-detected interface"
echo "  ./target/release/network-monitor -i eth0   # Monitor specific interface"
echo "  ./target/release/network-monitor --help    # Show help"
echo ""
echo "🎮 TUI Controls:"
echo "  Tab or 1-3: Switch between views"
echo "  q: Quit application"
echo ""
echo "📚 Documentation:"
echo "  README.md     - Complete user guide"
echo "  INSTALL.md    - Installation instructions"
echo "  examples/     - Configuration examples"
