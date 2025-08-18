#!/bin/bash
# Example commands for running Network Monitor TUI

echo "🖥️  Network Monitor TUI - Example Commands"
echo "=========================================="

# Build the application first
echo "1️⃣  Building the application..."
cargo build --release

echo ""
echo "2️⃣  Example Usage Commands:"
echo ""

echo "📋 Basic usage:"
echo "   ./target/release/network-monitor"
echo ""

echo "🔍 Monitor specific interface:"
echo "   ./target/release/network-monitor --interface eth0"
echo "   ./target/release/network-monitor -i enp0s3"
echo ""

echo "🐛 Debug mode:"
echo "   ./target/release/network-monitor --debug"
echo "   RUST_LOG=debug ./target/release/network-monitor"
echo ""

echo "⚙️  Custom configuration:"
echo "   ./target/release/network-monitor --config examples/config.toml"
echo ""

echo "🔐 With elevated privileges (for packet capture):"
echo "   sudo ./target/release/network-monitor"
echo ""

echo "🛡️  Set capabilities (run once, then no sudo needed):"
echo "   sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor"
echo "   ./target/release/network-monitor  # Now works without sudo"
echo ""

echo "📊 Development commands:"
echo "   cargo run                    # Run debug version"
echo "   cargo test                   # Run tests"
echo "   cargo check                  # Quick compile check"
echo "   cargo build --release        # Build optimized version"
echo ""

echo "🎮 TUI Controls (when running):"
echo "   Tab     - Switch between tabs"
echo "   1       - Dashboard view"
echo "   2       - Connections view"
echo "   3       - Packets view"
echo "   q       - Quit application"
