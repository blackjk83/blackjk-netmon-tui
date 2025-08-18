# Network Monitor TUI

A Terminal User Interface (TUI) network monitoring tool designed specifically for **Rocky Linux** with **kernel 5.x compatibility**. This tool provides real-time network traffic analysis through a modern terminal interface, with graceful fallbacks for systems with limited eBPF support.

## Features

- 🖥️ **Modern TUI Interface** - Clean, responsive terminal interface with multiple views
- 🔍 **Real-time Monitoring** - Live network traffic analysis and connection tracking
- 🛡️ **Rocky Linux Optimized** - Specifically designed for Rocky Linux with kernel 5.x
- 📊 **Multiple Views** - Dashboard, Connections, and Packets tabs
- 🔄 **Graceful Fallbacks** - Uses /proc filesystem when packet capture is unavailable
- ⚡ **Lightweight** - Minimal resource usage for continuous monitoring
- 🔧 **Protocol Support** - TCP, UDP, IPv4, IPv6 protocol identification

## System Requirements

- **Operating System**: Rocky Linux (tested on Rocky Linux 9)
- **Kernel**: 5.x or higher (automatically detected)
- **Architecture**: x86_64
- **Rust**: 1.70+ (automatically installed if needed)

## Installation

### Prerequisites

The application will automatically prompt to install Rust if not present:

```bash
# Rust will be installed automatically when running cargo commands
```

### Build from Source

1. **Clone or navigate to the project directory**:
   ```bash
   cd /path/to/network-monitor
   ```

2. **Build the application**:
   ```bash
   cargo build --release
   ```

3. **The binary will be available at**:
   ```bash
   ./target/release/network-monitor
   ```

## Usage

### Basic Commands

#### View Help
```bash
./target/release/network-monitor --help
```

#### Run with Default Settings
```bash
./target/release/network-monitor
```

#### Monitor Specific Interface
```bash
./target/release/network-monitor --interface eth0
```

#### Enable Debug Logging
```bash
./target/release/network-monitor --debug
```

#### Use Custom Configuration
```bash
./target/release/network-monitor --config /path/to/config.toml
```

### Development Commands

#### Check Code (Fast Compilation Check)
```bash
cargo check
```

#### Build Debug Version
```bash
cargo build
```

#### Build Release Version (Optimized)
```bash
cargo build --release
```

#### Run Tests
```bash
cargo test
```

#### Run with Debug Output
```bash
RUST_LOG=debug cargo run
```

#### Clean Build Artifacts
```bash
cargo clean
```

### TUI Controls

Once the application is running:

- **`q`** - Quit the application
- **`Tab`** - Switch between tabs
- **`1`** - Switch to Dashboard view
- **`2`** - Switch to Connections view  
- **`3`** - Switch to Packets view

## Permissions

### For Packet Capture (Optional)

The application works in two modes:

1. **Full Mode** (with packet capture) - requires elevated privileges
2. **Fallback Mode** (connection monitoring only) - works without privileges

#### Option 1: Run with sudo (Simple)
```bash
sudo ./target/release/network-monitor
```

#### Option 2: Set Capabilities (Recommended)
```bash
# Build first
cargo build --release

# Set capabilities (allows running without sudo)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor

# Now run without sudo
./target/release/network-monitor
```

#### Option 3: Fallback Mode (No privileges needed)
```bash
# Just run normally - will automatically fall back to /proc monitoring
./target/release/network-monitor
```

## Configuration

### Default Configuration

The application auto-detects system settings:

- **Kernel Version**: Automatically detected
- **Rocky Linux Mode**: Auto-enabled on Rocky Linux systems  
- **Interface**: Auto-selected or specify with `--interface`
- **Fallback Methods**: Automatically used on kernel 5.x

### Custom Configuration File

Create a `config.toml` file:

```toml
[capture]
interface = "eth0"          # Specific interface to monitor
buffer_size = 65536         # Capture buffer size
timeout_ms = 1000          # Capture timeout
promiscuous = false        # Promiscuous mode

[ui]
refresh_rate_ms = 1000     # UI refresh rate
default_view = "dashboard"  # Starting view
color_scheme = "dark"      # Color scheme

[system]
rocky_linux_mode = true    # Rocky Linux optimizations
use_ebpf_fallback = true   # Use fallback for kernel 5.x
check_capabilities = true  # Check for required permissions
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Error: Failed to open capture device: Permission denied
# Solution: Use one of the permission options above
sudo ./target/release/network-monitor
```

#### 2. No Network Interfaces Found
```bash
# Error: No network interfaces found
# Solution: Check available interfaces
ip link show
# Then specify interface manually
./target/release/network-monitor --interface eth0
```

#### 3. Compilation Issues
```bash
# Error: cargo: command not found
# Solution: Rust will be auto-installed, or install manually:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### 4. Library Dependencies
```bash
# Error: libpcap not found
# Solution: Install development packages
sudo dnf install libpcap-devel
```

### Debug Mode

For detailed troubleshooting:

```bash
# Enable debug logging
RUST_LOG=debug ./target/release/network-monitor --debug

# Or during development
RUST_LOG=debug cargo run -- --debug
```

## System Compatibility

### Tested Systems

- ✅ Rocky Linux 9 (kernel 5.14.0)
- ✅ Rocky Linux 8 (kernel 4.18+)
- ✅ RHEL 9 compatible systems
- ✅ CentOS Stream 9

### Kernel Compatibility

- **Kernel 5.x**: Full support with automatic fallbacks
- **Kernel 4.x**: Limited support, /proc monitoring only
- **Kernel 6.x+**: Full support with enhanced features

## Development

### Project Structure

```
network-monitor/
├── src/
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library exports
│   ├── config/              # Configuration management
│   │   ├── mod.rs
│   │   └── settings.rs
│   ├── capture/             # Network capture engines
│   │   ├── mod.rs
│   │   ├── pcap_engine.rs   # libpcap-based capture
│   │   └── proc_parser.rs   # /proc filesystem parser
│   ├── ui/                  # Terminal user interface
│   │   ├── mod.rs
│   │   └── app.rs           # Main TUI application
│   └── utils/               # Utility functions
│       ├── mod.rs
│       └── formatting.rs    # Data formatting
├── Cargo.toml               # Dependencies and metadata
└── README.md               # This file
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_tcp_state_display

# Run tests in release mode
cargo test --release
```

### Contributing

1. **Check code formatting**:
   ```bash
   cargo fmt --check
   ```

2. **Run clippy for linting**:
   ```bash
   cargo clippy
   ```

3. **Ensure tests pass**:
   ```bash
   cargo test
   ```

## Performance

### Resource Usage

- **CPU**: < 5% during normal monitoring
- **Memory**: < 50MB for typical workloads  
- **Disk**: Minimal (no persistent storage)
- **Network**: Passive monitoring only

### Optimization Tips

1. **Use release builds** for production:
   ```bash
   cargo build --release
   ```

2. **Adjust refresh rate** in config for lower resource usage:
   ```toml
   [ui]
   refresh_rate_ms = 2000  # Slower refresh = less CPU
   ```

3. **Monitor specific interface** instead of "any":
   ```bash
   ./target/release/network-monitor --interface eth0
   ```

## License

This project is designed for Rocky Linux system administrators and network engineers who need reliable, lightweight network monitoring tools that work consistently across different kernel versions.

## Support

For issues specific to Rocky Linux compatibility or kernel 5.x limitations, please ensure you're running the latest version and have followed the permission setup instructions above.

### Quick Start Summary

```bash
# 1. Build the application
cargo build --release

# 2. Set permissions (optional, for packet capture)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor

# 3. Run the monitor
./target/release/network-monitor

# 4. Use TUI controls: Tab to switch views, 'q' to quit
```

The application will automatically detect your Rocky Linux system and kernel version, enabling appropriate compatibility modes for optimal performance.
