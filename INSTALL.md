# Installation Guide - Network Monitor TUI

## Quick Install (Rocky Linux)

### 1. Prerequisites Check
```bash
# Check your system
cat /etc/os-release
uname -r
```

### 2. Install Rust (if needed)
```bash
# Rust will auto-install when running cargo, or install manually:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 3. Install System Dependencies
```bash
# Install required development packages
sudo dnf install -y libpcap-devel gcc
```

### 4. Build Application
```bash
# Navigate to project directory
cd network-monitor

# Build release version
cargo build --release
```

### 5. Set Up Permissions (Optional)
```bash
# For packet capture capabilities
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor
```

### 6. Test Installation
```bash
# Test without privileges (fallback mode)
./target/release/network-monitor --help

# Test with full monitoring
./target/release/network-monitor
```

## Verification

Your installation is successful if:
- ✅ Application shows help with `--help`
- ✅ TUI starts without errors
- ✅ Kernel version is detected correctly
- ✅ Network interfaces are listed

## Troubleshooting

### Build Errors
```bash
# Clean and rebuild
cargo clean
cargo build --release
```

### Permission Issues
```bash
# Run with sudo as fallback
sudo ./target/release/network-monitor
```

### Missing Dependencies
```bash
# Install all development tools
sudo dnf groupinstall "Development Tools"
sudo dnf install libpcap-devel
```
