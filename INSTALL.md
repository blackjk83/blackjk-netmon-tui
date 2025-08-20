# Installation Guide - Network Monitor TUI

## System Requirements

### Supported Platforms
- **Rocky Linux 9.x** (Primary target)
- Kernel 5.x with el9 designation
- x86_64 architecture

### Hardware Requirements
- **RAM**: Minimum 512MB, Recommended 2GB
- **Storage**: 100MB free disk space
- **CPU**: Any x86_64 processor
- **Network**: Network interface for monitoring

### Software Dependencies
- **Rust toolchain**: 1.70+ (for building from source)
- **GCC**: Build tools and compiler
- **pkg-config**: Package configuration tool
- **libpcap**: Packet capture library and headers
- **systemd**: For service management (optional)

## Quick Installation (Recommended)

### Option 1: Pre-built Package (Fastest)

1. **Download the latest release package:**
```bash
# Download from releases page or build server
wget https://releases.example.com/network-monitor-latest-rocky9-x86_64.tar.gz
```

2. **Extract and install:**
```bash
tar -xzf network-monitor-*-rocky9-x86_64.tar.gz
cd network-monitor-*/
sudo ./install.sh
```

3. **Verify installation:**
```bash
network-monitor --help
```

### Option 2: RPM Package (Rocky Linux Native)

1. **Install RPM package:**
```bash
sudo dnf install ./network-monitor-*.el9.x86_64.rpm
```

2. **Enable and start service:**
```bash
sudo systemctl enable network-monitor
sudo systemctl start network-monitor
```

## Build from Source

### Step 1: Install Build Dependencies

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install system dependencies
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y pkg-config libpcap-devel systemd-devel
```

### Step 2: Clone and Build

```bash
# Clone repository
git clone <repository-url>
cd network-monitor

# Build optimized release
make release

# Run tests
make test

# Install system-wide
sudo make install
```

### Step 3: Verify Installation

```bash
# Check binary
which network-monitor

# Test basic functionality
network-monitor --help

# Check capabilities
getcap /usr/bin/network-monitor
```

## Configuration

### System Configuration

The main configuration file is located at `/etc/network-monitor.conf`:

```bash
# Copy example configuration
sudo cp examples/config.toml /etc/network-monitor.conf

# Edit configuration
sudo nano /etc/network-monitor.conf
```

### Key Configuration Options

```toml
[capture]
interface = "ens18"          # Network interface to monitor
buffer_size = 65536          # Packet capture buffer size
timeout_ms = 1000           # Capture timeout

[advanced_features]
firewall_enabled = false     # Enable firewall functionality
metrics_enabled = false      # Enable metrics explorer
search_enabled = false       # Enable fuzzy search

[ui]
refresh_rate_ms = 3000      # UI refresh rate
default_view = "dashboard"   # Starting view
color_scheme = "dark"       # Color theme
```

### User Configuration (Optional)

Create user-specific configuration:
```bash
mkdir -p ~/.config/network-monitor
cp /etc/network-monitor.conf ~/.config/network-monitor/config.toml
```

## Usage Examples

### Basic Monitoring

```bash
# Start with default configuration
network-monitor

# Monitor specific interface
network-monitor -i eth0

# Use custom configuration file
network-monitor -c /path/to/custom-config.toml

# Enable debug logging
network-monitor --debug
```

### Advanced Features

```bash
# Enable firewall functionality
network-monitor --enable-firewall

# Enable metrics explorer
network-monitor --enable-metrics

# Enable fuzzy search
network-monitor --enable-search

# Enable all advanced features
network-monitor --enable-all-advanced

# Combine options
network-monitor -i ens18 --enable-firewall --enable-metrics
```

### Service Management

```bash
# Start as systemd service
sudo systemctl start network-monitor

# Enable auto-start on boot
sudo systemctl enable network-monitor

# Check service status
sudo systemctl status network-monitor

# View service logs
journalctl -u network-monitor -f

# Stop service
sudo systemctl stop network-monitor
```

### Navigation and Controls

- **Tab** or **1-5**: Switch between views
- **↑↓**: Navigate lists and options
- **←→**: Navigate connections/events
- **Enter**: Toggle/select items
- **q**: Quit application
- **h**: Help (context-sensitive)

## Advanced Installation Options

### Custom Installation Prefix

```bash
# Install to custom location
make install INSTALL_PREFIX=/opt/network-monitor

# Add to PATH
echo 'export PATH="/opt/network-monitor/bin:$PATH"' >> ~/.bashrc
```

### Development Installation

```bash
# Setup development environment
make dev-setup

# Install development dependencies
cargo install cargo-watch cargo-audit

# Quick development install
sudo make quick-install
```

### Docker Deployment

```bash
# Build Docker image
make docker

# Run in container
docker run -it --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --network=host network-monitor:latest
```

## Troubleshooting

### Permission Issues

**Problem**: "Permission denied" when capturing packets
**Solution**:
```bash
# Set required capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/network-monitor

# Or run as root
sudo network-monitor
```

### Interface Detection Issues

**Problem**: Interface not found or "any" interface used
**Solution**:
```bash
# List available interfaces
ip link show

# Check interface status
ip addr show ens18

# Specify interface explicitly
network-monitor -i ens18
```

### System Compatibility Issues

**Problem**: "System Compatibility Error"
**Solution**:
```bash
# Check OS version
cat /etc/os-release

# Verify Rocky Linux 9.x
grep "Rocky Linux" /etc/os-release
grep "VERSION_ID=\"9" /etc/os-release

# Check kernel version
uname -r | grep el9
```

### Build Issues

**Problem**: Compilation errors
**Solution**:
```bash
# Update Rust toolchain
rustup update

# Install missing dependencies
sudo dnf install -y gcc pkg-config libpcap-devel

# Clean and rebuild
make clean
make release
```

### Service Issues

**Problem**: Service fails to start
**Solution**:
```bash
# Check service logs
journalctl -u network-monitor --no-pager

# Verify configuration
network-monitor -c /etc/network-monitor.conf --debug

# Check file permissions
ls -la /etc/network-monitor.conf
```

### Performance Issues

**Problem**: High CPU/memory usage
**Solution**:
```bash
# Disable advanced features
network-monitor  # Run without --enable-* flags

# Adjust refresh rate in config
refresh_rate_ms = 5000  # Slower refresh

# Monitor resource usage
top -p $(pgrep network-monitor)
```

## Uninstallation

### Standard Uninstall

```bash
# Stop service
sudo systemctl stop network-monitor
sudo systemctl disable network-monitor

# Remove via make
sudo make uninstall

# Or use uninstall script
sudo ./uninstall.sh
```

### Complete Removal

```bash
# Remove all files and configurations
sudo rm -rf /usr/bin/network-monitor
sudo rm -rf /etc/network-monitor.conf
sudo rm -rf /usr/share/doc/network-monitor
sudo rm -rf ~/.config/network-monitor

# Remove systemd service
sudo rm -f /lib/systemd/system/network-monitor.service
sudo systemctl daemon-reload
```

### RPM Uninstall

```bash
sudo dnf remove network-monitor
```

## Getting Help

### Documentation
- **Manual page**: `man network-monitor`
- **Built-in help**: `network-monitor --help`
- **Configuration help**: Check `/usr/share/doc/network-monitor/`

### Support Resources
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Complete user and developer guides
- **Community**: Discussion forums and chat

### Diagnostic Information

When reporting issues, include:
```bash
# System information
uname -a
cat /etc/os-release

# Application version
network-monitor --version

# Configuration
cat /etc/network-monitor.conf

# Service status
systemctl status network-monitor
