#!/bin/bash
# Build script for Network Monitor TUI - Rocky Linux 9
# Creates optimized release builds and packages

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="network-monitor"
VERSION=$(grep '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
BUILD_DIR="target/release"
PACKAGE_DIR="target/package"
INSTALL_DIR="target/install"

echo -e "${BLUE}🚀 Network Monitor TUI Build Script${NC}"
echo -e "${BLUE}====================================${NC}"
echo -e "Project: ${PROJECT_NAME}"
echo -e "Version: ${VERSION}"
echo -e "Target:  Rocky Linux 9.x"
echo ""

# Validate system
echo -e "${YELLOW}📋 Validating build environment...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Rust/Cargo not found. Please install Rust toolchain.${NC}"
    exit 1
fi

if ! command -v gcc &> /dev/null; then
    echo -e "${RED}❌ GCC not found. Please install build-essential.${NC}"
    exit 1
fi

if ! command -v pkg-config &> /dev/null; then
    echo -e "${RED}❌ pkg-config not found. Please install pkg-config.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Build environment validated${NC}"

# Check Rocky Linux 9
echo -e "${YELLOW}🔍 Checking system compatibility...${NC}"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID" == "rocky" && "$VERSION_ID" =~ ^9\. ]]; then
        echo -e "${GREEN}✅ Rocky Linux 9.x detected: $PRETTY_NAME${NC}"
    else
        echo -e "${YELLOW}⚠️  Warning: Not Rocky Linux 9.x. Build may not be optimized for target platform.${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Warning: Cannot detect OS version.${NC}"
fi

# Clean previous builds
echo -e "${YELLOW}🧹 Cleaning previous builds...${NC}"
cargo clean
rm -rf "$PACKAGE_DIR" "$INSTALL_DIR"
mkdir -p "$PACKAGE_DIR" "$INSTALL_DIR"

# Build optimized release
echo -e "${YELLOW}🔨 Building optimized release...${NC}"
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1"
cargo build --release

if [[ ! -f "$BUILD_DIR/$PROJECT_NAME" ]]; then
    echo -e "${RED}❌ Build failed - binary not found${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Release build completed${NC}"

# Get binary info
BINARY_SIZE=$(du -h "$BUILD_DIR/$PROJECT_NAME" | cut -f1)
echo -e "Binary size: ${BINARY_SIZE}"

# Strip binary for smaller size
echo -e "${YELLOW}🔧 Optimizing binary...${NC}"
strip "$BUILD_DIR/$PROJECT_NAME"
STRIPPED_SIZE=$(du -h "$BUILD_DIR/$PROJECT_NAME" | cut -f1)
echo -e "Optimized size: ${STRIPPED_SIZE}"

# Run tests
echo -e "${YELLOW}🧪 Running tests...${NC}"
cargo test --release --quiet
echo -e "${GREEN}✅ All tests passed${NC}"

# Create package structure
echo -e "${YELLOW}📦 Creating package structure...${NC}"
mkdir -p "$PACKAGE_DIR"/{bin,etc,usr/share/doc/$PROJECT_NAME,usr/share/man/man1,lib/systemd/system}

# Copy binary
cp "$BUILD_DIR/$PROJECT_NAME" "$PACKAGE_DIR/bin/"

# Copy configuration
cp examples/config.toml "$PACKAGE_DIR/etc/$PROJECT_NAME.conf"

# Copy documentation
cp README.md "$PACKAGE_DIR/usr/share/doc/$PROJECT_NAME/"
cp CHANGELOG.md "$PACKAGE_DIR/usr/share/doc/$PROJECT_NAME/" 2>/dev/null || true
cp LICENSE* "$PACKAGE_DIR/usr/share/doc/$PROJECT_NAME/" 2>/dev/null || true

# Create man page
cat > "$PACKAGE_DIR/usr/share/man/man1/$PROJECT_NAME.1" << 'EOF'
.TH NETWORK-MONITOR 1 "2024" "Network Monitor TUI" "User Commands"
.SH NAME
network-monitor \- TUI Network Monitor for Rocky Linux
.SH SYNOPSIS
.B network-monitor
[\fIOPTIONS\fR]
.SH DESCRIPTION
Network Monitor TUI is a terminal-based network monitoring application designed for Rocky Linux 9.x systems. It provides real-time network traffic analysis, connection monitoring, and optional advanced features like firewall functionality.
.SH OPTIONS
.TP
\fB\-i\fR, \fB\-\-interface\fR \fIINTERFACE\fR
Network interface to monitor
.TP
\fB\-c\fR, \fB\-\-config\fR \fICONFIG\fR
Configuration file path
.TP
\fB\-d\fR, \fB\-\-debug\fR
Enable debug logging
.TP
\fB\-\-enable\-firewall\fR
Enable firewall functionality (advanced)
.TP
\fB\-\-enable\-metrics\fR
Enable metrics explorer (advanced)
.TP
\fB\-\-enable\-search\fR
Enable fuzzy search (advanced)
.TP
\fB\-\-enable\-all\-advanced\fR
Enable all advanced features
.TP
\fB\-h\fR, \fB\-\-help\fR
Print help information
.SH FILES
.TP
\fI/etc/network-monitor.conf\fR
System-wide configuration file
.TP
\fI~/.config/network-monitor/config.toml\fR
User configuration file
.SH EXAMPLES
.TP
Monitor default interface:
.B network-monitor
.TP
Monitor specific interface with firewall:
.B network-monitor \-i eth0 \-\-enable\-firewall
.TP
Use custom configuration:
.B network-monitor \-c /path/to/config.toml
.SH AUTHOR
Network Monitor TUI Development Team
.SH SEE ALSO
.BR tcpdump (1),
.BR netstat (8),
.BR ss (8)
EOF

# Create systemd service (optional)
cat > "$PACKAGE_DIR/lib/systemd/system/$PROJECT_NAME.service" << EOF
[Unit]
Description=Network Monitor TUI Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/$PROJECT_NAME -c /etc/$PROJECT_NAME.conf
Restart=always
RestartSec=5
User=root
Group=root

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /tmp

[Install]
WantedBy=multi-user.target
EOF

# Create install script
cat > "$PACKAGE_DIR/install.sh" << 'EOF'
#!/bin/bash
# Installation script for Network Monitor TUI

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Installing Network Monitor TUI...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Install binary
echo -e "${YELLOW}Installing binary...${NC}"
install -m 755 bin/network-monitor /usr/bin/

# Install configuration
echo -e "${YELLOW}Installing configuration...${NC}"
install -m 644 etc/network-monitor.conf /etc/

# Install documentation
echo -e "${YELLOW}Installing documentation...${NC}"
mkdir -p /usr/share/doc/network-monitor
cp -r usr/share/doc/network-monitor/* /usr/share/doc/network-monitor/

# Install man page
echo -e "${YELLOW}Installing man page...${NC}"
install -m 644 usr/share/man/man1/network-monitor.1 /usr/share/man/man1/
mandb -q 2>/dev/null || true

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
install -m 644 lib/systemd/system/network-monitor.service /lib/systemd/system/
systemctl daemon-reload

# Set capabilities for packet capture
echo -e "${YELLOW}Setting capabilities...${NC}"
setcap cap_net_raw,cap_net_admin=eip /usr/bin/network-monitor

echo -e "${GREEN}✅ Installation completed!${NC}"
echo ""
echo "Usage:"
echo "  network-monitor                    # Start with default settings"
echo "  network-monitor --enable-firewall # Start with firewall enabled"
echo "  systemctl start network-monitor   # Start as service"
echo ""
echo "Configuration: /etc/network-monitor.conf"
echo "Documentation: /usr/share/doc/network-monitor/"
echo "Manual: man network-monitor"
EOF

chmod +x "$PACKAGE_DIR/install.sh"

# Create uninstall script
cat > "$PACKAGE_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# Uninstallation script for Network Monitor TUI

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Uninstalling Network Monitor TUI...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Stop and disable service
systemctl stop network-monitor 2>/dev/null || true
systemctl disable network-monitor 2>/dev/null || true

# Remove files
rm -f /usr/bin/network-monitor
rm -f /etc/network-monitor.conf
rm -rf /usr/share/doc/network-monitor
rm -f /usr/share/man/man1/network-monitor.1
rm -f /lib/systemd/system/network-monitor.service

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}✅ Uninstallation completed!${NC}"
EOF

chmod +x "$PACKAGE_DIR/uninstall.sh"

# Create tarball
echo -e "${YELLOW}📦 Creating distribution package...${NC}"
cd target
tar -czf "$PROJECT_NAME-$VERSION-rocky9-x86_64.tar.gz" -C package .
cd ..

PACKAGE_SIZE=$(du -h "target/$PROJECT_NAME-$VERSION-rocky9-x86_64.tar.gz" | cut -f1)

echo ""
echo -e "${GREEN}🎉 Build completed successfully!${NC}"
echo -e "${GREEN}=================================${NC}"
echo -e "Package: target/$PROJECT_NAME-$VERSION-rocky9-x86_64.tar.gz"
echo -e "Size: $PACKAGE_SIZE"
echo ""
echo -e "${BLUE}Installation:${NC}"
echo -e "1. Extract: tar -xzf $PROJECT_NAME-$VERSION-rocky9-x86_64.tar.gz"
echo -e "2. Install: sudo ./install.sh"
echo -e "3. Run: network-monitor"
echo ""
echo -e "${BLUE}Advanced usage:${NC}"
echo -e "• Firewall: network-monitor --enable-firewall"
echo -e "• Config: network-monitor -c /path/to/config.toml"
echo -e "• Service: systemctl start network-monitor"
