#!/bin/bash
# RPM package creation script for Network Monitor TUI - Rocky Linux 9

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_NAME="network-monitor"
VERSION=$(grep '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
RELEASE="1"
ARCH="x86_64"

echo -e "${BLUE}📦 Creating RPM package for Rocky Linux 9${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if rpmbuild is available
if ! command -v rpmbuild &> /dev/null; then
    echo -e "${YELLOW}Installing rpm-build tools...${NC}"
    sudo dnf install -y rpm-build rpmdevtools
fi

# Setup RPM build environment
echo -e "${YELLOW}Setting up RPM build environment...${NC}"
rpmdev-setuptree

# Create spec file
cat > ~/rpmbuild/SPECS/$PROJECT_NAME.spec << EOF
Name:           $PROJECT_NAME
Version:        $VERSION
Release:        $RELEASE%{?dist}
Summary:        TUI Network Monitor for Rocky Linux

License:        MIT
URL:            https://github.com/your-org/network-monitor-tui
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  pkg-config
BuildRequires:  libpcap-devel

Requires:       libpcap
Requires:       systemd

%description
Network Monitor TUI is a terminal-based network monitoring application
designed specifically for Rocky Linux 9.x systems. It provides real-time
network traffic analysis, connection monitoring, and optional advanced
features including firewall functionality, metrics explorer, and fuzzy search.

Features:
- Real-time network traffic monitoring
- Connection state tracking
- Protocol analysis (TCP/UDP/ICMP)
- Optional firewall functionality
- Metrics and historical analysis
- Fuzzy search capabilities
- Rocky Linux 9.x optimized

%prep
%setup -q

%build
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat"
cargo build --release

%install
rm -rf %{buildroot}

# Create directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1
mkdir -p %{buildroot}%{_unitdir}

# Install binary
install -m 755 target/release/%{name} %{buildroot}%{_bindir}/

# Install configuration
install -m 644 examples/config.toml %{buildroot}%{_sysconfdir}/%{name}.conf

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/
install -m 644 CHANGELOG.md %{buildroot}%{_docdir}/%{name}/ || true

# Install man page
install -m 644 docs/%{name}.1 %{buildroot}%{_mandir}/man1/ || true

# Install systemd service
cat > %{buildroot}%{_unitdir}/%{name}.service << 'SYSTEMD_EOF'
[Unit]
Description=Network Monitor TUI Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=%{_bindir}/%{name} -c %{_sysconfdir}/%{name}.conf
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
SYSTEMD_EOF

%files
%{_bindir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}.conf
%{_docdir}/%{name}/
%{_mandir}/man1/%{name}.1*
%{_unitdir}/%{name}.service

%post
# Set capabilities for packet capture
setcap cap_net_raw,cap_net_admin=eip %{_bindir}/%{name} || true
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%changelog
* $(date +'%a %b %d %Y') Network Monitor Team <team@example.com> - $VERSION-$RELEASE
- Initial RPM package for Rocky Linux 9
- Real-time network monitoring capabilities
- Advanced features: firewall, metrics, search
- Rocky Linux 9.x optimized build
EOF

# Create source tarball
echo -e "${YELLOW}📦 Creating source tarball...${NC}"
cd "$SCRIPT_DIR/.."
tar --exclude-vcs --exclude='target' --exclude='*.rpm' \
    -czf "$SOURCES_DIR/${PROJECT_NAME}-${VERSION}.tar.gz" \
    --transform "s,^\.,${PROJECT_NAME}-${VERSION}," \
    .

# Build RPM
echo -e "${YELLOW}Building RPM package...${NC}"
rpmbuild -ba ~/rpmbuild/SPECS/$PROJECT_NAME.spec

# Copy RPM to target directory
mkdir -p target/rpm
cp ~/rpmbuild/RPMS/$ARCH/$PROJECT_NAME-$VERSION-$RELEASE.*.rpm target/rpm/
cp ~/rpmbuild/SRPMS/$PROJECT_NAME-$VERSION-$RELEASE.*.src.rpm target/rpm/

echo -e "${GREEN}✅ RPM package created successfully!${NC}"
echo -e "Location: target/rpm/$PROJECT_NAME-$VERSION-$RELEASE.el9.$ARCH.rpm"
echo ""
echo -e "${BLUE}Installation:${NC}"
echo -e "sudo dnf install target/rpm/$PROJECT_NAME-$VERSION-$RELEASE.el9.$ARCH.rpm"
echo ""
echo -e "${BLUE}Service management:${NC}"
echo -e "sudo systemctl enable $PROJECT_NAME"
echo -e "sudo systemctl start $PROJECT_NAME"
