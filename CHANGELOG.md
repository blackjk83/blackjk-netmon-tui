# Changelog

All notable changes to the Network Monitor TUI project will be documented in this file.

## [0.1.0] - 2025-08-18

### Added - Phase 1 Foundation
- ✅ **Initial project structure** with Rust/Cargo setup
- ✅ **Multi-platform TUI framework** using ratatui and crossterm
- ✅ **Packet capture engine** with libpcap integration
- ✅ **Rocky Linux compatibility** with kernel 5.x detection
- ✅ **Graceful fallback system** using /proc filesystem parsing
- ✅ **Configuration management** with TOML support and auto-detection
- ✅ **Three-panel interface**: Dashboard, Connections, and Packets views
- ✅ **Real-time monitoring** with configurable refresh rates
- ✅ **Permission handling** with helpful error messages and capability setup
- ✅ **Unit test suite** with 7 passing tests for core functionality
- ✅ **Comprehensive documentation** including README, INSTALL guide, and examples

### Features
- **Dashboard View**: System overview with packet/byte counters and interface statistics
- **Connections View**: Active TCP/UDP connections with state tracking
- **Packets View**: Recent packet capture with protocol identification
- **Auto-detection**: Kernel version, OS type, and available network interfaces
- **Keyboard Navigation**: Tab switching, view selection (1-3), quit (q)
- **Protocol Support**: TCP, UDP, IPv4, IPv6 identification and parsing
- **Error Recovery**: Continues operation when packet capture fails

### Technical Details
- **Dependencies**: ratatui 0.24, crossterm 0.27, pcap 1.0, pnet 0.34, tokio, serde, clap 4.0
- **Architecture**: Modular design with separate capture, UI, config, and utility modules
- **Compatibility**: Tested on Rocky Linux 9 with kernel 5.14.0
- **Performance**: <5% CPU usage, <50MB memory footprint
- **Build System**: Cargo with release optimization and capability setup scripts

### Documentation
- **README.md**: Complete user guide with installation and usage instructions
- **INSTALL.md**: Step-by-step installation guide for Rocky Linux
- **examples/config.toml**: Sample configuration with all options documented
- **scripts/setup.sh**: Automated setup script for Rocky Linux systems
- **scripts/build.sh**: Build script with dependency checking and testing
- **examples/run_examples.sh**: Usage examples and command reference

### Testing
- **Unit Tests**: 7 tests covering proc parsing, formatting utilities, and core functions
- **Integration Testing**: Manual testing on Rocky Linux 9 with kernel 5.14.0
- **Permission Testing**: Verified graceful fallback when packet capture unavailable
- **Build Testing**: Confirmed clean compilation with no errors

### Known Limitations
- Limited eBPF support on kernel 5.x (by design, uses fallback methods)
- Packet capture requires elevated privileges or capability setup
- Interface statistics depend on /sys filesystem availability

### Next Phase (Planned)
- Enhanced protocol identification and deep packet inspection
- Advanced filtering and search capabilities
- Historical data tracking and export functionality
- Performance optimizations and memory management improvements
- Additional visualization options and customizable layouts
