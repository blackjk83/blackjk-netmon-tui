# Makefile for Network Monitor TUI - Rocky Linux 9
# Provides easy build, install, and package management

.PHONY: all build release test clean install uninstall package rpm docker help

# Configuration
PROJECT_NAME := network-monitor
VERSION := $(shell grep '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
TARGET_DIR := target
INSTALL_PREFIX := /usr
CONFIG_DIR := /etc
SYSTEMD_DIR := /lib/systemd/system

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

all: build

help: ## Show this help message
	@echo "Network Monitor TUI - Build System"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build debug version
	@echo -e "$(BLUE)Building debug version...$(NC)"
	cargo build

release: ## Build optimized release version
	@echo -e "$(BLUE)Building optimized release...$(NC)"
	RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1" \
	cargo build --release
	strip $(TARGET_DIR)/release/$(PROJECT_NAME)
	@echo -e "$(GREEN)✅ Release build completed$(NC)"

test: ## Run all tests
	@echo -e "$(BLUE)Running tests...$(NC)"
	cargo test --release
	@echo -e "$(GREEN)✅ All tests passed$(NC)"

clean: ## Clean build artifacts
	@echo -e "$(YELLOW)Cleaning build artifacts...$(NC)"
	cargo clean
	rm -rf $(TARGET_DIR)/package $(TARGET_DIR)/install $(TARGET_DIR)/rpm

install: release ## Install to system (requires root)
	@echo -e "$(BLUE)Installing Network Monitor TUI...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)Error: Installation requires root privileges$(NC)"; \
		echo "Please run: sudo make install"; \
		exit 1; \
	fi
	
	# Install binary
	install -m 755 $(TARGET_DIR)/release/$(PROJECT_NAME) $(INSTALL_PREFIX)/bin/
	
	# Install configuration
	install -m 644 examples/config.toml $(CONFIG_DIR)/$(PROJECT_NAME).conf
	
	# Install documentation
	mkdir -p $(INSTALL_PREFIX)/share/doc/$(PROJECT_NAME)
	install -m 644 README.md $(INSTALL_PREFIX)/share/doc/$(PROJECT_NAME)/
	install -m 644 INSTALL.md $(INSTALL_PREFIX)/share/doc/$(PROJECT_NAME)/
	
	# Install man page if exists
	if [ -f docs/$(PROJECT_NAME).1 ]; then \
		install -m 644 docs/$(PROJECT_NAME).1 $(INSTALL_PREFIX)/share/man/man1/; \
		mandb -q 2>/dev/null || true; \
	fi
	
	# Install systemd service
	install -m 644 scripts/$(PROJECT_NAME).service $(SYSTEMD_DIR)/
	systemctl daemon-reload
	
	# Set capabilities
	setcap cap_net_raw,cap_net_admin=eip $(INSTALL_PREFIX)/bin/$(PROJECT_NAME)
	
	@echo -e "$(GREEN)✅ Installation completed!$(NC)"
	@echo "Start with: $(PROJECT_NAME)"
	@echo "Service: systemctl start $(PROJECT_NAME)"

uninstall: ## Remove from system (requires root)
	@echo -e "$(YELLOW)Uninstalling Network Monitor TUI...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)Error: Uninstallation requires root privileges$(NC)"; \
		echo "Please run: sudo make uninstall"; \
		exit 1; \
	fi
	
	# Stop and disable service
	systemctl stop $(PROJECT_NAME) 2>/dev/null || true
	systemctl disable $(PROJECT_NAME) 2>/dev/null || true
	
	# Remove files
	rm -f $(INSTALL_PREFIX)/bin/$(PROJECT_NAME)
	rm -f $(CONFIG_DIR)/$(PROJECT_NAME).conf
	rm -rf $(INSTALL_PREFIX)/share/doc/$(PROJECT_NAME)
	rm -f $(INSTALL_PREFIX)/share/man/man1/$(PROJECT_NAME).1
	rm -f $(SYSTEMD_DIR)/$(PROJECT_NAME).service
	
	# Reload systemd
	systemctl daemon-reload
	
	@echo -e "$(GREEN)✅ Uninstallation completed$(NC)"

package: release ## Create distribution package
	@echo -e "$(BLUE)Creating distribution package...$(NC)"
	./scripts/build-release.sh
	@echo -e "$(GREEN)✅ Package created: $(TARGET_DIR)/$(PROJECT_NAME)-$(VERSION)-rocky9-x86_64.tar.gz$(NC)"

rpm: ## Create RPM package for Rocky Linux 9
	@echo -e "$(BLUE)Creating RPM package...$(NC)"
	./scripts/create-rpm.sh
	@echo -e "$(GREEN)✅ RPM package created in $(TARGET_DIR)/rpm/$(NC)"

docker: ## Build Docker image for testing
	@echo -e "$(BLUE)Building Docker image...$(NC)"
	docker build -t $(PROJECT_NAME):$(VERSION) -f docker/Dockerfile .
	@echo -e "$(GREEN)✅ Docker image built: $(PROJECT_NAME):$(VERSION)$(NC)"

check-deps: ## Check system dependencies
	@echo -e "$(BLUE)Checking dependencies...$(NC)"
	@command -v cargo >/dev/null 2>&1 || { echo "❌ Rust/Cargo not found"; exit 1; }
	@command -v gcc >/dev/null 2>&1 || { echo "❌ GCC not found"; exit 1; }
	@command -v pkg-config >/dev/null 2>&1 || { echo "❌ pkg-config not found"; exit 1; }
	@echo -e "$(GREEN)✅ All dependencies satisfied$(NC)"

dev-setup: ## Setup development environment
	@echo -e "$(BLUE)Setting up development environment...$(NC)"
	rustup update
	rustup component add clippy rustfmt
	cargo install cargo-audit cargo-outdated
	@echo -e "$(GREEN)✅ Development environment ready$(NC)"

lint: ## Run code linting
	@echo -e "$(BLUE)Running linter...$(NC)"
	cargo clippy -- -D warnings
	cargo fmt --check
	@echo -e "$(GREEN)✅ Code linting passed$(NC)"

audit: ## Run security audit
	@echo -e "$(BLUE)Running security audit...$(NC)"
	cargo audit
	@echo -e "$(GREEN)✅ Security audit completed$(NC)"

bench: ## Run benchmarks
	@echo -e "$(BLUE)Running benchmarks...$(NC)"
	cargo bench
	@echo -e "$(GREEN)✅ Benchmarks completed$(NC)"

size: release ## Show binary size information
	@echo -e "$(BLUE)Binary size information:$(NC)"
	@ls -lh $(TARGET_DIR)/release/$(PROJECT_NAME)
	@echo ""
	@echo "Dependencies:"
	@ldd $(TARGET_DIR)/release/$(PROJECT_NAME) 2>/dev/null || echo "Static binary"

run: build ## Run debug version
	@echo -e "$(BLUE)Running debug version...$(NC)"
	cargo run

run-release: release ## Run release version
	@echo -e "$(BLUE)Running release version...$(NC)"
	./$(TARGET_DIR)/release/$(PROJECT_NAME)

# Development targets
watch: ## Watch for changes and rebuild
	@echo -e "$(BLUE)Watching for changes...$(NC)"
	cargo watch -x build

watch-test: ## Watch for changes and run tests
	@echo -e "$(BLUE)Watching for changes and running tests...$(NC)"
	cargo watch -x test

# Quick targets
quick-install: release ## Quick install for development (no docs)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Please run: sudo make quick-install"; \
		exit 1; \
	fi
	install -m 755 $(TARGET_DIR)/release/$(PROJECT_NAME) $(INSTALL_PREFIX)/bin/
	setcap cap_net_raw,cap_net_admin=eip $(INSTALL_PREFIX)/bin/$(PROJECT_NAME)
	@echo -e "$(GREEN)✅ Quick install completed$(NC)"
