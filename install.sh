#!/bin/bash
# Zandoli — Install Script
# Builds from source and installs the binary + config.
# Compatible with Debian/Ubuntu/Kali, Fedora/RHEL, Arch, Alpine.
#
# Usage:
#   sudo bash install.sh              # Standard install
#   sudo bash install.sh --deps       # Also install system dependencies
#   bash install.sh --help            # Show help
#   bash install.sh --check           # Check prerequisites only

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/zandoli"
APP="zandoli"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $*"; }
fail()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# --- Help ---
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<EOF
Zandoli Install Script

Usage: sudo bash install.sh [OPTIONS]

Options:
  --deps       Install system dependencies (libpcap-dev, etc.)
  --check      Check prerequisites without installing
  --help       Show this help

Steps:
  1. Check Go >= 1.24 is installed
  2. Build the binary from source (go build)
  3. Install to $INSTALL_DIR/$APP
  4. Copy config.yaml to $CONFIG_DIR/config.yaml (if not present)

Prerequisites:
  - Go 1.24+
  - libpcap development headers (libpcap-dev / libpcap-devel)
  - Root privileges (sudo)
EOF
    exit 0
fi

# --- Check prerequisites ---
check_go() {
    if ! command -v go >/dev/null 2>&1; then
        fail "Go is not installed. Install Go 1.24+ from https://go.dev/dl/"
    fi
    local ver
    ver=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    info "Go $ver found"
}

check_libpcap() {
    if ldconfig -p 2>/dev/null | grep -q libpcap; then
        info "libpcap found"
        return 0
    fi
    if pkg-config --exists libpcap 2>/dev/null; then
        info "libpcap found (pkg-config)"
        return 0
    fi
    # Check for header file directly
    if [ -f /usr/include/pcap.h ] || [ -f /usr/include/pcap/pcap.h ]; then
        info "libpcap headers found"
        return 0
    fi
    warn "libpcap-dev not found. Install it or use --deps"
    return 1
}

install_deps() {
    info "Installing system dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq libpcap-dev build-essential
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q libpcap-devel gcc make
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm libpcap base-devel
    elif command -v apk >/dev/null 2>&1; then
        apk add libpcap-dev build-base
    else
        fail "Unknown package manager. Install libpcap-dev manually."
    fi
    info "Dependencies installed"
}

# --- Parse args ---
INSTALL_DEPS=false
CHECK_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --deps) INSTALL_DEPS=true ;;
        --check) CHECK_ONLY=true ;;
    esac
done

echo ""
echo "=== Zandoli Installer ==="
echo ""

# --- Dependencies ---
if [ "$INSTALL_DEPS" = true ]; then
    if [ "$EUID" -ne 0 ]; then fail "Run with sudo to install dependencies"; fi
    install_deps
fi

# --- Prerequisites ---
check_go
check_libpcap || {
    if [ "$INSTALL_DEPS" = false ]; then
        warn "Run with --deps to auto-install, or install libpcap-dev manually"
    fi
}

if [ "$CHECK_ONLY" = true ]; then
    info "Prerequisites check complete"
    exit 0
fi

# --- Build ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "go.mod" ]; then
    fail "go.mod not found. Run this script from the zandoli repo root."
fi

info "Building $APP..."
go build -o "build/$APP" "./cmd/$APP" || fail "Build failed"
info "Binary built: build/$APP ($(du -h "build/$APP" | cut -f1))"

# --- Install ---
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. Skipping system install."
    warn "Binary available at: $SCRIPT_DIR/build/$APP"
    echo ""
    echo "To install system-wide, run:"
    echo "  sudo cp build/$APP $INSTALL_DIR/$APP"
    exit 0
fi

cp "build/$APP" "$INSTALL_DIR/$APP"
chmod 755 "$INSTALL_DIR/$APP"
info "Installed to $INSTALL_DIR/$APP"

# --- Config ---
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp config.yaml "$CONFIG_DIR/config.yaml"
    info "Config installed to $CONFIG_DIR/config.yaml"
else
    info "Config already exists at $CONFIG_DIR/config.yaml (not overwritten)"
fi

# --- Verify ---
if command -v "$APP" >/dev/null 2>&1; then
    info "Installation verified: $(which $APP)"
else
    warn "$INSTALL_DIR may not be in PATH. Add it or run: export PATH=$INSTALL_DIR:\$PATH"
fi

echo ""
info "Zandoli installed successfully!"
echo ""
echo "  Quick start:"
echo "    zandoli --help"
echo "    zandoli --pcap capture.pcap --formats json,csv,html"
echo "    sudo zandoli --passive --interface eth0 --profile stealth"
echo ""
