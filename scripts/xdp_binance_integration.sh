#!/bin/bash
# XDP Binance Integration Test Script
# Runs the complete XDP workflow: prepare -> filter -> test -> reset
#
# Usage: sudo ./scripts/xdp_binance_integration.sh [interface]
# Example: sudo ./scripts/xdp_binance_integration.sh enp108s0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IFACE="${1:-enp108s0}"
DOMAIN="stream.binance.com"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo ""
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║         XDP Binance Integration Test (AF_XDP Zero-Copy)           ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Interface: $IFACE"
    echo "  Domain:    $DOMAIN"
    echo ""
}

print_step() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Step $1: $2${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function for exit
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        print_error "Test failed or interrupted. Running cleanup..."
    fi
    "$SCRIPT_DIR/xdp_reset.sh" "$IFACE" 2>/dev/null || true
    exit $exit_code
}

# Set trap for cleanup on exit
trap cleanup EXIT INT TERM

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (sudo)"
    exit 1
fi

# Check if interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    print_error "Interface $IFACE does not exist"
    exit 1
fi

cd "$PROJECT_DIR"

print_banner

# Step 0: Build
print_step "0/5" "Building XDP Binance Integration Test"
echo "Cleaning and rebuilding..."
USE_XDP=1 USE_OPENSSL=1 make clean >/dev/null 2>&1
USE_XDP=1 USE_OPENSSL=1 make src/xdp/bpf/exchange_filter.bpf.o build/test_xdp_binance_integration 2>&1 | tail -5

if [[ ! -x "$PROJECT_DIR/build/test_xdp_binance_integration" ]]; then
    print_error "Build failed. Check compiler output above."
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Build complete"

# Step 1: Prepare
print_step "1/5" "Preparing NIC for XDP"
"$SCRIPT_DIR/xdp_prepare.sh" "$IFACE"

# Step 2: Filter
print_step "2/5" "Setting up DNS and route bypass"
"$SCRIPT_DIR/xdp_filter.sh" "$IFACE" "$DOMAIN"

# Step 3: Run test
print_step "3/5" "Running XDP Binance Integration Test"
timeout 45 "$PROJECT_DIR/build/test_xdp_binance_integration" "$IFACE"
TEST_RESULT=$?

# Step 4: Reset (handled by trap, but show status)
print_step "4/5" "Cleanup"

if [[ $TEST_RESULT -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  INTEGRATION TEST PASSED ✅                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                  INTEGRATION TEST FAILED ❌                        ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    exit 1
fi
