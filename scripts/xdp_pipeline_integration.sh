#!/bin/bash
# XDP Pipeline Integration Test Script
# Runs the complete XDP workflow: prepare -> filter -> pipeline test -> reset
# Always runs in multi-process mode with cores 2/4/6/8
#
# Usage: ./scripts/xdp_pipeline_integration.sh [interface] [timeout]
# Example: ./scripts/xdp_pipeline_integration.sh enp108s0      # Run forever (Ctrl+C to stop)
#          ./scripts/xdp_pipeline_integration.sh enp108s0 60   # 60s timeout
# Note: sudo is invoked internally for privileged operations (NIC config, XDP, AF_XDP sockets)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IFACE="${1:-enp108s0}"
TIMEOUT="${2:--1}"
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
    echo -e "${BOLD}║       XDP Pipeline Integration Test (AF_XDP Zero-Copy)             ║${NC}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Interface: $IFACE"
    echo "  Domain:    $DOMAIN"
    if [[ "$TIMEOUT" == "-1" ]]; then
        echo "  Timeout:   ∞ (Ctrl+C to stop)"
    else
        echo "  Timeout:   ${TIMEOUT}s"
    fi
    echo "  Mode:      multi-process (cores 2/4/6/8)"
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
    # Kill any lingering pipeline processes
    sudo pkill -9 -f binance_pipeline 2>/dev/null || true
    sleep 1
    sudo "$SCRIPT_DIR/xdp_reset.sh" "$IFACE" 2>/dev/null || true
    exit $exit_code
}

# Set trap for cleanup on exit
trap cleanup EXIT INT TERM

# Check if sudo is available (needed for privileged operations)
if ! command -v sudo &>/dev/null; then
    print_error "sudo is required but not found"
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
print_step "0/5" "Building Pipeline Integration Test"
echo "Cleaning and rebuilding..."
# Use WolfSSL with native I/O callbacks (no BIO/OPENSSL_EXTRA required)
USE_XDP=1 USE_WOLFSSL=1 XDP_INTERFACE="$IFACE" make clean >/dev/null 2>&1
USE_XDP=1 USE_WOLFSSL=1 XDP_INTERFACE="$IFACE" make src/xdp/bpf/exchange_filter.bpf.o build/binance_pipeline 2>&1 | tail -5

if [[ ! -x "$PROJECT_DIR/build/binance_pipeline" ]]; then
    print_error "Build failed. Check compiler output above."
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Build complete"

# Step 1: Prepare
print_step "1/5" "Preparing NIC for XDP"
sudo "$SCRIPT_DIR/xdp_prepare.sh" "$IFACE"

# Step 2: Filter
print_step "2/5" "Setting up DNS and route bypass"
sudo "$SCRIPT_DIR/xdp_filter.sh" "$IFACE" "$DOMAIN"

# Step 3: Run test
print_step "3/5" "Running Pipeline Integration Test"

# Always run in multi-process mode with cores 2,4,6,8
# sudo is required for AF_XDP socket operations
if [[ "$TIMEOUT" == "-1" ]]; then
    # Run forever (no timeout, Ctrl+C to stop)
    sudo taskset -c 2,4,6,8 "$PROJECT_DIR/build/binance_pipeline" "$IFACE"
    TEST_RESULT=$?
else
    # Run with timeout
    sudo timeout "$TIMEOUT" taskset -c 2,4,6,8 "$PROJECT_DIR/build/binance_pipeline" "$IFACE"
    TEST_RESULT=$?
    # timeout returns 124 on timeout - treat as success for timed tests
    if [[ $TEST_RESULT -eq 124 ]]; then
        TEST_RESULT=0
    fi
fi

# Step 4: Reset (handled by trap, but show status)
print_step "4/5" "Cleanup"

if [[ $TEST_RESULT -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  PIPELINE TEST PASSED ✅                           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                  PIPELINE TEST FAILED ❌                           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    exit 1
fi
