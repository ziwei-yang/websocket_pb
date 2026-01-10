#!/bin/bash
# scripts/test_pipeline_xdp_poll.sh
# XDP Poll Segregated Test - Remote Echo Server Mode
#
# SAFETY REQUIREMENTS:
# - Uses dedicated test interface ONLY (default: enp108s0)
# - NEVER modifies default route or other interfaces
# - Adds route ONLY for echo server IP via test interface
# - AF_XDP zero-copy mode with device-bound BPF
# - ProtonVPN and other interfaces remain untouched
# - SAFE-LOCK: 60 second timeout, auto-revert interface to original state
#
# Prerequisites:
# - Echo server running on remote machine: ncat -l 12345 -k -c 'cat'
# - Test interface connected to network that can reach echo server
# - sudo access (script uses sudo internally where needed)
# - BPF program compiled: make bpf
#
# Usage: ./scripts/test_pipeline_xdp_poll.sh [interface] [timeout_seconds]
#   interface: Network interface for testing (default: enp108s0)
#   timeout:   Safe-lock timeout in seconds (default: 60)
#
# NOTE: Do NOT run this script with sudo. It uses sudo internally only where
#       needed (XDP operations, IP configuration). This preserves user paths.

set -e

# ============================================================================
# Configuration
# ============================================================================

INTERFACE="${1:-enp108s0}"
SAFE_LOCK_TIMEOUT="${2:-60}"

# Echo server configuration
ECHO_SERVER_IP="139.162.79.171"
ECHO_SERVER_PORT="12345"

BPF_OBJ="src/xdp/bpf/exchange_filter.bpf.o"
TEST_BIN="build/test_pipeline_xdp_poll"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Route state for cleanup
ECHO_ROUTE_ADDED=false
GATEWAY_IP=""

# State snapshot for safe-lock revert
ORIGINAL_IP_STATE=""
ORIGINAL_LINK_STATE=""
SAFE_LOCK_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Safety Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

die() {
    log_error "$1"
    exit 1
}

# ============================================================================
# Safe-Lock Functions
# ============================================================================

# Capture current interface state before any modifications
snapshot_interface_state() {
    log_info "Capturing interface state snapshot for $INTERFACE..."

    # Capture all IP addresses on the interface
    ORIGINAL_IP_STATE=$(ip addr show dev "$INTERFACE" 2>/dev/null | grep -E "^\s+inet " || true)

    # Capture link state
    ORIGINAL_LINK_STATE=$(ip link show "$INTERFACE" 2>/dev/null | grep -o 'state [A-Z]*' | awk '{print $2}')

    # Check if echo server route already exists
    if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
        ECHO_ROUTE_ADDED=false
        log_info "Route to $ECHO_SERVER_IP already exists (will not remove on cleanup)"
    else
        ECHO_ROUTE_ADDED=true
        log_info "Route to $ECHO_SERVER_IP will be added (will remove on cleanup)"
    fi

    log_info "Original link state: $ORIGINAL_LINK_STATE"
    if [[ -n "$ORIGINAL_IP_STATE" ]]; then
        log_info "Original IPs:"
        echo "$ORIGINAL_IP_STATE" | while read -r line; do
            echo "        $line"
        done
    else
        log_info "No IPs configured on $INTERFACE"
    fi
}

# Revert interface to original state
revert_interface_state() {
    log_warn "SAFE-LOCK: Reverting interface $INTERFACE to original state..."

    # Kill the test process if running (needs sudo since test runs as root)
    if [[ -n "$TEST_PID" ]] && sudo kill -0 "$TEST_PID" 2>/dev/null; then
        log_warn "Killing test process (PID $TEST_PID)..."
        sudo kill -TERM "$TEST_PID" 2>/dev/null || true
        sleep 1
        sudo kill -KILL "$TEST_PID" 2>/dev/null || true
    fi

    # Detach XDP program (needs sudo)
    if ip link show "$INTERFACE" 2>/dev/null | grep -q "xdp"; then
        log_info "Detaching XDP program..."
        sudo ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
    fi

    # Remove echo server route if we added it (needs sudo)
    if [[ "$ECHO_ROUTE_ADDED" == "true" ]]; then
        if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
            log_info "Removing route to $ECHO_SERVER_IP..."
            sudo ip route del "$ECHO_SERVER_IP" dev "$INTERFACE" 2>/dev/null || true
        fi
    fi

    log_ok "Interface reverted to original state"

    # Show final state
    log_info "Final interface state:"
    ip addr show dev "$INTERFACE" 2>/dev/null | grep -E "inet |state " || true
    log_info "Routes via $INTERFACE:"
    ip route show dev "$INTERFACE" 2>/dev/null || echo "(no routes)"
}

# Safe-lock watchdog - kills everything after timeout
safe_lock_watchdog() {
    local timeout=$1
    local main_pid=$2

    sleep "$timeout"

    # Check if main script is still running
    if kill -0 "$main_pid" 2>/dev/null; then
        echo ""
        echo -e "${RED}============================================${NC}"
        echo -e "${RED}  SAFE-LOCK TIMEOUT (${timeout}s) TRIGGERED${NC}"
        echo -e "${RED}  Reverting interface to original state...${NC}"
        echo -e "${RED}============================================${NC}"
        echo ""

        # Send SIGUSR1 to main process to trigger cleanup
        kill -USR1 "$main_pid" 2>/dev/null || true

        # Give it 5 seconds to clean up gracefully
        sleep 5

        # Force kill if still running
        if kill -0 "$main_pid" 2>/dev/null; then
            echo -e "${RED}Force killing main process...${NC}"
            kill -KILL "$main_pid" 2>/dev/null || true
        fi
    fi
}

# Start the safe-lock watchdog
start_safe_lock() {
    log_info "Starting safe-lock watchdog (timeout: ${SAFE_LOCK_TIMEOUT}s)..."

    # Start watchdog in background
    safe_lock_watchdog "$SAFE_LOCK_TIMEOUT" $$ &
    SAFE_LOCK_PID=$!

    log_ok "Safe-lock active (PID: $SAFE_LOCK_PID)"
}

# Stop the safe-lock watchdog
stop_safe_lock() {
    if [[ -n "$SAFE_LOCK_PID" ]] && kill -0 "$SAFE_LOCK_PID" 2>/dev/null; then
        kill "$SAFE_LOCK_PID" 2>/dev/null || true
        wait "$SAFE_LOCK_PID" 2>/dev/null || true
        log_ok "Safe-lock watchdog stopped"
    fi
    SAFE_LOCK_PID=""
}

# Handle SIGUSR1 (triggered by safe-lock timeout)
handle_safe_lock_timeout() {
    log_error "Safe-lock timeout handler triggered!"
    revert_interface_state
    stop_safe_lock
    exit 124  # Standard timeout exit code
}

# Check sudo access (don't run as root, use sudo internally)
check_sudo_access() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root - this may cause path issues with ~/Proj"
        log_warn "Consider running as normal user (script uses sudo internally)"
    fi

    # Verify sudo access without password (or prompt once)
    if ! sudo -n true 2>/dev/null; then
        log_info "Sudo access required for XDP operations. Please authenticate:"
        sudo true || die "Sudo access required"
    fi
    log_ok "Sudo access verified"
}

# Verify interface exists and is NOT the default route interface
check_interface_safety() {
    log_info "Checking interface safety for $INTERFACE..."

    # Check interface exists
    if ! ip link show "$INTERFACE" &>/dev/null; then
        die "Interface $INTERFACE does not exist"
    fi

    # Get default route interface - NEVER touch this
    DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)

    if [[ -z "$DEFAULT_IFACE" ]]; then
        log_warn "No default route found (VPN may be handling routing)"
    else
        log_info "Default route interface: $DEFAULT_IFACE"

        if [[ "$INTERFACE" == "$DEFAULT_IFACE" ]]; then
            die "SAFETY VIOLATION: Cannot use default route interface $INTERFACE for testing!"
        fi
    fi

    # Check for any routes through our test interface (should be none or only test IP)
    EXISTING_ROUTES=$(ip route show dev "$INTERFACE" 2>/dev/null | grep -v "$TEST_IP" || true)
    if [[ -n "$EXISTING_ROUTES" ]]; then
        log_warn "Existing routes on $INTERFACE (will not be modified):"
        echo "$EXISTING_ROUTES" | while read -r line; do
            echo "        $line"
        done
    fi

    log_ok "Interface $INTERFACE is safe to use for testing"
}

# Verify VPN is still working (connectivity check)
check_connectivity() {
    log_info "Verifying external connectivity (VPN check)..."

    # Try to reach a common endpoint (don't care about actual response)
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        log_ok "External connectivity OK"
    else
        log_warn "Cannot reach 1.1.1.1 - VPN may be blocking ICMP (continuing anyway)"
    fi
}

# ============================================================================
# Setup Functions
# ============================================================================

# Test echo server connectivity
check_echo_server() {
    log_info "Testing echo server connectivity at $ECHO_SERVER_IP:$ECHO_SERVER_PORT..."

    # First check if we can reach the echo server at all
    if ! timeout 5 nc -zv "$ECHO_SERVER_IP" "$ECHO_SERVER_PORT" 2>&1; then
        log_error "Cannot connect to echo server at $ECHO_SERVER_IP:$ECHO_SERVER_PORT"
        log_error "Please ensure ncat is running: ncat -l $ECHO_SERVER_PORT -k -c 'cat'"
        die "Echo server not reachable"
    fi

    log_ok "Echo server is reachable"

    # Test actual echo functionality
    ECHO_RESPONSE=$(echo "test" | timeout 3 nc "$ECHO_SERVER_IP" "$ECHO_SERVER_PORT" 2>/dev/null || true)
    if [[ "$ECHO_RESPONSE" == "test" ]]; then
        log_ok "Echo server responding correctly"
    else
        log_warn "Echo server response: '$ECHO_RESPONSE' (expected 'test')"
        log_warn "Server may be running but not echoing - continuing anyway"
    fi
}

# Setup route to echo server via test interface
setup_echo_route() {
    log_info "Setting up route to echo server via $INTERFACE..."

    # Check if route already exists
    if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
        log_ok "Route to echo server already exists"
        ECHO_ROUTE_ADDED=false
        return 0
    fi

    # Get gateway for test interface
    GATEWAY_IP=$(ip route show dev "$INTERFACE" | grep -E "^default|^[0-9]" | grep via | awk '{print $3}' | head -1)
    if [[ -z "$GATEWAY_IP" ]]; then
        # No gateway, try to find one from the interface's subnet
        GATEWAY_IP=$(ip route show dev "$INTERFACE" | grep -v "^default" | awk '{print $1}' | head -1 | sed 's|/.*||')
        if [[ -z "$GATEWAY_IP" ]]; then
            log_warn "No gateway found for $INTERFACE, trying direct route"
            sudo ip route add "$ECHO_SERVER_IP/32" dev "$INTERFACE" 2>/dev/null || {
                die "Failed to add route to echo server (no gateway)"
            }
            ECHO_ROUTE_ADDED=true
            log_ok "Direct route to echo server added"
            return 0
        fi
    fi

    log_info "Using gateway: $GATEWAY_IP"

    # Add specific route for echo server (needs sudo)
    sudo ip route add "$ECHO_SERVER_IP/32" via "$GATEWAY_IP" dev "$INTERFACE" 2>/dev/null || {
        # Check if it was added anyway
        if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
            log_ok "Route already exists"
            ECHO_ROUTE_ADDED=false
            return 0
        fi
        die "Failed to add route to echo server"
    }

    ECHO_ROUTE_ADDED=true
    log_ok "Route to echo server added via $GATEWAY_IP"

    # Verify route
    log_info "Verifying route:"
    ip route show "$ECHO_SERVER_IP" 2>/dev/null || true
}

# Sync CPU clock to NIC PHC (required for accurate timestamp comparison)
sync_nic_clock() {
    log_info "Syncing CPU clock to NIC PHC..."

    # Find PHC device for this interface
    local phc_device=""
    for ptp in /sys/class/ptp/ptp*; do
        if [[ -d "$ptp/device/net" ]]; then
            local ptp_iface=$(ls "$ptp/device/net/" 2>/dev/null | head -n 1)
            if [[ "$ptp_iface" == "$INTERFACE" ]]; then
                local ptp_num=$(basename "$ptp" | sed 's/ptp//')
                phc_device="/dev/ptp${ptp_num}"
                break
            fi
        fi
    done

    if [[ -z "$phc_device" ]]; then
        log_warn "Could not find PHC device for $INTERFACE. Clock sync skipped."
        return 0
    fi

    log_info "Found PHC device: $phc_device for $INTERFACE"

    # Check if nic_local_clock_sync.sh exists
    local sync_script="${PROJECT_DIR}/scripts/nic_local_clock_sync.sh"

    if [[ ! -x "$sync_script" ]]; then
        log_warn "Clock sync script not found: $sync_script"
        return 0
    fi

    # Start the clock sync daemon (CPU CLOCK_REALTIME → NIC PHC)
    # This ensures NIC timestamps are comparable to system time
    if sudo "$sync_script" start "$phc_device" 2>&1 | grep -q "started\|already"; then
        log_ok "NIC clock sync daemon started (CPU → $phc_device)"
    else
        log_warn "Failed to start NIC clock sync daemon"
        # Show status for debugging
        sudo "$sync_script" status "$phc_device" 2>&1 | head -10 || true
    fi

    # Wait a moment for sync to stabilize
    sleep 1

    # Show current sync status
    log_info "Clock sync status:"
    sudo "$sync_script" status "$phc_device" 2>&1 | grep -E "offset|Daemon" | head -5 || true
}

# Bring interface up if needed
ensure_interface_up() {
    log_info "Ensuring $INTERFACE is up..."

    LINK_STATE=$(ip link show "$INTERFACE" | grep -o 'state [A-Z]*' | awk '{print $2}')

    if [[ "$LINK_STATE" != "UP" ]]; then
        sudo ip link set "$INTERFACE" up
        sleep 1
    fi

    # Check link detected
    if command -v ethtool &>/dev/null; then
        LINK_DETECTED=$(sudo ethtool "$INTERFACE" 2>/dev/null | grep "Link detected" | awk '{print $3}')
        if [[ "$LINK_DETECTED" == "yes" ]]; then
            log_ok "Link detected on $INTERFACE"
        else
            log_warn "No link detected on $INTERFACE - check cable connection"
        fi
    fi

    log_ok "Interface $INTERFACE is up"
}

# Detach any existing XDP program from our interface only
cleanup_xdp() {
    log_info "Cleaning up existing XDP program on $INTERFACE..."

    # Only detach from our test interface (needs sudo)
    if ip link show "$INTERFACE" | grep -q "xdp"; then
        sudo ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
        log_ok "Detached existing XDP program"
    else
        log_info "No existing XDP program on $INTERFACE"
    fi
}

# Build BPF program if needed
build_bpf() {
    cd "$PROJECT_DIR"

    if [[ ! -f "$BPF_OBJ" ]]; then
        log_info "Building BPF program..."
        make bpf || die "Failed to build BPF program"
        log_ok "BPF program built"
    else
        log_ok "BPF program already exists: $BPF_OBJ"
    fi
}

# Build test binary if needed
build_test() {
    cd "$PROJECT_DIR"

    if [[ ! -f "$TEST_BIN" ]]; then
        log_info "Building XDP Poll test..."
        make "build-test-pipeline-xdp-poll" "XDP_INTERFACE=$INTERFACE" || die "Failed to build test"
        log_ok "Test binary built"
    else
        log_ok "Test binary already exists: $TEST_BIN"
    fi
}

# ============================================================================
# Cleanup Function
# ============================================================================

cleanup() {
    local exit_code=$?
    log_info "Cleaning up (exit code: $exit_code)..."

    cd "$PROJECT_DIR"

    # Stop safe-lock watchdog first
    stop_safe_lock

    # Revert interface to original state
    revert_interface_state

    # Verify connectivity still works
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        log_ok "External connectivity verified after cleanup"
    else
        log_warn "External connectivity check failed (VPN may block ICMP)"
    fi

    log_ok "Cleanup complete"
}

# ============================================================================
# Main
# ============================================================================

# Global for test process PID (used by safe-lock revert)
TEST_PID=""

main() {
    echo "========================================================"
    echo "  XDP Poll Segregated Test - Remote Echo Server"
    echo "========================================================"
    echo ""
    echo "Interface:   $INTERFACE"
    echo "Echo Server: $ECHO_SERVER_IP:$ECHO_SERVER_PORT"
    echo "Safe-lock:   ${SAFE_LOCK_TIMEOUT}s timeout"
    echo "BPF:         $BPF_OBJ"
    echo "Test:        $TEST_BIN"
    echo ""

    # Safety checks first
    check_sudo_access
    check_interface_safety
    check_connectivity

    # Check echo server is running FIRST (before any interface changes)
    echo ""
    echo "--- Echo Server Check ---"
    check_echo_server

    # Capture original state BEFORE any modifications
    snapshot_interface_state

    # Setup signal handlers
    trap cleanup EXIT
    trap handle_safe_lock_timeout USR1

    # Start safe-lock watchdog
    start_safe_lock

    # Setup
    echo ""
    echo "--- Setup ---"
    ensure_interface_up
    setup_echo_route
    cleanup_xdp
    sync_nic_clock
    build_bpf
    build_test

    # Final safety verification
    echo ""
    echo "--- Safety Verification ---"
    check_connectivity

    # Show current state
    echo ""
    echo "--- Interface State ---"
    ip addr show dev "$INTERFACE" | grep -E "inet |state "
    echo ""
    echo "--- Routes ---"
    ip route show dev "$INTERFACE" || echo "(no routes)"
    echo "--- Route to Echo Server ---"
    ip route show "$ECHO_SERVER_IP" || echo "(no route to echo server)"
    echo ""

    # Run test with timeout protection
    echo "--- Running Test (safe-lock: ${SAFE_LOCK_TIMEOUT}s) ---"
    echo ""
    cd "$PROJECT_DIR"

    # Run the test binary with sudo (needs root for XDP/AF_XDP)
    # Pass interface, BPF object, and echo server address
    sudo "./$TEST_BIN" "$INTERFACE" "$BPF_OBJ" "$ECHO_SERVER_IP" "$ECHO_SERVER_PORT" &
    TEST_PID=$!

    log_info "Test started (PID: $TEST_PID)"

    # Wait for test to complete
    wait $TEST_PID
    TEST_RESULT=$?
    TEST_PID=""

    echo ""
    if [[ $TEST_RESULT -eq 0 ]]; then
        log_ok "Test completed successfully"
    else
        log_error "Test failed with exit code $TEST_RESULT"
    fi

    # Stop safe-lock (test completed before timeout)
    stop_safe_lock

    # Cleanup is automatic via trap
    exit $TEST_RESULT
}

# Run main
main "$@"
