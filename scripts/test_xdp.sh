#!/bin/bash
# scripts/test_xdp.sh
# XDP Test Wrapper - Safely prepare AF_XDP environment, run test, cleanup
#
# SAFETY REQUIREMENTS:
# - Uses dedicated test interface ONLY (default: enp108s0)
# - NEVER modifies default route or other interfaces
# - ProtonVPN and other interfaces remain untouched
# - 3-minute watchdog timeout to auto-cleanup on hang
# - AF_XDP zero-copy mode with device-bound BPF
#
# Usage: ./scripts/test_xdp.sh [OPTIONS] <test_source|selftest> [test_args...]
#
# Commands:
#   selftest              Run self-test to verify XDP environment
#   <test_source>         Test source file from test/pipeline/
#
# Options:
#   -i, --interface IFACE   Network interface (default: enp108s0)
#   -t, --timeout SECS      Watchdog timeout (default: 180 = 3 minutes)
#   --reload                Reload NIC driver before setup
#   --skip-clock-sync       Skip NIC clock synchronization
#   -h, --help              Show help
#
# Examples:
#   ./scripts/test_xdp.sh selftest
#   ./scripts/test_xdp.sh 00_xdp_poll.cpp
#   ./scripts/test_xdp.sh test/pipeline/01_xdp_poll_tcp.cpp
#   ./scripts/test_xdp.sh -i enp108s0 -t 120 00_xdp_poll.cpp arg1 arg2
#
# NOTE: Do NOT run this script with sudo. It uses sudo internally where needed.

set -e

# ============================================================================
# Configuration
# ============================================================================

INTERFACE="enp108s0"
TIMEOUT=180  # 3 minutes default
RELOAD_DRIVER=false
SKIP_CLOCK_SYNC=false
TEST_SOURCE=""
TEST_ARGS=()

# Echo server configuration
ECHO_SERVER_IP="139.162.79.171"
ECHO_SERVER_PORT="12345"

# Paths
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BPFTOOL_PATH="$HOME/Proj/bpftool/linux-6.14/tools/bpf/bpftool/bpftool"
BPF_OBJ="src/xdp/bpf/exchange_filter.bpf.o"

# State
ECHO_ROUTE_ADDED=false
GATEWAY_IP=""
WATCHDOG_PID=""
TEST_PID=""
ORIGINAL_QUEUES=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# Logging Functions
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
# Usage
# ============================================================================

usage() {
    cat <<EOF
XDP Test Wrapper - Safely prepare AF_XDP environment, run test, cleanup

Usage: $0 [OPTIONS] <test_source|selftest> [test_args...]

Commands:
  selftest              Run self-test to verify XDP environment
  <test_source>         Test source file from test/pipeline/
                        Can be filename only (00_xdp_poll.cpp) or full path

Options:
  -i, --interface IFACE   Network interface (default: enp108s0)
  -t, --timeout SECS      Watchdog timeout (default: 180 = 3 minutes)
  --reload                Reload NIC driver before setup
  --skip-clock-sync       Skip NIC clock synchronization
  -h, --help              Show help

Examples:
  $0 selftest
  $0 selftest -i enp108s0
  $0 00_xdp_poll.cpp
  $0 test/pipeline/01_xdp_poll_tcp.cpp
  $0 -i enp108s0 -t 120 00_xdp_poll.cpp arg1 arg2

NOTE: Do NOT run this script with sudo. It uses sudo internally where needed.

Protected Interfaces (never modified):
  - lo, proton*, ipv6leak*, zt* (VPN/ZeroTier)
  - Default route interface

EOF
    exit 0
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --reload)
                RELOAD_DRIVER=true
                shift
                ;;
            --skip-clock-sync)
                SKIP_CLOCK_SYNC=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                # First non-option is test source
                if [[ -z "$TEST_SOURCE" ]]; then
                    TEST_SOURCE="$1"
                else
                    # Rest are test args
                    TEST_ARGS+=("$1")
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$TEST_SOURCE" ]]; then
        log_error "No test source specified"
        echo ""
        usage
    fi
}

# ============================================================================
# Safety Functions
# ============================================================================

# MUST NOT run as root
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        die "Do NOT run this script as root. Run as normal user - script uses sudo internally."
    fi
}

# Verify sudo access
check_sudo_access() {
    if ! sudo -n true 2>/dev/null; then
        log_info "Sudo access required. Please authenticate:"
        sudo true || die "Sudo access required"
    fi
    log_ok "Sudo access verified"
}

# Check if interface is protected
is_protected_interface() {
    local iface="$1"
    case "$iface" in
        lo|proton*|ipv6leak*|zt*)
            return 0  # Protected
            ;;
        *)
            return 1  # Not protected
            ;;
    esac
}

# Verify interface is safe to use
verify_safe_interface() {
    local iface="$1"

    # Check interface exists
    if ! ip link show "$iface" &>/dev/null; then
        die "Interface $iface does not exist"
    fi

    # Check not protected
    if is_protected_interface "$iface"; then
        die "Cannot use protected interface: $iface"
    fi

    # Check not default route
    local default_iface
    default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)

    if [[ -n "$default_iface" ]]; then
        if [[ "$iface" == "$default_iface" ]]; then
            die "SAFETY VIOLATION: Cannot use default route interface $iface for testing!"
        fi
        log_info "Default route interface: $default_iface (protected)"
    else
        log_warn "No default route found (VPN may be handling routing)"
    fi

    log_ok "Interface $iface is safe to use"
}

# Check AWS EC2 environment
is_aws_ec2() {
    # Check for EC2 hypervisor or metadata
    if [[ -f /sys/hypervisor/uuid ]]; then
        local uuid
        uuid=$(cat /sys/hypervisor/uuid 2>/dev/null || echo "")
        if [[ "$uuid" == ec2* ]]; then
            return 0
        fi
    fi

    # Check for EC2 metadata service
    if timeout 1 curl -s http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        return 0
    fi

    return 1
}

# Check if NIC driver supports XDP
is_xdp_driver() {
    local driver="$1"
    case "$driver" in
        igc|i40e|ixgbe|mlx5_core|ice|bnxt_en|ena|virtio_net)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ============================================================================
# Watchdog Functions
# ============================================================================

# Watchdog uses a named pipe to receive notification when test completes
WATCHDOG_PIPE=""

# Watchdog process - monitors for timeout or completion signal
watchdog_process() {
    local timeout=$1
    local main_pid=$2
    local interface=$3
    local pipe=$4

    # Wait for either timeout or signal via pipe
    # read will return when: pipe is written to, pipe is closed, or timeout
    if read -t "$timeout" <"$pipe" 2>/dev/null; then
        # Received completion signal - exit cleanly
        exit 0
    fi

    # Timeout reached - check if main script is still running
    if kill -0 "$main_pid" 2>/dev/null; then
        echo ""
        echo -e "${RED}============================================${NC}"
        echo -e "${RED}  WATCHDOG TIMEOUT (${timeout}s) TRIGGERED${NC}"
        echo -e "${RED}  Forcing cleanup and termination...${NC}"
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

        # Force cleanup XDP
        sudo ip link set "$interface" xdp off 2>/dev/null || true
    fi
}

start_watchdog() {
    log_info "Starting watchdog (timeout: ${TIMEOUT}s)..."

    # Create named pipe for signaling
    WATCHDOG_PIPE="/tmp/xdp_watchdog_$$"
    mkfifo "$WATCHDOG_PIPE" 2>/dev/null || true

    watchdog_process "$TIMEOUT" $$ "$INTERFACE" "$WATCHDOG_PIPE" &
    WATCHDOG_PID=$!
    log_ok "Watchdog active (PID: $WATCHDOG_PID)"
}

stop_watchdog() {
    if [[ -n "$WATCHDOG_PID" ]] && kill -0 "$WATCHDOG_PID" 2>/dev/null; then
        # Signal watchdog to exit via pipe
        echo "done" > "$WATCHDOG_PIPE" 2>/dev/null || true
        # Wait briefly for clean exit
        sleep 0.1
        # Force kill if still running
        kill -KILL "$WATCHDOG_PID" 2>/dev/null || true
        log_ok "Watchdog stopped"
    fi
    WATCHDOG_PID=""

    # Cleanup pipe
    if [[ -n "$WATCHDOG_PIPE" ]]; then
        rm -f "$WATCHDOG_PIPE" 2>/dev/null || true
        WATCHDOG_PIPE=""
    fi
}

# Handle SIGUSR1 (triggered by watchdog timeout)
handle_watchdog_timeout() {
    log_error "Watchdog timeout handler triggered!"
    cleanup
    exit 124  # Standard timeout exit code
}

# ============================================================================
# Selftest Functions
# ============================================================================

selftest_check() {
    local description="$1"
    local command="$2"

    printf "  %-50s " "$description"
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}[PASS]${NC}"
        return 0
    else
        echo -e "${RED}[FAIL]${NC}"
        return 1
    fi
}

run_selftest() {
    local passed=0
    local failed=0

    echo ""
    echo "========================================"
    echo "  XDP Environment Self-Test"
    echo "  Interface: $INTERFACE"
    echo "========================================"
    echo ""

    # Helper to track results
    run_check() {
        if selftest_check "$1" "$2"; then
            ((passed++)) || true
        else
            ((failed++)) || true
        fi
    }

    echo "--- Basic Checks ---"
    run_check "Interface $INTERFACE exists" "ip link show $INTERFACE"
    run_check "Interface is not protected" "! is_protected_interface $INTERFACE"
    run_check "Sudo access available" "sudo -n true"

    echo ""
    echo "--- Tool Checks ---"
    run_check "Custom bpftool exists" "test -x '$BPFTOOL_PATH'"

    if [[ -x "$BPFTOOL_PATH" ]]; then
        local bpf_version
        bpf_version=$("$BPFTOOL_PATH" version 2>/dev/null | head -1 || echo "unknown")
        echo "        bpftool version: $bpf_version"
    fi

    run_check "ethtool available" "command -v ethtool"
    run_check "phc2sys available (linuxptp)" "command -v phc2sys"

    echo ""
    echo "--- BPF Program ---"
    # Always rebuild BPF to ensure it's up-to-date
    echo "        Rebuilding BPF program..."
    if (cd "$PROJECT_DIR" && make bpf USE_XDP=1 XDP_INTERFACE="$INTERFACE") &>/dev/null; then
        printf "  %-50s ${GREEN}[PASS]${NC}\n" "Rebuild BPF program"
        ((passed++)) || true
    else
        printf "  %-50s ${RED}[FAIL]${NC}\n" "Rebuild BPF program"
        ((failed++)) || true
    fi
    run_check "BPF object exists" "test -f '$PROJECT_DIR/$BPF_OBJ'"

    echo ""
    echo "--- NIC Capabilities ---"
    local driver
    driver=$(ethtool -i "$INTERFACE" 2>/dev/null | grep "driver:" | awk '{print $2}')
    echo "        NIC driver: $driver"
    run_check "NIC driver supports XDP" "is_xdp_driver '$driver'"
    run_check "NIC supports HW timestamps" "ethtool -T $INTERFACE 2>/dev/null | grep -q 'hardware-'"

    echo ""
    echo "--- Network ---"
    run_check "Echo server reachable" "timeout 3 nc -zv $ECHO_SERVER_IP $ECHO_SERVER_PORT 2>&1"

    echo ""
    echo "--- XDP Attach/Detach Cycle Test ---"

    # Save original queue count
    ORIGINAL_QUEUES=$(ethtool -l "$INTERFACE" 2>/dev/null | grep -A 5 "Current hardware settings" | grep "Combined:" | awk '{print $2}')
    echo "        Original queue count: $ORIGINAL_QUEUES"

    run_check "Set NIC to 1 queue" "sudo ethtool -L $INTERFACE combined 1"

    # Create temp directory for BPF pin
    local bpf_pin_dir="/sys/fs/bpf/selftest_$$"
    sudo mkdir -p "$bpf_pin_dir" 2>/dev/null || true

    # Attach XDP program using bpftool with xdpmeta_dev for device-bound mode
    # This is required for BPF programs that use metadata kfuncs like bpf_xdp_metadata_rx_timestamp
    local attach_cmd="sudo '$BPFTOOL_PATH' prog load '$PROJECT_DIR/$BPF_OBJ' '$bpf_pin_dir/xdp_prog' type xdp xdpmeta_dev $INTERFACE"
    if selftest_check "Load XDP program (device-bound)" "$attach_cmd"; then
        ((passed++)) || true

        # Get program ID and attach to interface
        local prog_id
        prog_id=$(sudo "$BPFTOOL_PATH" prog show pinned "$bpf_pin_dir/xdp_prog" 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')

        if [[ -n "$prog_id" ]]; then
            if selftest_check "Attach XDP to $INTERFACE" "sudo '$BPFTOOL_PATH' net attach xdp id $prog_id dev $INTERFACE"; then
                ((passed++)) || true

                echo "        Waiting 3 seconds with XDP attached..."
                sleep 3

                run_check "Verify XDP attached" "ip link show $INTERFACE | grep -q xdp"
                run_check "Detach XDP program" "sudo '$BPFTOOL_PATH' net detach xdp dev $INTERFACE"
                run_check "Verify XDP detached" "! ip link show $INTERFACE 2>/dev/null | grep -q 'xdp '"
            else
                ((failed++)) || true
            fi
        else
            log_warn "Could not get program ID"
            ((failed++)) || true
        fi

        # Cleanup pinned program
        sudo rm -f "$bpf_pin_dir/xdp_prog" 2>/dev/null || true
        sudo rmdir "$bpf_pin_dir" 2>/dev/null || true
    else
        ((failed++)) || true
        log_warn "XDP load failed - skipping attach/detach verification"
        sudo rmdir "$bpf_pin_dir" 2>/dev/null || true
    fi

    # Restore original queue count
    if [[ -n "$ORIGINAL_QUEUES" && "$ORIGINAL_QUEUES" != "1" ]]; then
        echo "        Restoring queue count to $ORIGINAL_QUEUES"
        sudo ethtool -L "$INTERFACE" combined "$ORIGINAL_QUEUES" 2>/dev/null || true
    fi

    echo ""
    echo "========================================"
    echo "  Results: $passed passed, $failed failed"
    echo "========================================"
    echo ""

    if [[ $failed -eq 0 ]]; then
        log_ok "All self-tests passed!"
        return 0
    else
        log_error "$failed self-test(s) failed"
        return 1
    fi
}

# ============================================================================
# Test Binary Functions
# ============================================================================

# Map test source to binary name and make target
map_test_source() {
    local source="$1"

    # Extract just the filename if full path given
    local filename
    filename=$(basename "$source")

    # Remove .cpp extension
    local base="${filename%.cpp}"

    # Map to binary name and make target
    case "$base" in
        00_xdp_poll)
            TEST_BIN="build/test_pipeline_xdp_poll"
            MAKE_TARGET="build-test-pipeline-xdp-poll"
            ;;
        01_xdp_poll_tcp)
            TEST_BIN="build/test_pipeline_xdp_poll_tcp"
            MAKE_TARGET="build-test-pipeline-xdp-poll-tcp"
            ;;
        *)
            # Generic pattern: NN_name.cpp -> test_pipeline_name
            local name="${base#*_}"  # Remove NN_ prefix
            TEST_BIN="build/test_pipeline_${name}"
            MAKE_TARGET="build-test-pipeline-${name}"
            ;;
    esac

    log_info "Test source: $filename"
    log_info "Test binary: $TEST_BIN"
    log_info "Make target: $MAKE_TARGET"
}

# Build test if needed
build_test() {
    cd "$PROJECT_DIR"

    if [[ -f "$TEST_BIN" ]]; then
        log_ok "Test binary exists: $TEST_BIN"
        return 0
    fi

    log_info "Building test: $MAKE_TARGET"

    # Build BPF first if needed
    if [[ ! -f "$BPF_OBJ" ]]; then
        log_info "Building BPF program first..."
        make bpf USE_XDP=1 || die "Failed to build BPF program"
    fi

    # Build test binary (as normal user, no sudo)
    make "$MAKE_TARGET" USE_XDP=1 || die "Failed to build test: $MAKE_TARGET"

    log_ok "Test binary built: $TEST_BIN"
}

# ============================================================================
# Setup Functions
# ============================================================================

setup_environment() {
    # Add custom bpftool to PATH
    export PATH="$(dirname "$BPFTOOL_PATH"):$PATH"
    log_info "Added custom bpftool to PATH"
}

get_gateway() {
    # Get gateway for the interface
    GATEWAY_IP=$(ip route show dev "$INTERFACE" 2>/dev/null | grep -E "^default|via" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)

    if [[ -z "$GATEWAY_IP" ]]; then
        # Try to find gateway from interface subnet
        local subnet
        subnet=$(ip route show dev "$INTERFACE" 2>/dev/null | grep -v "^default" | awk '{print $1}' | head -1)
        if [[ -n "$subnet" ]]; then
            # Use first IP in subnet as gateway (common pattern)
            GATEWAY_IP=$(echo "$subnet" | sed 's|/.*||' | sed 's/\.[0-9]*$/.1/')
        fi
    fi

    if [[ -z "$GATEWAY_IP" ]]; then
        log_warn "Could not determine gateway for $INTERFACE"
        return 1
    fi

    log_info "Gateway: $GATEWAY_IP"
    return 0
}

setup_echo_route() {
    log_info "Setting up route to echo server via $INTERFACE..."

    # Check if route already exists
    if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
        log_ok "Route to echo server already exists"
        ECHO_ROUTE_ADDED=false
        return 0
    fi

    if ! get_gateway; then
        log_warn "Skipping route setup (no gateway)"
        return 0
    fi

    # Add route with high metric (low priority)
    if sudo ip route add "$ECHO_SERVER_IP/32" via "$GATEWAY_IP" dev "$INTERFACE" metric 9999 2>/dev/null; then
        ECHO_ROUTE_ADDED=true
        log_ok "Route to echo server added via $GATEWAY_IP (metric 9999)"
    else
        # Check if it was added anyway
        if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
            log_ok "Route already exists"
            ECHO_ROUTE_ADDED=false
        else
            log_warn "Could not add route to echo server"
        fi
    fi
}

run_xdp_prepare() {
    log_info "Running XDP preparation..."

    local prepare_script="$PROJECT_DIR/scripts/xdp_prepare.sh"

    if [[ ! -x "$prepare_script" ]]; then
        die "XDP prepare script not found: $prepare_script"
    fi

    local args=()
    if [[ "$RELOAD_DRIVER" == "true" ]]; then
        args+=("--reload")
    fi
    args+=("$INTERFACE")

    sudo "$prepare_script" "${args[@]}" || die "XDP preparation failed"

    log_ok "XDP preparation complete"
}

run_clock_sync() {
    if [[ "$SKIP_CLOCK_SYNC" == "true" ]]; then
        log_info "Skipping clock sync (--skip-clock-sync)"
        return 0
    fi

    if is_aws_ec2; then
        log_info "Skipping clock sync (AWS EC2 detected)"
        return 0
    fi

    local sync_script="$PROJECT_DIR/scripts/nic_local_clock_sync.sh"

    if [[ ! -x "$sync_script" ]]; then
        log_warn "Clock sync script not found: $sync_script"
        return 0
    fi

    # Find PHC device for interface
    local phc_device=""
    for ptp in /sys/class/ptp/ptp*; do
        if [[ -d "$ptp/device/net" ]]; then
            local ptp_iface
            ptp_iface=$(ls "$ptp/device/net/" 2>/dev/null | head -n 1)
            if [[ "$ptp_iface" == "$INTERFACE" ]]; then
                local ptp_num
                ptp_num=$(basename "$ptp" | sed 's/ptp//')
                phc_device="/dev/ptp${ptp_num}"
                break
            fi
        fi
    done

    if [[ -z "$phc_device" ]]; then
        log_warn "Could not find PHC device for $INTERFACE"
        return 0
    fi

    log_info "Starting clock sync (CPU -> $phc_device)..."
    sudo "$sync_script" start "$phc_device" 2>&1 | head -5 || true
}

set_capabilities() {
    log_info "Setting capabilities on test binary..."

    # Required capabilities for AF_XDP/BPF operations
    local caps="cap_net_admin,cap_net_raw,cap_bpf,cap_perfmon,cap_ipc_lock,cap_sys_nice+ep"

    sudo setcap "$caps" "$PROJECT_DIR/$TEST_BIN" || die "Failed to set capabilities"

    log_ok "Capabilities set: $caps"
}

prepare_shm() {
    log_info "Preparing shared memory directory..."
    sudo mkdir -p /dev/shm/hft
    sudo chown "$(id -u):$(id -g)" /dev/shm/hft
    sudo chmod 755 /dev/shm/hft
    log_ok "Shared memory directory: /dev/shm/hft"
}

# ============================================================================
# Cleanup Function
# ============================================================================

cleanup() {
    local exit_code=$?
    log_info "Cleaning up (exit code: $exit_code)..."

    cd "$PROJECT_DIR" 2>/dev/null || true

    # Stop watchdog first
    stop_watchdog

    # Kill test process if still running
    if [[ -n "$TEST_PID" ]] && kill -0 "$TEST_PID" 2>/dev/null; then
        log_warn "Killing test process (PID $TEST_PID)..."
        kill -TERM "$TEST_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$TEST_PID" 2>/dev/null || true
    fi

    # Detach XDP program
    if ip link show "$INTERFACE" 2>/dev/null | grep -q "xdp"; then
        log_info "Detaching XDP program..."
        sudo ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
    fi

    # Remove echo server route if we added it
    if [[ "$ECHO_ROUTE_ADDED" == "true" ]]; then
        if ip route show "$ECHO_SERVER_IP" 2>/dev/null | grep -q "$INTERFACE"; then
            log_info "Removing route to $ECHO_SERVER_IP..."
            sudo ip route del "$ECHO_SERVER_IP" dev "$INTERFACE" 2>/dev/null || true
        fi
    fi

    # Verify connectivity
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        log_ok "External connectivity verified"
    else
        log_warn "External connectivity check failed (VPN may block ICMP)"
    fi

    log_ok "Cleanup complete"
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    parse_args "$@"

    # Safety: must not run as root
    check_not_root

    # Check sudo access
    check_sudo_access

    # Change to project directory
    cd "$PROJECT_DIR"

    # Setup environment (PATH with custom bpftool)
    setup_environment

    # Handle selftest
    if [[ "$TEST_SOURCE" == "selftest" ]]; then
        verify_safe_interface "$INTERFACE"
        run_selftest
        exit $?
    fi

    # Verify interface is safe
    verify_safe_interface "$INTERFACE"

    # Map test source to binary
    map_test_source "$TEST_SOURCE"

    # Setup signal handlers
    trap cleanup EXIT
    trap handle_watchdog_timeout USR1

    # Start watchdog
    start_watchdog

    echo ""
    echo "========================================"
    echo "  XDP Test Runner"
    echo "========================================"
    echo ""
    echo "  Interface:   $INTERFACE"
    echo "  Test:        $TEST_BIN"
    echo "  Timeout:     ${TIMEOUT}s"
    echo "  Echo Server: $ECHO_SERVER_IP:$ECHO_SERVER_PORT"
    echo ""

    # Setup phase
    echo "--- Setup ---"
    run_xdp_prepare
    run_clock_sync
    setup_echo_route
    build_test
    set_capabilities
    prepare_shm

    # Final safety check
    echo ""
    echo "--- Safety Verification ---"
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        log_ok "External connectivity OK"
    else
        log_warn "Cannot reach 1.1.1.1 (VPN may block ICMP)"
    fi

    # Show current state
    echo ""
    echo "--- Interface State ---"
    ip addr show dev "$INTERFACE" 2>/dev/null | grep -E "inet |state " || true
    echo ""
    echo "--- Route to Echo Server ---"
    ip route show "$ECHO_SERVER_IP" 2>/dev/null || echo "(no route)"
    echo ""

    # Run test
    echo "--- Running Test (timeout: ${TIMEOUT}s) ---"
    echo ""

    # Run test binary as normal user (with capabilities)
    "./$TEST_BIN" "$INTERFACE" "$BPF_OBJ" "$ECHO_SERVER_IP" "$ECHO_SERVER_PORT" "${TEST_ARGS[@]}" &
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

    # Stop watchdog (test completed before timeout)
    stop_watchdog

    # Cleanup via trap
    exit $TEST_RESULT
}

# Run main
main "$@"
