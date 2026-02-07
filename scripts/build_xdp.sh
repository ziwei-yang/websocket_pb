#!/bin/bash
# scripts/build_xdp.sh
# XDP Build & Prepare - Build test binary and prepare AF_XDP environment
#
# This script builds the test binary and prepares the XDP environment
# WITHOUT running the test. Use this when you want to run the test manually
# or with custom arguments.
#
# SAFETY REQUIREMENTS:
# - Uses dedicated test interface ONLY (default: enp108s0)
# - NEVER modifies default route or other interfaces
# - ProtonVPN and other interfaces remain untouched
#
# Usage: ./scripts/build_xdp.sh [OPTIONS] <test_source>
#
# Options:
#   -i, --interface IFACE   Network interface (default: enp108s0)
#   --reload                Reload NIC driver before setup
#   --skip-clock-sync       Skip NIC clock synchronization
#   -h, --help              Show help
#
# Examples:
#   ./scripts/build_xdp.sh 20_websocket_binance.cpp
#   ./scripts/build_xdp.sh xdp_binance.cpp
#   ./scripts/build_xdp.sh -i enp108s0 00_xdp_poll.cpp
#
# After running this script, you can run the test manually:
#   ./build/test_pipeline_websocket_binance enp108s0 src/xdp/bpf/exchange_filter.bpf.o --timeout -1
#
# NOTE: Do NOT run this script with sudo. It uses sudo internally where needed.

set -e

# ============================================================================
# Configuration
# ============================================================================

INTERFACE="enp108s0"
RELOAD_DRIVER=false
SKIP_CLOCK_SYNC=false
ENABLE_AB_FLAG=false
TEST_SOURCE=""

# Paths
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BPFTOOL_PATH="$HOME/Proj/bpftool/linux-6.14/tools/bpf/bpftool/bpftool"
BPF_OBJ="src/xdp/bpf/exchange_filter.bpf.o"

# State
GATEWAY_IP=""

# Original interface settings (saved before xdp_prepare modifies them)
ORIGINAL_QUEUES=""
ORIGINAL_GRO=""
ORIGINAL_LRO=""
ORIGINAL_RX_USECS=""
ORIGINAL_TX_USECS=""

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
XDP Build & Prepare - Build test binary and prepare AF_XDP environment

Usage: $0 [OPTIONS] <test_source>

Options:
  -i, --interface IFACE   Network interface (default: enp108s0)
  --enable-ab             Enable dual A/B connection mode (-DENABLE_AB)
  --reload                Reload NIC driver before setup
  --skip-clock-sync       Skip NIC clock synchronization
  -h, --help              Show help

Examples:
  $0 20_websocket_binance.cpp
  $0 --enable-ab 20_websocket_binance.cpp
  $0 -i enp108s0 00_xdp_poll.cpp

After running this script, you can run the test manually:
  ./build/test_pipeline_websocket_binance enp108s0 src/xdp/bpf/exchange_filter.bpf.o --timeout -1

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
            --enable-ab)
                ENABLE_AB_FLAG=true
                shift
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

# ============================================================================
# Interface Settings Functions
# ============================================================================

# Save original interface settings before xdp_prepare modifies them
save_interface_settings() {
    log_info "Saving original interface settings for $INTERFACE..."

    # Save queue count
    ORIGINAL_QUEUES=$(ethtool -l "$INTERFACE" 2>/dev/null | grep -A 5 "Current hardware settings" | grep "Combined:" | awk '{print $2}')

    # Save GRO/LRO state
    ORIGINAL_GRO=$(ethtool -k "$INTERFACE" 2>/dev/null | grep "generic-receive-offload:" | awk '{print $2}')
    ORIGINAL_LRO=$(ethtool -k "$INTERFACE" 2>/dev/null | grep "large-receive-offload:" | awk '{print $2}')

    # Save coalescing
    ORIGINAL_RX_USECS=$(ethtool -c "$INTERFACE" 2>/dev/null | grep "^rx-usecs:" | awk '{print $2}')
    ORIGINAL_TX_USECS=$(ethtool -c "$INTERFACE" 2>/dev/null | grep "^tx-usecs:" | awk '{print $2}')

    log_ok "Saved: queues=$ORIGINAL_QUEUES, gro=$ORIGINAL_GRO, lro=$ORIGINAL_LRO, rx-usecs=$ORIGINAL_RX_USECS, tx-usecs=$ORIGINAL_TX_USECS"
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

    # Remove .cpp extension for matching
    local base="${filename%.cpp}"

    # Resolve actual source file in test/pipeline/ (exact match or prefix glob)
    local search_dir="$PROJECT_DIR/test/pipeline"
    if [[ -f "$search_dir/$filename" ]]; then
        : # exact match, use as-is
    else
        # Try prefix glob: e.g. "98_websocket_binance.cpp" -> "98_websocket_binance_*.cpp"
        local matches
        matches=$(cd "$search_dir" && ls ${base}*.cpp 2>/dev/null || true)
        local count
        count=$(echo "$matches" | wc -w)
        if [[ $count -eq 1 ]]; then
            filename="$matches"
            base="${filename%.cpp}"
        elif [[ $count -gt 1 ]]; then
            log_error "Multiple files match '$source': $matches"
            exit 1
        fi
        # If count == 0, fall through to case (may be a non-pipeline target like xdp_binance)
    fi

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
        02_xdp_packetio_tcp)
            TEST_BIN="build/test_pipeline_02_xdp_packetio_tcp"
            MAKE_TARGET="build-test-pipeline-02_xdp_packetio_tcp"
            ;;
        03_disruptor_packetio_tcp)
            TEST_BIN="build/test_pipeline_03_disruptor_packetio_tcp"
            MAKE_TARGET="build-test-pipeline-03_disruptor_packetio_tcp"
            ;;
        00_xdp_poll_ping)
            TEST_BIN="build/test_pipeline_xdp_poll_ping"
            MAKE_TARGET="build-test-pipeline-xdp-poll-ping"
            ;;
        10_transport_tcp)
            TEST_BIN="build/test_pipeline_transport_tcp"
            MAKE_TARGET="build-test-pipeline-transport-tcp"
            ;;
        11_transport_http)
            TEST_BIN="build/test_pipeline_transport_http"
            MAKE_TARGET="build-test-pipeline-transport-http"
            ;;
        xdp_binance)
            TEST_BIN="build/test_xdp_binance_integration"
            MAKE_TARGET="build/test_xdp_binance_integration"
            ;;
        xdp_okx)
            TEST_BIN="build/test_xdp_okx_integration"
            MAKE_TARGET="build/test_xdp_okx_integration"
            ;;
        99_websocket_binance_1_proc|99_websocket_binance)
            TEST_BIN="build/test_pipeline_99_websocket_binance"
            MAKE_TARGET="build-test-pipeline-unified_binance"
            ;;
        98_websocket_binance_piotransport_ws|98_websocket_binance)
            TEST_BIN="build/test_pipeline_98_websocket_binance"
            MAKE_TARGET="build-test-pipeline-98_websocket_binance"
            ;;
        96_websocket_binance_xdp_piotransport_ws|96_websocket_binance)
            TEST_BIN="build/test_pipeline_96_websocket_binance"
            MAKE_TARGET="build-test-pipeline-96_websocket_binance"
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

# Build test (always rebuild to ensure latest code)
build_test() {
    cd "$PROJECT_DIR"

    log_info "Building test: $MAKE_TARGET"

    # Determine SSL library flags based on test name or USE_WOLFSSL env var
    local SSL_FLAGS=""
    if [[ -n "$USE_WOLFSSL" ]] || [[ "$MAKE_TARGET" == *"wolfssl"* ]]; then
        SSL_FLAGS="USE_WOLFSSL=1"
        log_info "Using WolfSSL (USE_WOLFSSL=1)"
    elif [[ "$MAKE_TARGET" == *"libressl"* ]]; then
        SSL_FLAGS="USE_LIBRESSL=1"
        log_info "Detected LibreSSL test, adding USE_LIBRESSL=1"
    elif [[ -n "$USE_OPENSSL" ]] || [[ "$MAKE_TARGET" == *"wss"* ]] || [[ "$MAKE_TARGET" == *"binance"* ]] || [[ "$MAKE_TARGET" == *"okx"* ]] || [[ "$MAKE_TARGET" == *"openssl"* ]]; then
        SSL_FLAGS="USE_OPENSSL=1"
        log_info "Using OpenSSL (USE_OPENSSL=1)"
    else
        # Default to OpenSSL for tests that include ssl.hpp (e.g. NoSSLPolicy tests)
        SSL_FLAGS="USE_OPENSSL=1"
        log_info "Defaulting to OpenSSL (USE_OPENSSL=1)"
    fi

    # Build BPF first if needed
    if [[ ! -f "$BPF_OBJ" ]]; then
        log_info "Building BPF program first..."
        make bpf USE_XDP=1 XDP_INTERFACE="$INTERFACE" || die "Failed to build BPF program"
    fi

    # Dual A/B connection mode (via --enable-ab flag or ENABLE_AB env var)
    local AB_FLAGS=""
    if [[ "$ENABLE_AB_FLAG" == "true" ]] || [[ -n "$ENABLE_AB" ]]; then
        AB_FLAGS="ENABLE_AB=1"
        log_info "Dual A/B connection mode enabled (ENABLE_AB=1)"
    fi

    # Remove existing binary to force rebuild (make doesn't track flag changes like ENABLE_AB)
    rm -f "$TEST_BIN"

    # Build test binary (as normal user, no sudo)
    make "$MAKE_TARGET" USE_XDP=1 XDP_INTERFACE="$INTERFACE" $SSL_FLAGS $AB_FLAGS || die "Failed to build test: $MAKE_TARGET"

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

    # Verify interface is safe
    verify_safe_interface "$INTERFACE"

    # Map test source to binary
    map_test_source "$TEST_SOURCE"

    echo ""
    echo "========================================"
    echo "  XDP Build & Prepare"
    echo "========================================"
    echo ""
    echo "  Interface:   $INTERFACE"
    echo "  Test:        $TEST_BIN"
    echo ""

    # Setup phase
    echo "--- Setup ---"

    # Build BPF first (as user, before sudo prepare)
    if [[ ! -f "$BPF_OBJ" ]]; then
        log_info "Building BPF program..."
        make bpf USE_XDP=1 XDP_INTERFACE="$INTERFACE" || die "Failed to build BPF program"
    fi

    # Save interface settings before xdp_prepare modifies them
    save_interface_settings

    run_xdp_prepare
    run_clock_sync

    build_test
    set_capabilities
    prepare_shm

    # Show current state
    echo ""
    echo "--- Interface State ---"
    ip addr show dev "$INTERFACE" 2>/dev/null | grep -E "inet |state " || true
    echo ""

    # Print run instructions
    echo ""
    echo "========================================"
    echo "  Build & Prepare Complete"
    echo "========================================"
    echo ""
    echo "To run the test manually:"
    echo ""
    echo "  ./$TEST_BIN $INTERFACE $BPF_OBJ [test_args...]"
    echo ""
    echo "Examples:"
    echo "  ./$TEST_BIN $INTERFACE $BPF_OBJ --timeout 5000"
    echo "  ./$TEST_BIN $INTERFACE $BPF_OBJ --timeout -1   # forever mode"
    echo ""
    log_ok "Ready to run test"
}

# Run main
main "$@"
