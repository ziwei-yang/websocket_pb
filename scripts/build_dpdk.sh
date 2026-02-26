#!/bin/bash
# scripts/build_dpdk.sh
# DPDK Build & Prepare - Bind NIC to vfio-pci, setup hugepages, build test binary
#
# DPDK equivalent of build_xdp.sh. Prepares the DPDK environment and builds
# the test binary WITHOUT running it.
#
# SAFETY REQUIREMENTS:
# - Uses dedicated test interface ONLY (default: enp108s0)
# - NEVER modifies default route or other interfaces
# - ProtonVPN and other interfaces remain untouched
#
# Usage: ./scripts/build_dpdk.sh [OPTIONS] <test_source>
#
# Options:
#   -i, --interface IFACE   Network interface (default: enp108s0)
#   --enable-ab             Enable dual A/B connection mode (-DENABLE_AB)
#   --enable-reconnect      Enable auto-reconnect mode (-DENABLE_RECONNECT)
#   --hugepages N           Number of 2MB hugepages to allocate (default: 512)
#   --skip-bind             Skip vfio-pci bind (assume already bound)
#   -h, --help              Show help
#
# Examples:
#   ./scripts/build_dpdk.sh 04_dpdk_poll_ping.cpp
#   ./scripts/build_dpdk.sh 30_binance_sbe_dpdk.cpp
#   ./scripts/build_dpdk.sh -i enp108s0 05_dpdk_disruptor_packetio_tcp.cpp
#
# After running this script, run the test as root:
#   sudo ./build/test_pipeline_30_binance_sbe_dpdk enp108s0 --timeout 10000
#
# NOTE: Do NOT run this script with sudo. It uses sudo internally where needed.

set -e

# ============================================================================
# Configuration
# ============================================================================

INTERFACE="enp108s0"
HUGEPAGES=512
ENABLE_AB_FLAG=false
ENABLE_RECONNECT_FLAG=false
SKIP_BIND=false
TEST_SOURCE=""

# Paths
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DPDK_BIND_SCRIPT="$PROJECT_DIR/scripts/dpdk_bind.sh"

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
DPDK Build & Prepare - Bind NIC to vfio-pci, setup hugepages, build test binary

Usage: $0 [OPTIONS] <test_source>

Options:
  -i, --interface IFACE   Network interface (default: enp108s0)
  --enable-ab             Enable dual A/B connection mode (-DENABLE_AB)
  --enable-reconnect      Enable auto-reconnect mode (-DENABLE_RECONNECT)
  --hugepages N           Number of 2MB hugepages to allocate (default: 512)
  --skip-bind             Skip vfio-pci bind (assume already bound)
  -h, --help              Show help

Examples:
  $0 04_dpdk_poll_ping.cpp
  $0 30_binance_sbe_dpdk.cpp
  $0 -i enp108s0 05_dpdk_disruptor_packetio_tcp.cpp

After running this script, run the test as root:
  sudo ./build/test_pipeline_30_binance_sbe_dpdk enp108s0 --timeout 10000

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
            --enable-reconnect)
                ENABLE_RECONNECT_FLAG=true
                shift
                ;;
            --hugepages)
                HUGEPAGES="$2"
                shift 2
                ;;
            --skip-bind)
                SKIP_BIND=true
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

# Verify interface is safe to use (check before it gets bound to vfio-pci)
verify_safe_interface() {
    local iface="$1"

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

    # Interface may or may not exist in sysfs (already bound to vfio-pci)
    if ip link show "$iface" &>/dev/null; then
        log_ok "Interface $iface is safe to use"
    elif [[ -f "/tmp/dpdk_pci_${iface}" ]]; then
        log_ok "Interface $iface already bound to vfio-pci (cached PCI: $(cat /tmp/dpdk_pci_${iface}))"
    else
        die "Interface $iface not found (not in sysfs and no cached PCI address)"
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

    # Remove .cpp extension for matching
    local base="${filename%.cpp}"

    # Resolve actual source file in test/pipeline/
    local search_dir="$PROJECT_DIR/test/pipeline"
    if [[ -f "$search_dir/$filename" ]]; then
        : # exact match
    else
        # Try prefix glob
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
    fi

    # Map known DPDK tests to their targets
    case "$base" in
        04_dpdk_poll_ping)
            TEST_BIN="build/test_pipeline_04_dpdk_poll_ping"
            MAKE_TARGET="build-test-pipeline-04_dpdk_poll_ping"
            ;;
        05_dpdk_disruptor_packetio_tcp)
            TEST_BIN="build/test_pipeline_05_dpdk_disruptor_packetio_tcp"
            MAKE_TARGET="build-test-pipeline-05_dpdk_disruptor_packetio_tcp"
            ;;
        30_binance_sbe_dpdk)
            TEST_BIN="build/test_pipeline_30_binance_sbe_dpdk"
            MAKE_TARGET="build-test-pipeline-30_binance_sbe_dpdk"
            ;;
        *)
            # Generic pattern: NN_name.cpp -> test_pipeline_NN_name
            TEST_BIN="build/test_pipeline_${base}"
            MAKE_TARGET="build-test-pipeline-${base}"
            ;;
    esac

    log_info "Test source: $filename"
    log_info "Test binary: $TEST_BIN"
    log_info "Make target: $MAKE_TARGET"
}

# Build test binary
build_test() {
    cd "$PROJECT_DIR"

    log_info "Building test: $MAKE_TARGET"

    # Determine SSL library flags
    local SSL_FLAGS=""
    if [[ -n "$USE_WOLFSSL" ]] || [[ "$MAKE_TARGET" == *"wolfssl"* ]]; then
        SSL_FLAGS="USE_WOLFSSL=1"
        log_info "Using WolfSSL (USE_WOLFSSL=1)"
    elif [[ -n "$USE_OPENSSL" ]] || [[ "$MAKE_TARGET" == *"binance"* ]] || [[ "$MAKE_TARGET" == *"okx"* ]] || [[ "$MAKE_TARGET" == *"wss"* ]] || [[ "$MAKE_TARGET" == *"openssl"* ]]; then
        SSL_FLAGS="USE_OPENSSL=1"
        log_info "Using OpenSSL (USE_OPENSSL=1)"
    fi
    # Some DPDK tests (04, 05) don't need SSL — SSL_FLAGS may be empty

    # Dual A/B connection mode
    local AB_FLAGS=""
    if [[ "$ENABLE_AB_FLAG" == "true" ]] || [[ -n "$ENABLE_AB" ]]; then
        AB_FLAGS="ENABLE_AB=1"
        log_info "Dual A/B connection mode enabled (ENABLE_AB=1)"
    fi

    # Auto-reconnect mode
    local RECONNECT_FLAGS=""
    if [[ "$ENABLE_RECONNECT_FLAG" == "true" ]] || [[ -n "$ENABLE_RECONNECT" ]]; then
        RECONNECT_FLAGS="ENABLE_RECONNECT=1"
        log_info "Auto-reconnect mode enabled (ENABLE_RECONNECT=1)"
    fi

    # Remove existing binary to force rebuild (make doesn't track flag changes)
    rm -f "$TEST_BIN"

    # Build test binary (as normal user, no sudo)
    make "$MAKE_TARGET" USE_DPDK=1 DPDK_INTERFACE="$INTERFACE" $SSL_FLAGS $AB_FLAGS $RECONNECT_FLAGS || die "Failed to build test: $MAKE_TARGET"

    log_ok "Test binary built: $TEST_BIN"
}

# ============================================================================
# DPDK Setup Functions
# ============================================================================

setup_hugepages() {
    local current
    current=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)

    if [[ "$current" -ge "$HUGEPAGES" ]]; then
        log_ok "Hugepages already sufficient: $current (requested $HUGEPAGES)"
    else
        log_info "Allocating $HUGEPAGES hugepages (current: $current)..."
        sudo sh -c "echo $HUGEPAGES > /proc/sys/vm/nr_hugepages"

        # Verify
        local actual
        actual=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
        if [[ "$actual" -lt "$HUGEPAGES" ]]; then
            log_warn "Only got $actual/$HUGEPAGES hugepages (memory fragmentation?)"
        else
            log_ok "Hugepages allocated: $actual"
        fi
    fi

    # Ensure /dev/hugepages is accessible by current user (DPDK EAL maps hugepages here)
    if [[ -d /dev/hugepages ]]; then
        sudo chmod 1777 /dev/hugepages
        log_ok "Hugepages dir /dev/hugepages: world-writable"
    fi
}

check_iommu() {
    if ! dmesg 2>/dev/null | grep -qi "iommu"; then
        log_warn "IOMMU may not be enabled. Check: dmesg | grep -i iommu"
        log_warn "Boot with intel_iommu=on iommu=pt (Intel) or amd_iommu=on (AMD)"
    else
        log_ok "IOMMU detected"
    fi
}

bind_vfio() {
    if [[ "$SKIP_BIND" == "true" ]]; then
        log_info "Skipping vfio-pci bind (--skip-bind)"
        return 0
    fi

    # Check if already bound to vfio-pci
    if [[ -f "/tmp/dpdk_pci_${INTERFACE}" ]]; then
        local cached_pci
        cached_pci=$(cat "/tmp/dpdk_pci_${INTERFACE}")
        local current_driver
        current_driver=$(basename "$(readlink "/sys/bus/pci/devices/$cached_pci/driver" 2>/dev/null)" 2>/dev/null || true)
        if [[ "$current_driver" == "vfio-pci" ]]; then
            log_ok "Interface $INTERFACE already bound to vfio-pci (PCI: $cached_pci)"
            return 0
        fi
    fi

    # Interface must exist in sysfs for initial bind
    if ! ip link show "$INTERFACE" &>/dev/null; then
        die "Interface $INTERFACE not found. Cannot bind to vfio-pci."
    fi

    log_info "Binding $INTERFACE to vfio-pci..."

    if [[ ! -x "$DPDK_BIND_SCRIPT" ]]; then
        die "DPDK bind script not found: $DPDK_BIND_SCRIPT"
    fi

    "$DPDK_BIND_SCRIPT" "$INTERFACE" || die "Failed to bind $INTERFACE to vfio-pci"

    log_ok "Interface $INTERFACE bound to vfio-pci"
}

verify_dpdk_cache() {
    log_info "Verifying DPDK cache files for $INTERFACE..."

    local missing=()
    for f in pci ip mac gw gw_mac; do
        if [[ ! -f "/tmp/dpdk_${f}_${INTERFACE}" ]]; then
            missing+=("$f")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing DPDK cache files: ${missing[*]}"
        log_warn "These are created by dpdk_bind.sh before NIC is bound to vfio-pci."
        log_warn "If NIC is already bound, unbind first, then re-bind:"
        log_warn "  $DPDK_BIND_SCRIPT $INTERFACE --unbind && $DPDK_BIND_SCRIPT $INTERFACE"
    else
        log_ok "DPDK cache: IP=$(cat /tmp/dpdk_ip_${INTERFACE}), MAC=$(cat /tmp/dpdk_mac_${INTERFACE}), GW=$(cat /tmp/dpdk_gw_${INTERFACE})"
    fi
}

set_capabilities() {
    log_info "Setting capabilities on test binary..."

    local caps="cap_ipc_lock,cap_net_admin,cap_net_raw,cap_sys_nice,cap_sys_rawio+ep"
    sudo setcap "$caps" "$PROJECT_DIR/$TEST_BIN" || die "Failed to set capabilities"
    log_ok "Capabilities set: $caps"
}

setup_vfio_permissions() {
    log_info "Setting VFIO device permissions..."

    # /dev/vfio/vfio and group devices must be accessible
    for dev in /dev/vfio/vfio /dev/vfio/*; do
        if [[ -e "$dev" ]]; then
            sudo chown "$(id -u):$(id -g)" "$dev" 2>/dev/null || true
        fi
    done
    log_ok "VFIO devices owned by $(id -un)"
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

    # Verify interface is safe
    verify_safe_interface "$INTERFACE"

    # Map test source to binary
    map_test_source "$TEST_SOURCE"

    echo ""
    echo "========================================"
    echo "  DPDK Build & Prepare"
    echo "========================================"
    echo ""
    echo "  Interface:   $INTERFACE"
    echo "  Hugepages:   $HUGEPAGES"
    echo "  Test:        $TEST_BIN"
    echo ""

    # Setup phase
    echo "--- Setup ---"

    check_iommu
    setup_hugepages
    bind_vfio
    verify_dpdk_cache
    build_test
    set_capabilities
    setup_vfio_permissions
    prepare_shm

    # Show DPDK status
    echo ""
    echo "--- DPDK Status ---"
    dpdk-devbind.py --status 2>/dev/null | head -20 || log_warn "dpdk-devbind.py not in PATH"
    echo ""

    # Print run instructions
    echo ""
    echo "========================================"
    echo "  Build & Prepare Complete"
    echo "========================================"
    echo ""
    echo "To run the test (capabilities set, no sudo needed):"
    echo ""
    echo "  ./$TEST_BIN $INTERFACE [test_args...]"
    echo ""
    echo "Examples:"
    echo "  ./$TEST_BIN $INTERFACE --timeout 5000"
    echo "  ./$TEST_BIN $INTERFACE --timeout -1   # forever mode"
    echo ""
    echo "To unbind NIC from vfio-pci after testing:"
    echo "  $DPDK_BIND_SCRIPT $INTERFACE --unbind"
    echo ""
    log_ok "Ready to run test"
}

# Run main
main "$@"
