#!/bin/bash
# scripts/nic_optimise.sh
# NIC optimization script for ultra-low latency HFT trading
#
# This script configures network interface for minimum latency:
# - Disables interrupt coalescing (rx/tx-usecs, rx/tx-frames = 0)
#   → Eliminates interrupt batching delay
# - Disables GRO/LRO offloading (CRITICAL FOR HFT!)
#   → GRO batches packets, adding 5-50μs latency + jitter
#   → With GRO ON: Packets wait to be batched before delivery
#   → With GRO OFF: Packets delivered immediately to application
# - Verifies hardware timestamping support
#
# Expected latency improvement: 5-50μs per packet when disabling GRO
# Expected jitter reduction: Significantly more consistent packet delivery
#
# Usage:
#   sudo ./scripts/nic_optimise.sh [interface]
#   sudo ./scripts/nic_optimise.sh enp108s0

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         NIC Optimization for Ultra-Low Latency Trading            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        echo ""
        echo "Usage: sudo $0 [interface]"
        exit 1
    fi
}

# Detect network interface
detect_interface() {
    local iface="$1"

    if [[ -z "$iface" ]]; then
        # Try to auto-detect from WS_NIC_INTERFACE env var
        if [[ -n "${WS_NIC_INTERFACE:-}" ]]; then
            iface="$WS_NIC_INTERFACE"
            print_info "Using interface from WS_NIC_INTERFACE: $iface"
        else
            # Find first non-loopback interface with carrier
            iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -1)
            if [[ -z "$iface" ]]; then
                print_error "No network interface found"
                exit 1
            fi
            print_warning "Auto-detected interface: $iface"
            echo "           To specify manually: sudo $0 <interface>"
        fi
    fi

    # Verify interface exists
    if ! ip link show "$iface" &>/dev/null; then
        print_error "Interface '$iface' not found"
        echo ""
        echo "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  - " $2}'
        exit 1
    fi

    echo "$iface"
}

# Check current coalescing settings
check_coalescing() {
    local iface="$1"

    echo ""
    echo "Current interrupt coalescing settings:"
    echo "────────────────────────────────────────────────────────────────────"

    local output
    if output=$(ethtool -c "$iface" 2>&1); then
        echo "$output" | grep -E "(rx-usecs|rx-frames|tx-usecs|tx-frames):" | grep -v "irq"
    else
        print_warning "Cannot read coalescing settings (not supported or permission issue)"
        return 1
    fi
}

# Set coalescing to zero (disable interrupt coalescing)
optimize_coalescing() {
    local iface="$1"

    echo ""
    echo "Setting interrupt coalescing to 0 (immediate packet delivery)..."
    echo "────────────────────────────────────────────────────────────────────"

    local changes_made=0
    local already_optimal=0
    local errors=0

    # Try to set all coalescing parameters to 0
    # Note: Not all NICs support all parameters
    local params=("rx-usecs" "rx-frames" "tx-usecs" "tx-frames")

    for param in "${params[@]}"; do
        # Get current value
        local current
        current=$(ethtool -c "$iface" 2>/dev/null | grep "^$param:" | awk '{print $2}') || current="n/a"

        # Skip if not supported (n/a)
        if [[ "$current" == "n/a" || -z "$current" ]]; then
            continue
        fi

        # Always try to set to 0, regardless of current value
        if ethtool -C "$iface" "$param" 0 2>/dev/null; then
            if [[ "$current" != "0" ]]; then
                print_success "Set $param: $current → 0"
                ((changes_made++))
            else
                print_info "$param: already 0 (verified and set)"
                ((already_optimal++))
            fi
        else
            # Failed to set - check why
            if [[ "$current" == "0" ]]; then
                print_info "$param: already 0 (read-only or not settable)"
                ((already_optimal++))
            else
                print_warning "$param: Failed to set (current: ${current}, not supported)"
                ((errors++))
            fi
        fi
    done

    echo ""
    if [[ $changes_made -gt 0 ]]; then
        print_success "✓ Changed $changes_made parameter(s) to optimal values"
    fi
    if [[ $already_optimal -gt 0 ]]; then
        print_info "ℹ $already_optimal parameter(s) already optimal"
    fi
    if [[ $errors -gt 0 ]]; then
        print_warning "⚠ $errors parameter(s) not supported by this NIC"
    fi
}

# Check offload settings
check_offload() {
    local iface="$1"

    echo ""
    echo "Current offload settings:"
    echo "────────────────────────────────────────────────────────────────────"

    local output
    if output=$(ethtool -k "$iface" 2>/dev/null | grep -E "(generic-receive-offload|large-receive-offload):"); then
        echo "$output"

        # Check if GRO is ON and warn about HFT impact
        if echo "$output" | grep "generic-receive-offload: on" >/dev/null; then
            echo ""
            print_error "⚠️  CRITICAL FOR HFT: Generic Receive Offload (GRO) is ON!"
            print_warning "   GRO batches packets, adding 5-50μs latency and jitter"
            print_warning "   This SIGNIFICANTLY hurts HFT trading performance"
            print_warning "   Will disable GRO in next step..."
        fi
    else
        print_warning "Cannot read offload settings"
    fi
}

# Disable GRO and LRO
optimize_offload() {
    local iface="$1"

    echo ""
    echo "Disabling receive offloads (GRO, LRO) for ultra-low latency..."
    echo "────────────────────────────────────────────────────────────────────"

    local changes_made=0
    local already_optimal=0

    # Get current states BEFORE attempting changes
    local gro_before lro_before
    gro_before=$(ethtool -k "$iface" 2>/dev/null | grep "generic-receive-offload:" | awk '{print $2}')
    lro_before=$(ethtool -k "$iface" 2>/dev/null | grep "large-receive-offload:" | awk '{print $2}')

    # ALWAYS try to disable GRO (Generic Receive Offload)
    if ethtool -K "$iface" gro off 2>/dev/null; then
        if [[ "$gro_before" == "on" ]]; then
            print_success "GRO (Generic Receive Offload): ON → OFF"
            print_info "   Expected latency reduction: 5-50μs per packet"
            print_info "   Expected jitter reduction: Packets now delivered immediately"
            ((changes_made++))
        else
            print_info "GRO: already off (verified and set)"
            ((already_optimal++))
        fi
    else
        if [[ "$gro_before" == "off" ]]; then
            print_info "GRO: already off (read-only or fixed)"
            ((already_optimal++))
        else
            print_warning "GRO: Failed to disable (current: ${gro_before:-N/A}, may be fixed)"
        fi
    fi

    # ALWAYS try to disable LRO (Large Receive Offload)
    if ethtool -K "$iface" lro off 2>/dev/null; then
        if [[ "$lro_before" == "on" ]]; then
            print_success "LRO (Large Receive Offload): ON → OFF"
            ((changes_made++))
        else
            print_info "LRO: already off (verified and set)"
            ((already_optimal++))
        fi
    else
        if [[ "$lro_before" == "off" || "$lro_before" =~ "fixed" ]]; then
            print_info "LRO: already off (read-only or fixed)"
            ((already_optimal++))
        else
            print_warning "LRO: Failed to disable (current: ${lro_before:-N/A}, may be fixed)"
        fi
    fi

    echo ""
    if [[ $changes_made -gt 0 ]]; then
        print_success "✓ Changed $changes_made offload setting(s) - CRITICAL for HFT latency!"
    fi
    if [[ $already_optimal -gt 0 ]]; then
        print_info "ℹ $already_optimal offload setting(s) already optimal"
    fi
}

# Check hardware timestamping
check_hw_timestamp() {
    local iface="$1"

    echo ""
    echo "Hardware timestamping capabilities:"
    echo "────────────────────────────────────────────────────────────────────"

    local output
    if output=$(ethtool -T "$iface" 2>&1); then
        echo "$output"

        # Check for RX hardware timestamping
        if echo "$output" | grep -q "hardware-raw-clock"; then
            print_success "Hardware timestamping is SUPPORTED"
            echo ""
            print_info "To enable in application:"
            echo "           1. Run application with CAP_NET_ADMIN or as root"
            echo "           2. Set WS_NIC_INTERFACE=$iface"
            return 0
        else
            print_warning "Hardware timestamping support unclear"
            return 1
        fi
    else
        print_error "Cannot query timestamping capabilities"
        return 1
    fi
}

# Verify final settings
verify_settings() {
    local iface="$1"

    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                    Verification Summary                            ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    local all_good=1

    # Check coalescing
    echo "Interrupt Coalescing:"
    local rx_usecs tx_usecs rx_frames tx_frames
    rx_usecs=$(ethtool -c "$iface" 2>/dev/null | grep "^rx-usecs:" | awk '{print $2}')
    tx_usecs=$(ethtool -c "$iface" 2>/dev/null | grep "^tx-usecs:" | awk '{print $2}')
    rx_frames=$(ethtool -c "$iface" 2>/dev/null | grep "^rx-frames:" | awk '{print $2}')
    tx_frames=$(ethtool -c "$iface" 2>/dev/null | grep "^tx-frames:" | awk '{print $2}')

    if [[ "$rx_usecs" == "0" ]]; then
        print_success "rx-usecs: 0 (optimal)"
    else
        print_warning "rx-usecs: ${rx_usecs:-N/A} (should be 0)"
        all_good=0
    fi

    if [[ "$rx_frames" == "0" ]]; then
        print_success "rx-frames: 0 (optimal)"
    else
        print_warning "rx-frames: ${rx_frames:-N/A} (should be 0)"
        all_good=0
    fi

    if [[ "$tx_usecs" == "0" ]]; then
        print_success "tx-usecs: 0 (optimal)"
    else
        print_warning "tx-usecs: ${tx_usecs:-N/A} (should be 0)"
        all_good=0
    fi

    if [[ "$tx_frames" == "0" ]]; then
        print_success "tx-frames: 0 (optimal)"
    else
        print_warning "tx-frames: ${tx_frames:-N/A} (should be 0)"
        all_good=0
    fi

    echo ""
    echo "Receive Offload:"
    local gro_state lro_state
    gro_state=$(ethtool -k "$iface" 2>/dev/null | grep "generic-receive-offload:" | awk '{print $2}')
    lro_state=$(ethtool -k "$iface" 2>/dev/null | grep "large-receive-offload:" | awk '{print $2}')

    if [[ "$gro_state" == "off" ]]; then
        print_success "GRO: off (optimal)"
    else
        print_warning "GRO: ${gro_state:-N/A} (should be off)"
        all_good=0
    fi

    if [[ "$lro_state" == "off" ]]; then
        print_success "LRO: off (optimal)"
    else
        print_warning "LRO: ${lro_state:-N/A} (should be off)"
        all_good=0
    fi

    echo ""
    echo "Hardware Timestamping:"
    if ethtool -T "$iface" 2>/dev/null | grep -q "hardware-raw-clock"; then
        print_success "Hardware timestamping: ENABLED"
    else
        print_warning "Hardware timestamping: Not detected"
        all_good=0
    fi

    echo ""
    echo "────────────────────────────────────────────────────────────────────"
    if [[ $all_good -eq 1 ]]; then
        print_success "All optimizations applied successfully!"
        echo ""
        echo "Expected HFT Latency Impact:"
        if [[ "$gro_state" == "off" ]]; then
            print_success "GRO disabled: Expect 5-50μs latency reduction per packet"
            print_success "              Significantly reduced jitter and more consistent delivery"
        fi
        print_success "Interrupt coalescing disabled: Packets delivered immediately"
        print_success "Overall: Your WebSocket should see measurably lower Stage 1→2 latency"
    else
        print_warning "Some optimizations could not be applied (may not be supported)"
    fi

    echo ""
    print_info "NIC Interface: $iface"
    print_info "To persist across reboots, add this script to /etc/rc.local or systemd"
    print_info ""
    print_info "Verify impact by running: make test-binance"
    print_info "Compare Stage 1→2 (NIC→Event) latency before/after these optimizations"
}

# Main execution
main() {
    print_header

    # Check root privileges
    check_root

    # Detect or validate interface
    local interface
    interface=$(detect_interface "${1:-}")

    echo ""
    print_info "Target Interface: $interface"

    # Show current state BEFORE optimization
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║              BEFORE OPTIMIZATION - Current Settings                ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    check_coalescing "$interface" || true
    check_offload "$interface" || true

    # APPLY OPTIMIZATIONS (making actual changes)
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║           APPLYING OPTIMIZATIONS - Making Changes...              ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    optimize_coalescing "$interface"
    optimize_offload "$interface"
    check_hw_timestamp "$interface"

    # Show final state AFTER optimization
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║              AFTER OPTIMIZATION - Final Settings                   ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    verify_settings "$interface"

    echo ""
    print_success "NIC optimization complete!"
    echo ""
}

# Run main function
main "$@"
