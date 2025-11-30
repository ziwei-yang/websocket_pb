#!/bin/bash
# XDP Preparation Script
# Prepares the NIC and environment for AF_XDP zero-copy operation
#
# Usage: ./scripts/xdp_prepare.sh <interface>
# Example: ./scripts/xdp_prepare.sh enp108s0

set -e

IFACE="${1:-enp108s0}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo "========================================"
    echo "  XDP Preparation: $IFACE"
    echo "========================================"
    echo ""
}

# Check if interface exists
check_interface() {
    if ! ip link show "$IFACE" &>/dev/null; then
        print_error "Interface $IFACE does not exist"
        exit 1
    fi
    print_status "Interface $IFACE exists"
}

# Check if running as root (needed for some operations)
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "Not running as root. Some operations may require sudo."
    fi
}

# Set NIC queue to 1 for AF_XDP (RSS must route all traffic to queue 0)
set_nic_queue() {
    echo "Setting NIC combined queues to 1..."

    # Get current queue count
    local current_queues=$(ethtool -l "$IFACE" 2>/dev/null | grep -A 5 "Current hardware settings" | grep "Combined:" | awk '{print $2}')

    if [[ "$current_queues" == "1" ]]; then
        print_status "NIC queues already set to 1"
        return 0
    fi

    # Set to 1 queue
    if sudo ethtool -L "$IFACE" combined 1 2>/dev/null; then
        print_status "NIC queues set to 1 (was: $current_queues)"
    else
        print_warning "Could not set NIC queues (may already be at minimum or unsupported)"
    fi
}

# Enable hardware timestamping for XDP metadata kfuncs
enable_hw_timestamp() {
    echo "Enabling NIC hardware timestamping..."

    # Check if hwstamp_ctl is available
    if ! command -v hwstamp_ctl &>/dev/null; then
        print_warning "hwstamp_ctl not found. Install linuxptp package for HW timestamps."
        return 0
    fi

    # Enable RX hardware timestamping (rx_filter=1 = HWTSTAMP_FILTER_ALL)
    local output=$(sudo hwstamp_ctl -i "$IFACE" -r 1 2>&1)
    local new_filter=$(echo "$output" | grep "rx_filter" | tail -1 | awk '{print $2}')

    if [[ "$new_filter" == "1" ]]; then
        print_status "Hardware RX timestamping enabled (rx_filter=1)"
    else
        print_warning "Could not enable hardware timestamping (rx_filter=$new_filter)"
    fi
}

# Detach any existing XDP program
detach_xdp() {
    echo "Detaching any existing XDP program..."

    # Check if XDP program is attached
    local xdp_info=$(ip link show "$IFACE" | grep -o "xdp[^ ]*" || true)

    if [[ -n "$xdp_info" ]]; then
        if sudo ip link set "$IFACE" xdp off 2>/dev/null; then
            print_status "Detached existing XDP program"
        else
            print_error "Failed to detach XDP program"
            exit 1
        fi
    else
        print_status "No XDP program attached"
    fi
}

# Check BPF object file exists
check_bpf_object() {
    local bpf_obj="src/xdp/bpf/exchange_filter.bpf.o"

    echo "Checking BPF object file..."

    if [[ -f "$bpf_obj" ]]; then
        print_status "BPF object exists: $bpf_obj"
    else
        print_warning "BPF object not found. Building..."
        if make src/xdp/bpf/exchange_filter.bpf.o USE_XDP=1 2>/dev/null; then
            print_status "BPF object built successfully"
        else
            print_error "Failed to build BPF object. Run: USE_XDP=1 make"
            exit 1
        fi
    fi
}

# Verify NIC supports XDP native mode
check_xdp_support() {
    echo "Checking XDP support..."

    local driver=$(ethtool -i "$IFACE" 2>/dev/null | grep "driver:" | awk '{print $2}')

    case "$driver" in
        igc|i40e|ixgbe|mlx5_core|ice|bnxt_en)
            print_status "Driver '$driver' supports XDP native mode"
            ;;
        *)
            print_warning "Driver '$driver' may not fully support XDP native mode"
            ;;
    esac
}

# Display NIC info
show_nic_info() {
    echo ""
    echo "NIC Configuration:"
    echo "  Interface: $IFACE"
    echo "  Driver: $(ethtool -i "$IFACE" 2>/dev/null | grep "driver:" | awk '{print $2}')"
    echo "  Queues: $(ethtool -l "$IFACE" 2>/dev/null | grep -A 5 "Current hardware settings" | grep "Combined:" | awk '{print $2}')"
    echo "  MAC: $(ip link show "$IFACE" | grep ether | awk '{print $2}')"
    echo "  IP: $(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' | head -1)"
    echo ""
}

# Start NIC clock sync daemon (syncs CPU CLOCK_REALTIME → NIC PHC)
start_clock_sync() {
    echo "Starting NIC clock sync daemon..."

    # Find PHC device for this interface
    local phc_device=""
    for ptp in /sys/class/ptp/ptp*; do
        if [[ -d "$ptp/device/net" ]]; then
            local ptp_iface=$(ls "$ptp/device/net/" 2>/dev/null | head -n 1)
            if [[ "$ptp_iface" == "$IFACE" ]]; then
                local ptp_num=$(basename "$ptp" | sed 's/ptp//')
                phc_device="/dev/ptp${ptp_num}"
                break
            fi
        fi
    done

    if [[ -z "$phc_device" ]]; then
        print_warning "Could not find PHC device for $IFACE. Clock sync skipped."
        return 0
    fi

    # Check if nic_local_clock_sync.sh exists
    local script_dir="$(dirname "$0")"
    local sync_script="${script_dir}/nic_local_clock_sync.sh"

    if [[ ! -x "$sync_script" ]]; then
        print_warning "Clock sync script not found: $sync_script"
        return 0
    fi

    # Start the clock sync daemon
    if "$sync_script" start "$phc_device" 2>/dev/null; then
        print_status "Clock sync daemon started (CPU → $phc_device)"
    else
        print_warning "Failed to start clock sync daemon"
    fi
}

# Main
print_header
check_interface
check_root
check_xdp_support
set_nic_queue
enable_hw_timestamp
detach_xdp
check_bpf_object
show_nic_info
start_clock_sync

print_status "XDP preparation complete for $IFACE"
echo ""
