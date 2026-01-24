#!/bin/bash
# XDP Preparation Script
# Prepares the NIC and environment for AF_XDP zero-copy operation
#
# Usage: ./scripts/xdp_prepare.sh [--reload] [--domain <hostname>] <interface>
# Example: ./scripts/xdp_prepare.sh enp108s0
#          ./scripts/xdp_prepare.sh --reload enp108s0  # Reload NIC driver first
#          ./scripts/xdp_prepare.sh --domain stream.binance.com enp108s0
#
# Options:
#   --reload              Reload NIC driver to reset stuck XDP state
#   --domain <hostname>   Update /etc/hosts with latest DNS for hostname
#
# The --reload flag is useful when XDP gets stuck after a previous session.
# This is a known issue with the igc driver.

set -e

# Parse arguments
RELOAD_DRIVER=0
IFACE="enp108s0"
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reload)
            RELOAD_DRIVER=1
            shift
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        *)
            IFACE="$1"
            shift
            ;;
    esac
done

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

# Update /etc/hosts with latest DNS result for a domain
# This is needed for domains with severe IP churn (e.g., stream.binance.com)
update_domain_hosts() {
    if [[ -z "$DOMAIN" ]]; then
        return 0
    fi

    echo "Updating /etc/hosts for $DOMAIN..."

    # Get fresh DNS result (bypass local cache using external DNS)
    local new_ip=$(dig +short "$DOMAIN" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)

    if [[ -z "$new_ip" ]]; then
        # Fallback to default resolver
        new_ip=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '/STREAM/ {print $1; exit}')
    fi

    if [[ -z "$new_ip" ]]; then
        print_warning "Could not resolve $DOMAIN"
        return 1
    fi

    # Check current /etc/hosts entry
    local current_ip=$(grep -E "^[0-9].*[[:space:]]${DOMAIN}$" /etc/hosts 2>/dev/null | awk '{print $1}' | head -1)

    if [[ "$current_ip" == "$new_ip" ]]; then
        print_status "$DOMAIN already points to $new_ip in /etc/hosts"
        return 0
    fi

    # Remove old entry (if any) and add new one
    sudo sed -i "/[[:space:]]${DOMAIN}$/d" /etc/hosts
    echo "$new_ip $DOMAIN" | sudo tee -a /etc/hosts >/dev/null

    if [[ -n "$current_ip" ]]; then
        print_status "$DOMAIN updated in /etc/hosts: $current_ip → $new_ip"
    else
        print_status "$DOMAIN added to /etc/hosts: $new_ip"
    fi
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

# Reload NIC driver (fixes stuck XDP state on igc driver)
reload_nic_driver() {
    local driver=$(ethtool -i "$IFACE" 2>/dev/null | grep "driver:" | awk '{print $2}')

    if [[ -z "$driver" ]]; then
        print_warning "Could not detect NIC driver"
        return 0
    fi

    # Only reload if --reload flag was passed or driver is known to need it
    if [[ "$RELOAD_DRIVER" == "1" ]]; then
        echo "Reloading NIC driver ($driver) to reset XDP state..."

        if sudo modprobe -r "$driver" 2>/dev/null && sleep 2 && sudo modprobe "$driver" 2>/dev/null; then
            sleep 5  # Wait for interface to come back up (increased from 3s)
            # Wait for interface to have an IP address
            local retry=0
            while [[ $retry -lt 10 ]]; do
                if ip addr show "$IFACE" 2>/dev/null | grep -q "inet "; then
                    break
                fi
                sleep 1
                ((retry++))
            done
            print_status "NIC driver $driver reloaded"
        else
            print_warning "Could not reload driver $driver (may require manual intervention)"
        fi
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

# Set RX/TX ring buffers to maximum (prevents packet drops under load)
set_ring_buffers_max() {
    echo "Setting RX/TX ring buffers to maximum..."

    # Get maximum and current RX ring size
    local rx_max=$(ethtool -g "$IFACE" 2>/dev/null | grep -A 5 "Pre-set maximums:" | grep "^RX:" | awk '{print $2}')
    local rx_cur=$(ethtool -g "$IFACE" 2>/dev/null | grep -A 5 "Current hardware settings:" | grep "^RX:" | awk '{print $2}')

    # Get maximum and current TX ring size
    local tx_max=$(ethtool -g "$IFACE" 2>/dev/null | grep -A 5 "Pre-set maximums:" | grep "^TX:" | awk '{print $2}')
    local tx_cur=$(ethtool -g "$IFACE" 2>/dev/null | grep -A 5 "Current hardware settings:" | grep "^TX:" | awk '{print $2}')

    # Set RX ring to maximum
    if [[ -n "$rx_max" && "$rx_cur" != "$rx_max" ]]; then
        if sudo ethtool -G "$IFACE" rx "$rx_max" 2>/dev/null; then
            print_status "RX ring: $rx_cur → $rx_max (max)"
        else
            print_warning "Could not set RX ring to $rx_max"
        fi
    else
        print_status "RX ring already at max ($rx_cur)"
    fi

    # Set TX ring to maximum
    if [[ -n "$tx_max" && "$tx_cur" != "$tx_max" ]]; then
        if sudo ethtool -G "$IFACE" tx "$tx_max" 2>/dev/null; then
            print_status "TX ring: $tx_cur → $tx_max (max)"
        else
            print_warning "Could not set TX ring to $tx_max"
        fi
    else
        print_status "TX ring already at max ($tx_cur)"
    fi
}

# Disable GRO/LRO for lowest latency (prevents packet batching)
disable_gro_lro() {
    echo "Disabling GRO/LRO for lowest latency..."

    # Disable GRO (Generic Receive Offload) - adds 5-50μs latency
    local gro_before=$(ethtool -k "$IFACE" 2>/dev/null | grep "generic-receive-offload:" | awk '{print $2}')
    if sudo ethtool -K "$IFACE" gro off 2>/dev/null; then
        if [[ "$gro_before" == "on" ]]; then
            print_status "GRO disabled (was: on) - saves 5-50μs per packet"
        else
            print_status "GRO already disabled"
        fi
    else
        print_warning "Could not disable GRO (may be fixed or unsupported)"
    fi

    # Disable LRO (Large Receive Offload)
    local lro_before=$(ethtool -k "$IFACE" 2>/dev/null | grep "large-receive-offload:" | awk '{print $2}')
    if sudo ethtool -K "$IFACE" lro off 2>/dev/null; then
        if [[ "$lro_before" == "on" ]]; then
            print_status "LRO disabled (was: on)"
        else
            print_status "LRO already disabled"
        fi
    else
        if [[ "$lro_before" != "off" ]]; then
            print_warning "Could not disable LRO (may be fixed or unsupported)"
        fi
    fi
}

# Disable interrupt coalescing for immediate packet delivery
disable_coalescing() {
    echo "Disabling interrupt coalescing..."

    local params=("rx-usecs" "rx-frames" "tx-usecs" "tx-frames")
    local changes=0

    for param in "${params[@]}"; do
        local current=$(ethtool -c "$IFACE" 2>/dev/null | grep "^$param:" | awk '{print $2}')
        if [[ -z "$current" || "$current" == "n/a" ]]; then
            continue
        fi

        if sudo ethtool -C "$IFACE" "$param" 0 2>/dev/null; then
            if [[ "$current" != "0" ]]; then
                print_status "$param: $current → 0"
                ((changes++)) || true
            fi
        fi
    done

    if [[ $changes -eq 0 ]]; then
        print_status "Interrupt coalescing already at optimal (0)"
    else
        print_status "Disabled coalescing on $changes parameter(s)"
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
# IMPORTANT: Must kill owning process first to avoid kernel crash!
# Device-bound XDP programs (BPF_F_XDP_DEV_BOUND_ONLY) can cause kernel hang
# if forcibly detached while AF_XDP socket is still active.
detach_xdp() {
    echo "Checking for existing XDP program on $IFACE..."

    # Check if XDP is currently attached
    local xdp_info=$(ip link show "$IFACE" | grep -o "xdp[^ ]*" || true)

    if [[ -n "$xdp_info" ]]; then
        print_warning "XDP program detected: $xdp_info"

        # Find processes using AF_XDP sockets on this interface
        # Method 1: Find test_pipeline_* processes with this interface argument
        local xdp_pids=$(pgrep -f "test_pipeline_.*$IFACE" 2>/dev/null || true)

        # Method 2: Find any test_pipeline_* process (may not have interface in cmdline)
        if [[ -z "$xdp_pids" ]]; then
            xdp_pids=$(pgrep -f "test_pipeline_" 2>/dev/null || true)
        fi

        # Method 3: Use bpftool to find XDP program and trace to owning process
        if [[ -z "$xdp_pids" ]]; then
            local prog_id=$(sudo bpftool net show dev "$IFACE" 2>/dev/null | grep -oP 'xdp.*prog_id \K[0-9]+' || true)
            if [[ -n "$prog_id" ]]; then
                # Find process holding this BPF program fd
                xdp_pids=$(sudo bpftool prog show id "$prog_id" 2>/dev/null | grep -oP 'pids \K[^\]]+' | tr -d '[]' | cut -d'/' -f1 || true)
            fi
        fi

        # Method 4: Find processes with xsk (AF_XDP socket) in their fd links
        if [[ -z "$xdp_pids" ]]; then
            xdp_pids=$(sudo sh -c 'for pid in /proc/[0-9]*/fd/*; do readlink "$pid" 2>/dev/null | grep -q "xsk:" && echo "$pid"; done' | grep -oP '/proc/\K[0-9]+' | sort -u || true)
        fi

        if [[ -n "$xdp_pids" ]]; then
            echo "Found process(es) using XDP: $xdp_pids"

            # Send SIGTERM first for graceful cleanup
            for pid in $xdp_pids; do
                if [[ -d "/proc/$pid" ]]; then
                    local proc_name=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
                    echo "Sending SIGTERM to PID $pid ($proc_name)..."
                    sudo kill -TERM "$pid" 2>/dev/null || true
                fi
            done

            # Wait for graceful shutdown (BPFLoader destructor calls detach())
            echo "Waiting for graceful XDP cleanup..."
            local wait_count=0
            while [[ $wait_count -lt 10 ]]; do
                sleep 1
                ((wait_count++))

                # Check if XDP is still attached
                xdp_info=$(ip link show "$IFACE" | grep -o "xdp[^ ]*" || true)
                if [[ -z "$xdp_info" ]]; then
                    print_status "XDP program gracefully detached after ${wait_count}s"
                    break
                fi

                # Check if processes are still running
                local still_running=0
                for pid in $xdp_pids; do
                    if [[ -d "/proc/$pid" ]]; then
                        still_running=1
                        break
                    fi
                done

                if [[ $still_running -eq 0 ]]; then
                    # Processes died but XDP still attached - wait a bit more
                    sleep 2
                    break
                fi

                echo "  Still waiting... (${wait_count}s)"
            done

            # If still running after 10s, send SIGKILL
            for pid in $xdp_pids; do
                if [[ -d "/proc/$pid" ]]; then
                    local proc_name=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
                    print_warning "Process $pid ($proc_name) didn't exit, sending SIGKILL..."
                    sudo kill -KILL "$pid" 2>/dev/null || true
                fi
            done

            # Wait for SIGKILL to take effect
            sleep 2
        else
            # No owning process found - XDP program is orphaned
            # This is safe to detach since AF_XDP socket died with the process
            print_warning "XDP program is orphaned (no owning process found)"
            print_status "Safe to force-detach orphaned program"
        fi
    fi

    # Now safe to detach any remaining XDP program
    # (should already be detached if process exited cleanly)
    xdp_info=$(ip link show "$IFACE" | grep -o "xdp[^ ]*" || true)
    if [[ -n "$xdp_info" ]]; then
        echo "Force-detaching remaining XDP program..."
        sudo ip link set "$IFACE" xdp off 2>/dev/null || true
        sudo ip link set "$IFACE" xdpdrv off 2>/dev/null || true
        sleep 1
    fi

    # Clean up any pinned BPF programs from previous test runs
    # These are created by bpftool when loading device-bound XDP programs
    for pin_dir in /sys/fs/bpf/selftest_* /sys/fs/bpf/xdp_test_*; do
        if [[ -d "$pin_dir" ]]; then
            echo "Cleaning up pinned BPF: $pin_dir"
            sudo rm -rf "$pin_dir" 2>/dev/null || true
        fi
    done

    # Verify cleanup
    xdp_info=$(ip link show "$IFACE" | grep -o "xdp[^ ]*" || true)

    if [[ -n "$xdp_info" ]]; then
        print_error "Failed to detach XDP program: $xdp_info"
        print_error "Manual intervention required. Try: sudo ip link set $IFACE xdp off"
        exit 1
    else
        print_status "XDP cleanup complete"
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
        if make src/xdp/bpf/exchange_filter.bpf.o USE_XDP=1 XDP_INTERFACE="$IFACE" 2>/dev/null; then
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

# Refresh ARP cache for gateway (ensures bidirectional ARP is fresh)
# This prevents connection timeouts when gateway's ARP for our IP is stale
refresh_gateway_arp() {
    echo "Refreshing gateway ARP cache..."

    # Get gateway IP for this interface
    local gateway_ip=$(ip route show dev "$IFACE" | grep "^default" | awk '{print $3}' | head -1)

    # If no default route on this interface, try to find any gateway
    if [[ -z "$gateway_ip" ]]; then
        gateway_ip=$(ip route show dev "$IFACE" | grep "via" | awk '{print $3}' | head -1)
    fi

    if [[ -z "$gateway_ip" ]]; then
        print_warning "Could not determine gateway IP for $IFACE"
        return 0
    fi

    # Ping gateway to refresh bidirectional ARP
    # This ensures both our ARP cache and the gateway's ARP cache are fresh
    if ping -c 2 -I "$IFACE" "$gateway_ip" &>/dev/null; then
        local arp_state=$(ip neigh show dev "$IFACE" | grep "$gateway_ip" | awk '{print $NF}')
        print_status "Gateway ARP refreshed: $gateway_ip ($arp_state)"
    else
        print_warning "Could not ping gateway $gateway_ip on $IFACE"
    fi
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

    # Start the clock sync daemon (requires root for phc2sys)
    local sync_output
    if sync_output=$("$sync_script" start "$phc_device" 2>&1); then
        print_status "Clock sync daemon started (CPU → $phc_device)"
    else
        # Show actual error instead of hiding it
        print_warning "Failed to start clock sync daemon"
        echo "       $sync_output" | head -3
    fi
}

# Main
print_header
check_interface
check_root
update_domain_hosts
reload_nic_driver
check_xdp_support
set_nic_queue
set_ring_buffers_max
disable_gro_lro
disable_coalescing
enable_hw_timestamp
detach_xdp
refresh_gateway_arp
check_bpf_object
show_nic_info
start_clock_sync

print_status "XDP preparation complete for $IFACE"
echo ""
