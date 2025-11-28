#!/bin/bash
# NIC Queue Number Switch - Toggle between single and multi-queue modes
#
# Single queue mode is required for AF_XDP to receive all packets.
# Multi-queue mode enables RSS for parallel processing.
#
# Usage:
#   sudo ./scripts/nic_queue_num_switch.sh <interface> <enable|disable|status>
#
# Examples:
#   sudo ./scripts/nic_queue_num_switch.sh enp108s0 disable    # Single queue for AF_XDP
#   sudo ./scripts/nic_queue_num_switch.sh enp108s0 enable     # Multi-queue for RSS
#   sudo ./scripts/nic_queue_num_switch.sh enp108s0 status     # Check current config

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root (use sudo)"
    exit 1
fi

# Check arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <interface> <enable|disable|status>"
    echo ""
    echo "Commands:"
    echo "  disable   - Set to single queue mode (required for AF_XDP)"
    echo "  enable    - Set to multi-queue mode (4 queues, enables RSS)"
    echo "  status    - Show current queue configuration"
    echo ""
    echo "Example:"
    echo "  sudo $0 enp108s0 disable    # Single queue for AF_XDP"
    echo "  sudo $0 enp108s0 enable     # Multi-queue (4 queues)"
    echo "  sudo $0 enp108s0 status     # Check current config"
    exit 1
fi

INTERFACE="$1"
ACTION="$2"

# Verify interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "ERROR: Interface '$INTERFACE' not found"
    echo ""
    echo "Available interfaces:"
    ip -brief link show | grep -v "^lo" | awk '{print "  " $1}'
    exit 1
fi

# Function to get max supported queues
get_max_queues() {
    local iface="$1"
    ethtool -l "$iface" 2>/dev/null | \
        awk 'BEGIN{in_preset=0}
             /^Pre-set maximums:/{in_preset=1; next}
             /^Current hardware settings:/{in_preset=0}
             in_preset && /Combined:/{print $2; exit}'
}

# Function to get current queues
get_current_queues() {
    local iface="$1"
    ethtool -l "$iface" 2>/dev/null | \
        awk 'BEGIN{in_current=0}
             /^Current hardware settings:/{in_current=1; next}
             in_current && /Combined:/{print $2; exit}'
}

# Get queue info
MAX_QUEUES=$(get_max_queues "$INTERFACE")
CURRENT_QUEUES=$(get_current_queues "$INTERFACE")

if [ -z "$MAX_QUEUES" ] || [ -z "$CURRENT_QUEUES" ]; then
    echo "ERROR: Could not read queue configuration for $INTERFACE"
    echo "This interface may not support ethtool queue configuration"
    exit 1
fi

case "$ACTION" in
    status)
        echo "═══════════════════════════════════════════════════════"
        echo "  NIC Queue Configuration Status"
        echo "═══════════════════════════════════════════════════════"
        echo ""
        echo "Interface: $INTERFACE"
        echo ""
        ethtool -l "$INTERFACE"
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo "Current mode: $([ "$CURRENT_QUEUES" -eq 1 ] && echo "Single Queue (RSS Disabled)" || echo "Multi-Queue (RSS Enabled)")"
        echo "───────────────────────────────────────────────────────"

        if [ "$CURRENT_QUEUES" -eq 1 ]; then
            echo "✅ Single queue mode - AF_XDP will receive all packets on queue 0"
            echo ""
            echo "To enable multi-queue RSS:"
            echo "  sudo $0 $INTERFACE enable"
        else
            echo "⚠️  Multi-queue mode - AF_XDP on queue 0 may miss packets!"
            echo ""
            echo "Packet distribution across queues:"
            ethtool -S "$INTERFACE" | grep -E "rx_queue_[0-9]+_packets" | head -8 || \
                echo "  (Queue stats not available for this driver)"
            echo ""
            echo "To fix AF_XDP packet reception:"
            echo "  sudo $0 $INTERFACE disable"
        fi
        echo ""
        ;;

    disable)
        echo "═══════════════════════════════════════════════════════"
        echo "  Disabling RSS (Single Queue Mode)"
        echo "═══════════════════════════════════════════════════════"
        echo ""
        echo "Interface: $INTERFACE"
        echo "Current queues: $CURRENT_QUEUES"
        echo "Target queues: 1"
        echo ""

        if [ "$CURRENT_QUEUES" -eq 1 ]; then
            echo "✅ Already in single queue mode"
            echo ""
            echo "Current configuration:"
            ethtool -l "$INTERFACE"
            echo ""
            exit 0
        fi

        echo "Disabling RSS (setting to 1 combined queue)..."
        if ethtool -L "$INTERFACE" combined 1 2>&1; then
            echo ""
            echo "✅ SUCCESS! RSS disabled"
            echo ""
            echo "New configuration:"
            ethtool -l "$INTERFACE"
            echo ""
            echo "───────────────────────────────────────────────────────"
            echo "All traffic will now go to queue 0"
            echo "AF_XDP sockets on queue 0 will receive all packets"
            echo ""
            echo "Verify with:"
            echo "  sudo ethtool -S $INTERFACE | grep rx_queue.*packets"
            echo "  sudo ./build/test_xdp_rx $INTERFACE"
            echo ""
        else
            echo ""
            echo "❌ FAILED to disable RSS"
            echo ""
            echo "Possible causes:"
            echo "  1. Driver doesn't support dynamic queue reconfiguration"
            echo "  2. Interface is currently in use (try: sudo ip link set $INTERFACE down)"
            echo "  3. Insufficient permissions"
            exit 1
        fi
        ;;

    enable)
        echo "═══════════════════════════════════════════════════════"
        echo "  Enabling RSS (Multi-Queue Mode)"
        echo "═══════════════════════════════════════════════════════"
        echo ""
        echo "Interface: $INTERFACE"
        echo "Current queues: $CURRENT_QUEUES"
        echo "Max supported queues: $MAX_QUEUES"
        echo "Target queues: $MAX_QUEUES"
        echo ""

        if [ "$CURRENT_QUEUES" -eq "$MAX_QUEUES" ]; then
            echo "✅ Already in multi-queue mode ($MAX_QUEUES queues)"
            echo ""
            echo "Current configuration:"
            ethtool -l "$INTERFACE"
            echo ""
            echo "Packet distribution:"
            ethtool -S "$INTERFACE" | grep -E "rx_queue_[0-9]+_packets" | head -8 || \
                echo "  (Queue stats not available)"
            echo ""
            exit 0
        fi

        echo "Enabling RSS (setting to $MAX_QUEUES combined queues)..."
        if ethtool -L "$INTERFACE" combined "$MAX_QUEUES" 2>&1; then
            echo ""
            echo "✅ SUCCESS! RSS enabled with $MAX_QUEUES queues"
            echo ""
            echo "New configuration:"
            ethtool -l "$INTERFACE"
            echo ""
            echo "───────────────────────────────────────────────────────"
            echo "⚠️  IMPORTANT: AF_XDP Configuration Required"
            echo "───────────────────────────────────────────────────────"
            echo ""
            echo "Traffic will now be distributed across $MAX_QUEUES queues by RSS."
            echo ""
            echo "For AF_XDP to work correctly, you must either:"
            echo ""
            echo "  Option 1: Create AF_XDP sockets on ALL $MAX_QUEUES queues"
            echo "    - Modify your application to bind to queues 0-$((MAX_QUEUES-1))"
            echo "    - Requires multi-threaded AF_XDP implementation"
            echo ""
            echo "  Option 2: Configure RSS to route specific traffic to queue 0"
            echo "    - Use ethtool flow rules (driver-specific)"
            echo "    - Example: ethtool -U $INTERFACE flow-type tcp4 dst-ip <exchange_ip> action 0"
            echo ""
            echo "  Option 3: Disable RSS again for simple AF_XDP"
            echo "    - Run: sudo $0 $INTERFACE disable"
            echo ""
            echo "Verify packet distribution:"
            echo "  watch -n1 'sudo ethtool -S $INTERFACE | grep rx_queue.*packets'"
            echo ""
        else
            echo ""
            echo "❌ FAILED to enable RSS"
            echo ""
            echo "Possible causes:"
            echo "  1. Driver doesn't support dynamic queue reconfiguration"
            echo "  2. Interface is currently in use"
            echo "  3. Insufficient permissions"
            exit 1
        fi
        ;;

    *)
        echo "ERROR: Invalid action '$ACTION'"
        echo ""
        echo "Valid actions:"
        echo "  disable   - Set to single queue mode (for AF_XDP)"
        echo "  enable    - Set to multi-queue mode (for RSS)"
        echo "  status    - Show current queue configuration"
        exit 1
        ;;
esac
