#!/bin/bash
# XDP Reset Script
# Cleans up XDP program, routes, and /etc/hosts entries
#
# Usage: ./scripts/xdp_reset.sh <interface>
# Example: ./scripts/xdp_reset.sh enp108s0

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

print_info() {
    echo -e "[INFO] $1"
}

# State file locations (shared with xdp_filter.sh)
STATE_DIR="/tmp/xdp_filter_state"
ROUTES_FILE="$STATE_DIR/routes"
HOSTS_BACKUP="$STATE_DIR/hosts_entries"

echo ""
echo "========================================"
echo "  XDP Reset: $IFACE"
echo "========================================"
echo ""

# Check interface
if ! ip link show "$IFACE" &>/dev/null; then
    print_error "Interface $IFACE does not exist"
    exit 1
fi

# Detach XDP program
echo "Detaching XDP program..."
if ip link show "$IFACE" | grep -q "xdp"; then
    if sudo ip link set "$IFACE" xdp off 2>/dev/null; then
        print_status "XDP program detached from $IFACE"
    else
        print_error "Failed to detach XDP program"
    fi
else
    print_info "No XDP program attached to $IFACE"
fi

# Remove routes added by xdp_filter.sh
echo "Removing route bypasses..."
if [[ -f "$ROUTES_FILE" ]]; then
    while IFS= read -r ip; do
        if [[ -n "$ip" ]]; then
            if sudo ip route del "$ip" dev "$IFACE" 2>/dev/null; then
                print_status "Removed route: $ip"
            else
                print_info "Route $ip already removed or doesn't exist"
            fi
        fi
    done < "$ROUTES_FILE"
    rm -f "$ROUTES_FILE"
else
    print_info "No tracked routes to remove"
fi

# Remove /etc/hosts entries added by xdp_filter.sh
echo "Cleaning up /etc/hosts..."
if [[ -f "$HOSTS_BACKUP" ]]; then
    while IFS= read -r domain; do
        if [[ -n "$domain" ]]; then
            if sudo sed -i "/$domain/d" /etc/hosts 2>/dev/null; then
                print_status "Removed $domain from /etc/hosts"
            fi
        fi
    done < "$HOSTS_BACKUP"
    rm -f "$HOSTS_BACKUP"
else
    print_info "No tracked /etc/hosts entries to remove"
fi

# Clean up state directory if empty
if [[ -d "$STATE_DIR" ]] && [[ -z "$(ls -A "$STATE_DIR" 2>/dev/null)" ]]; then
    rmdir "$STATE_DIR" 2>/dev/null || true
fi

echo ""
echo "========================================"
echo "  Reset Complete"
echo "========================================"
echo ""
print_status "XDP reset complete for $IFACE"
echo ""
