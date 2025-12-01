#!/bin/bash
# XDP Filter Script
# Resolves DNS, updates /etc/hosts, and sets up route bypass for XDP testing
#
# Usage:
#   ./scripts/xdp_filter.sh <interface> <domain>           # Setup filter
#   ./scripts/xdp_filter.sh --reset <interface>            # Reset/cleanup
#
# Examples:
#   ./scripts/xdp_filter.sh enp108s0 stream.binance.com
#   ./scripts/xdp_filter.sh --reset enp108s0

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
    echo -e "${BLUE}[INFO]${NC} $1"
}

# State file for tracking added routes
STATE_DIR="/tmp/xdp_filter_state"
ROUTES_FILE="$STATE_DIR/routes"
HOSTS_BACKUP="$STATE_DIR/hosts_entries"

# Get gateway IP for the interface
get_gateway() {
    local iface="$1"
    ip route show dev "$iface" | grep "default" | awk '{print $3}' | head -1
}

# Resolve DNS and get all IPs
resolve_dns() {
    local domain="$1"
    # Use host command for DNS lookup, filter A records
    host "$domain" 2>/dev/null | grep "has address" | awk '{print $NF}' | sort -u
}

# Check if an IP route exists
route_exists() {
    local ip="$1"
    local iface="$2"
    ip route show "$ip" dev "$iface" &>/dev/null
}

# Check if iptables RST rule exists
rst_rule_exists() {
    local ip="$1"
    local iface="$2"
    sudo iptables -C OUTPUT -o "$iface" -p tcp --tcp-flags RST RST -d "$ip" -j DROP 2>/dev/null
}

# Add iptables rule to block kernel RST packets
add_rst_block() {
    local ip="$1"
    local iface="$2"

    if rst_rule_exists "$ip" "$iface"; then
        print_info "RST block rule already exists for $ip"
        return 0
    fi

    if sudo iptables -I OUTPUT -o "$iface" -p tcp --tcp-flags RST RST -d "$ip" -j DROP 2>/dev/null; then
        echo "$ip" >> "$STATE_DIR/rst_rules"
        print_status "Added RST block: $ip on $iface"
        return 0
    else
        print_warning "Could not add RST block rule for $ip"
        return 1
    fi
}

# Remove iptables RST block rule
remove_rst_block() {
    local ip="$1"
    local iface="$2"

    if sudo iptables -D OUTPUT -o "$iface" -p tcp --tcp-flags RST RST -d "$ip" -j DROP 2>/dev/null; then
        print_status "Removed RST block: $ip on $iface"
    fi
}

# Add route for IP via interface
add_route() {
    local ip="$1"
    local gateway="$2"
    local iface="$3"

    if route_exists "$ip" "$iface"; then
        print_info "Route already exists for $ip via $iface"
        return 0
    fi

    if sudo ip route add "$ip" via "$gateway" dev "$iface" metric 50 2>/dev/null; then
        echo "$ip" >> "$ROUTES_FILE"
        print_status "Added route: $ip via $gateway dev $iface"
        return 0
    else
        print_warning "Could not add route for $ip (may conflict with existing route)"
        return 1
    fi
}

# Remove route for IP
remove_route() {
    local ip="$1"
    local iface="$2"

    if sudo ip route del "$ip" dev "$iface" 2>/dev/null; then
        print_status "Removed route: $ip dev $iface"
    fi
}

# Update /etc/hosts with domain -> IP mapping
update_hosts() {
    local domain="$1"
    local ip="$2"

    # Remove any existing entries for this domain
    sudo sed -i "/$domain/d" /etc/hosts 2>/dev/null || true

    # Add new entry
    echo "$ip $domain" | sudo tee -a /etc/hosts > /dev/null
    echo "$domain" >> "$HOSTS_BACKUP"
    print_status "Updated /etc/hosts: $ip $domain"
}

# Remove domain entries from /etc/hosts
cleanup_hosts() {
    if [[ -f "$HOSTS_BACKUP" ]]; then
        while IFS= read -r domain; do
            sudo sed -i "/$domain/d" /etc/hosts 2>/dev/null || true
            print_status "Removed $domain from /etc/hosts"
        done < "$HOSTS_BACKUP"
        rm -f "$HOSTS_BACKUP"
    fi
}

# Setup filter for domain
setup_filter() {
    local iface="$1"
    local domain="$2"

    echo ""
    echo "========================================"
    echo "  XDP Filter Setup"
    echo "  Interface: $iface"
    echo "  Domain: $domain"
    echo "========================================"
    echo ""

    # Check interface exists
    if ! ip link show "$iface" &>/dev/null; then
        print_error "Interface $iface does not exist"
        exit 1
    fi

    # Create state directory
    mkdir -p "$STATE_DIR"

    # Get gateway
    local gateway=$(get_gateway "$iface")
    if [[ -z "$gateway" ]]; then
        print_error "Could not determine gateway for $iface"
        exit 1
    fi
    print_info "Gateway: $gateway"

    # Resolve DNS
    echo "Resolving DNS for $domain..."
    local ips=$(resolve_dns "$domain")

    if [[ -z "$ips" ]]; then
        print_error "Could not resolve DNS for $domain"
        exit 1
    fi

    local ip_count=$(echo "$ips" | wc -l)
    print_status "Resolved $ip_count IP(s) for $domain"

    # Pick the first IP for /etc/hosts (connection will use this)
    local primary_ip=$(echo "$ips" | head -1)

    # Update /etc/hosts
    update_hosts "$domain" "$primary_ip"

    # Add routes and RST blocks for all resolved IPs
    echo ""
    echo "Setting up route bypasses and RST blocks..."
    local route_count=0
    while IFS= read -r ip; do
        if [[ -n "$ip" ]]; then
            if add_route "$ip" "$gateway" "$iface"; then
                ((route_count++)) || true
            fi
            # Block kernel RST packets for this IP (required for userspace TCP)
            add_rst_block "$ip" "$iface"
        fi
    done <<< "$ips"

    echo ""
    echo "========================================"
    echo "  Filter Setup Complete"
    echo "========================================"
    echo ""
    echo "  Domain:     $domain"
    echo "  Primary IP: $primary_ip"
    echo "  Routes:     $route_count"
    echo "  Interface:  $iface"
    echo "  Gateway:    $gateway"
    echo ""

    # Verify the primary IP is reachable
    echo "Verifying connectivity..."
    if timeout 3 curl -s --connect-to ":443:$primary_ip:443" "https://$domain/" --max-time 2 &>/dev/null; then
        print_status "Connectivity verified to $primary_ip"
    else
        print_warning "Could not verify connectivity (may still work)"
    fi

    echo ""
    print_status "XDP filter setup complete"
}

# Reset/cleanup
reset_filter() {
    local iface="$1"

    echo ""
    echo "========================================"
    echo "  XDP Filter Reset"
    echo "  Interface: $iface"
    echo "========================================"
    echo ""

    # Remove routes
    if [[ -f "$ROUTES_FILE" ]]; then
        echo "Removing route bypasses..."
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                remove_route "$ip" "$iface"
            fi
        done < "$ROUTES_FILE"
        rm -f "$ROUTES_FILE"
    else
        print_info "No routes to remove"
    fi

    # Remove RST block rules
    if [[ -f "$STATE_DIR/rst_rules" ]]; then
        echo "Removing RST block rules..."
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                remove_rst_block "$ip" "$iface"
            fi
        done < "$STATE_DIR/rst_rules"
        rm -f "$STATE_DIR/rst_rules"
    else
        print_info "No RST block rules to remove"
    fi

    # Cleanup hosts
    echo "Cleaning up /etc/hosts..."
    cleanup_hosts

    # Detach XDP program
    echo "Detaching XDP program..."
    if sudo ip link set "$iface" xdp off 2>/dev/null; then
        print_status "XDP program detached"
    else
        print_info "No XDP program was attached"
    fi

    echo ""
    print_status "XDP filter reset complete"
}

# Show help
show_help() {
    echo "XDP Filter Script"
    echo ""
    echo "Usage:"
    echo "  $0 <interface> <domain>        Setup filter for domain"
    echo "  $0 --reset <interface>         Reset/cleanup all filters"
    echo "  $0 --help                      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 enp108s0 stream.binance.com"
    echo "  $0 --reset enp108s0"
    echo ""
}

# Main
case "${1:-}" in
    --reset|-r)
        if [[ -z "${2:-}" ]]; then
            print_error "Interface required for reset"
            show_help
            exit 1
        fi
        reset_filter "$2"
        ;;
    --help|-h)
        show_help
        ;;
    "")
        print_error "No arguments provided"
        show_help
        exit 1
        ;;
    *)
        if [[ -z "${2:-}" ]]; then
            print_error "Domain required"
            show_help
            exit 1
        fi
        setup_filter "$1" "$2"
        ;;
esac
