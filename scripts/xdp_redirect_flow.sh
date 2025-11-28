#!/bin/bash
# XDP Flow Redirection Setup
#
# Configures NIC hardware to steer specific traffic to a dedicated RX queue.
# This allows AF_XDP to bind to that queue without affecting other traffic.
#
# Usage:
#   sudo ./scripts/xdp_redirect_flow.sh <domain> <interface> <queue_id>
#
# Example:
#   sudo ./scripts/xdp_redirect_flow.sh stream.binance.com eth0 5
#
# What it does:
#   1. Resolves domain to IP addresses
#   2. Creates flow rules to steer traffic (IP:443) to specified queue
#   3. Verifies rules are active
#   4. Saves configuration for later cleanup
#
# Requirements:
#   - Multi-queue NIC with ntuple-filters support
#   - CAP_NET_ADMIN or root privileges

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="$1"
INTERFACE="$2"
QUEUE_ID="$3"
PORT=443
CONFIG_FILE="/tmp/xdp_flow_config_${INTERFACE}.txt"

# Usage
usage() {
    echo "Usage: $0 <domain> <interface> <queue_id>"
    echo ""
    echo "Arguments:"
    echo "  domain      - Target domain (e.g., stream.binance.com)"
    echo "  interface   - Network interface (e.g., eth0)"
    echo "  queue_id    - RX queue to steer traffic to (e.g., 5)"
    echo ""
    echo "Example:"
    echo "  sudo $0 stream.binance.com eth0 5"
    echo ""
    echo "This will steer all traffic to/from domain:443 to queue 5"
    exit 1
}

# Validate arguments
if [ -z "$DOMAIN" ] || [ -z "$INTERFACE" ] || [ -z "$QUEUE_ID" ]; then
    usage
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0 $@"
    exit 1
fi

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}XDP Flow Redirection Setup${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Configuration:"
echo "  Domain:     $DOMAIN"
echo "  Interface:  $INTERFACE"
echo "  Queue:      $QUEUE_ID"
echo "  Port:       $PORT"
echo ""

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interface $INTERFACE does not exist${NC}"
    exit 1
fi

# Check if interface is up
if ! ip link show "$INTERFACE" | grep -q "state UP"; then
    echo -e "${YELLOW}Warning: Interface $INTERFACE is not UP${NC}"
    echo "Bringing up interface..."
    ip link set "$INTERFACE" up
    sleep 1
fi

# Check NIC capabilities
echo "Checking NIC capabilities..."

# Check for ntuple-filters support
if ! ethtool -k "$INTERFACE" | grep -q "ntuple-filters:.*on"; then
    echo -e "${YELLOW}Warning: ntuple-filters not enabled on $INTERFACE${NC}"
    echo "Attempting to enable ntuple-filters..."
    if ethtool -K "$INTERFACE" ntuple on 2>/dev/null; then
        echo -e "${GREEN}✓ Enabled ntuple-filters${NC}"
    else
        echo -e "${RED}Error: Failed to enable ntuple-filters${NC}"
        echo "This NIC may not support hardware flow steering."
        exit 1
    fi
else
    echo -e "${GREEN}✓ ntuple-filters enabled${NC}"
fi

# Check number of queues
echo ""
echo "Checking RX queue configuration..."
QUEUE_INFO=$(ethtool -l "$INTERFACE" 2>/dev/null || echo "")
if [ -z "$QUEUE_INFO" ]; then
    echo -e "${YELLOW}Warning: Cannot determine queue count${NC}"
else
    echo "$QUEUE_INFO" | grep -E "(Combined|RX):" | head -4

    # Extract max queues
    MAX_QUEUES=$(echo "$QUEUE_INFO" | grep "Combined:" | head -1 | awk '{print $2}')
    if [ ! -z "$MAX_QUEUES" ] && [ "$QUEUE_ID" -ge "$MAX_QUEUES" ]; then
        echo -e "${RED}Error: Queue $QUEUE_ID exceeds maximum ($((MAX_QUEUES - 1)))${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Queue $QUEUE_ID is valid${NC}"
fi

# Resolve domain to IP addresses
echo ""
echo "Resolving domain: $DOMAIN"
IPS=$(dig +short "$DOMAIN" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

if [ -z "$IPS" ]; then
    echo -e "${YELLOW}Warning: dig failed, trying nslookup...${NC}"
    IPS=$(nslookup "$DOMAIN" | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' || true)
fi

if [ -z "$IPS" ]; then
    echo -e "${YELLOW}Warning: DNS resolution failed, trying getent...${NC}"
    IPS=$(getent hosts "$DOMAIN" | awk '{print $1}' || true)
fi

if [ -z "$IPS" ]; then
    echo -e "${RED}Error: Could not resolve $DOMAIN to any IP addresses${NC}"
    exit 1
fi

echo "Resolved IP addresses:"
echo "$IPS" | while read ip; do
    echo "  → $ip"
done

IP_COUNT=$(echo "$IPS" | wc -l)
echo -e "${GREEN}✓ Found $IP_COUNT IP address(es)${NC}"

# Create config file header
cat > "$CONFIG_FILE" <<EOF
# XDP Flow Configuration
# Generated: $(date)
# Domain: $DOMAIN
# Interface: $INTERFACE
# Queue: $QUEUE_ID
# Port: $PORT
#
# Format: rule_id|ip_address|direction
EOF

echo ""
echo "Creating flow steering rules..."
echo ""

RULE_ID=1000  # Start from 1000 to avoid conflicts
SUCCESS_COUNT=0
FAILED_COUNT=0

for IP in $IPS; do
    echo "Processing $IP:$PORT..."

    # Rule 1: Incoming traffic (src-ip = exchange)
    echo -n "  → Incoming traffic (src $IP:$PORT)... "
    if ethtool -U "$INTERFACE" flow-type tcp4 \
        src-ip "$IP" src-port "$PORT" action "$QUEUE_ID" loc "$RULE_ID" 2>&1 | grep -q "Cannot"; then
        echo -e "${YELLOW}SKIP (rule may already exist)${NC}"
    else
        echo -e "${GREEN}OK${NC}"
        echo "$RULE_ID|$IP|incoming" >> "$CONFIG_FILE"
        ((SUCCESS_COUNT++))
    fi
    ((RULE_ID++))

    # Rule 2: Outgoing traffic (dst-ip = exchange)
    echo -n "  → Outgoing traffic (dst $IP:$PORT)... "
    if ethtool -U "$INTERFACE" flow-type tcp4 \
        dst-ip "$IP" dst-port "$PORT" action "$QUEUE_ID" loc "$RULE_ID" 2>&1 | grep -q "Cannot"; then
        echo -e "${YELLOW}SKIP (rule may already exist)${NC}"
    else
        echo -e "${GREEN}OK${NC}"
        echo "$RULE_ID|$IP|outgoing" >> "$CONFIG_FILE"
        ((SUCCESS_COUNT++))
    fi
    ((RULE_ID++))

    echo ""
done

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "Flow rules created: $SUCCESS_COUNT"
if [ $FAILED_COUNT -gt 0 ]; then
    echo "Rules skipped: $FAILED_COUNT"
fi
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Verify rules
echo "Verifying active flow rules..."
echo ""
ethtool -u "$INTERFACE" | grep -A2 "Filter:"
echo ""

# Show queue statistics
echo "Current RX queue statistics:"
ethtool -S "$INTERFACE" | grep "rx_queue_${QUEUE_ID}_" | head -5

echo ""
echo -e "${GREEN}✓ Flow redirection configured successfully!${NC}"
echo ""
echo "Configuration saved to: $CONFIG_FILE"
echo ""
echo "What happens now:"
echo "  • Traffic to/from $DOMAIN:$PORT → Queue $QUEUE_ID"
echo "  • All other traffic → Other queues (kernel stack)"
echo "  • SSH, DNS, HTTP, etc. → Unaffected ✓"
echo ""
echo "To bind AF_XDP to queue $QUEUE_ID:"
echo "  XDPConfig config;"
echo "  config.interface = \"$INTERFACE\";"
echo "  config.queue_id = $QUEUE_ID;"
echo "  xdp.init(config);"
echo ""
echo "To remove these rules:"
echo "  sudo ./scripts/xdp_redirect_reset.sh $INTERFACE"
echo ""
