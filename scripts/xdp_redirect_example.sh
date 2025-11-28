#!/bin/bash
# XDP Flow Redirection - Usage Example
#
# This script demonstrates how to use XDP flow redirection for HFT applications.
# It shows the complete workflow from setup to cleanup.
#
# DO NOT RUN THIS DIRECTLY - Read and adapt for your environment!

set -e

# CONFIGURATION - ADAPT THESE FOR YOUR ENVIRONMENT
INTERFACE="eth0"              # Your network interface
DOMAIN="stream.binance.com"   # Exchange domain
QUEUE_ID=5                    # Dedicated queue for HFT (use queue 1-15)
CPU_CORE=5                    # CPU core to pin application to (same as queue)

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}XDP Flow Redirection - Complete Workflow${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 1: Check Prerequisites
echo -e "${GREEN}Step 1: Checking prerequisites...${NC}"
echo ""

echo "1.1 Check if running as root:"
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}  ✗ Not running as root. Use: sudo $0${NC}"
    exit 1
else
    echo "  ✓ Running as root"
fi

echo ""
echo "1.2 Check interface $INTERFACE exists:"
if ip link show "$INTERFACE" &> /dev/null; then
    echo "  ✓ Interface exists"
else
    echo "  ✗ Interface not found"
    exit 1
fi

echo ""
echo "1.3 Check NIC capabilities:"
if ethtool -k "$INTERFACE" | grep -q "ntuple-filters:.*on"; then
    echo "  ✓ ntuple-filters supported"
else
    echo "  ⚠ Attempting to enable ntuple-filters..."
    ethtool -K "$INTERFACE" ntuple on || echo "  ✗ Failed to enable"
fi

echo ""
echo "1.4 Check number of queues:"
ethtool -l "$INTERFACE" | grep -E "(Combined|RX):" | head -2
echo ""

# Step 2: Configure Flow Redirection
echo -e "${GREEN}Step 2: Configuring flow redirection...${NC}"
echo ""
echo "Command:"
echo "  sudo ./scripts/xdp_redirect_flow.sh $DOMAIN $INTERFACE $QUEUE_ID"
echo ""

read -p "Continue with flow configuration? [y/N] " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Run the configuration script
./scripts/xdp_redirect_flow.sh "$DOMAIN" "$INTERFACE" "$QUEUE_ID"

echo ""
echo -e "${GREEN}Step 3: Verify configuration...${NC}"
echo ""

echo "3.1 Active flow rules:"
ethtool -u "$INTERFACE" | grep -A2 "Filter:" || echo "  (none)"

echo ""
echo "3.2 Queue statistics (baseline):"
ethtool -S "$INTERFACE" | grep "rx_queue_${QUEUE_ID}_packets"

echo ""
echo -e "${GREEN}Step 4: Run HFT application...${NC}"
echo ""
echo "Your application should now use:"
echo ""
echo "  XDPConfig config;"
echo "  config.interface = \"$INTERFACE\";"
echo "  config.queue_id = $QUEUE_ID;"
echo "  config.zero_copy = true;"
echo ""
echo "  XDPTransport xdp;"
echo "  xdp.init(config);"
echo ""
echo "  UserspaceStack stack;"
echo "  stack.init(&xdp, local_ip, gateway_ip, netmask, local_mac);"
echo "  stack.connect(\"$DOMAIN\", 443);"
echo ""
echo "Recommended: Pin to CPU core $CPU_CORE:"
echo "  sudo taskset -c $CPU_CORE ./build/hft_app --queue $QUEUE_ID"
echo ""

read -p "Press Enter to continue to cleanup..."

# Step 5: Cleanup
echo ""
echo -e "${GREEN}Step 5: Cleanup and reset...${NC}"
echo ""

read -p "Remove flow rules and reset to normal? [y/N] " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Keeping configuration. To reset later, run:"
    echo "  sudo ./scripts/xdp_redirect_reset.sh $INTERFACE"
    exit 0
fi

./scripts/xdp_redirect_reset.sh "$INTERFACE"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Workflow complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Summary:"
echo "  • Flow rules configured to steer $DOMAIN:443 → Queue $QUEUE_ID"
echo "  • XDP application can bind to Queue $QUEUE_ID"
echo "  • Other traffic (SSH, DNS, HTTP) uses other queues"
echo "  • Zero interference with system services ✓"
echo "  • Zero CPU overhead (NIC hardware does steering) ✓"
echo ""
