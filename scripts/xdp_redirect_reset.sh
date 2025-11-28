#!/bin/bash
# XDP Flow Redirection Reset
#
# Removes all flow steering rules created by xdp_redirect_flow.sh
# Restores normal packet processing (all traffic to kernel stack)
#
# Usage:
#   sudo ./scripts/xdp_redirect_reset.sh <interface>
#
# Example:
#   sudo ./scripts/xdp_redirect_reset.sh eth0
#
# What it does:
#   1. Reads configuration from /tmp/xdp_flow_config_<interface>.txt
#   2. Removes all flow rules by rule ID
#   3. Optionally removes ALL flow rules on interface
#   4. Verifies cleanup
#
# Requirements:
#   - CAP_NET_ADMIN or root privileges

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERFACE="$1"
CONFIG_FILE="/tmp/xdp_flow_config_${INTERFACE}.txt"
REMOVE_ALL=false

# Usage
usage() {
    echo "Usage: $0 <interface> [--all]"
    echo ""
    echo "Arguments:"
    echo "  interface   - Network interface (e.g., eth0)"
    echo "  --all       - Remove ALL flow rules (not just XDP ones)"
    echo ""
    echo "Example:"
    echo "  sudo $0 eth0              # Remove XDP flow rules only"
    echo "  sudo $0 eth0 --all        # Remove ALL flow rules"
    echo ""
    exit 1
}

# Validate arguments
if [ -z "$INTERFACE" ]; then
    usage
fi

# Check for --all flag
if [ "$2" = "--all" ]; then
    REMOVE_ALL=true
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0 $@"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}XDP Flow Redirection Reset${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Interface: $INTERFACE"
echo ""

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interface $INTERFACE does not exist${NC}"
    exit 1
fi

# Show current flow rules
echo "Current flow rules on $INTERFACE:"
echo ""
CURRENT_RULES=$(ethtool -u "$INTERFACE" 2>/dev/null | grep "Filter:" || echo "")
if [ -z "$CURRENT_RULES" ]; then
    echo "  (none)"
    echo ""
    echo -e "${GREEN}✓ No flow rules to remove${NC}"

    # Clean up config file if it exists
    if [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE"
        echo "Removed config file: $CONFIG_FILE"
    fi

    exit 0
else
    ethtool -u "$INTERFACE" | grep -A2 "Filter:"
    echo ""
fi

# Count total rules
RULE_COUNT=$(echo "$CURRENT_RULES" | wc -l)
echo "Total rules found: $RULE_COUNT"
echo ""

# Remove rules based on mode
if [ "$REMOVE_ALL" = true ]; then
    echo -e "${YELLOW}WARNING: Removing ALL flow rules on $INTERFACE${NC}"
    echo "This will affect all applications using flow steering."
    read -p "Continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""

    # Extract all rule IDs and delete
    RULE_IDS=$(ethtool -u "$INTERFACE" 2>/dev/null | grep "Filter:" | awk '{print $2}' | tr -d ':' || echo "")

    if [ -z "$RULE_IDS" ]; then
        echo "No rules to remove."
    else
        echo "Removing all rules..."
        for RULE_ID in $RULE_IDS; do
            echo -n "  Removing rule $RULE_ID... "
            if ethtool -U "$INTERFACE" delete "$RULE_ID" 2>&1 | grep -q "Cannot"; then
                echo -e "${YELLOW}SKIP${NC}"
            else
                echo -e "${GREEN}OK${NC}"
            fi
        done
    fi

    # Remove config file
    if [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE"
        echo ""
        echo "Removed config file: $CONFIG_FILE"
    fi

else
    # Remove only XDP rules (from config file)
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Warning: Config file not found: $CONFIG_FILE${NC}"
        echo ""
        echo "Cannot determine which rules to remove."
        echo "Options:"
        echo "  1. Use --all flag to remove ALL rules"
        echo "  2. Manually remove rules using: ethtool -U $INTERFACE delete <rule_id>"
        echo ""
        echo "Current rule IDs:"
        ethtool -u "$INTERFACE" 2>/dev/null | grep "Filter:" | awk '{print "  " $2}'
        exit 1
    fi

    echo "Reading configuration from: $CONFIG_FILE"
    echo ""

    # Extract rule IDs from config file
    RULE_IDS=$(grep -v '^#' "$CONFIG_FILE" | cut -d'|' -f1)

    if [ -z "$RULE_IDS" ]; then
        echo "No rules found in config file."
    else
        echo "Removing XDP flow rules..."
        REMOVED=0
        FAILED=0

        for RULE_ID in $RULE_IDS; do
            echo -n "  Removing rule $RULE_ID... "
            if ethtool -U "$INTERFACE" delete "$RULE_ID" 2>&1 | grep -q "Cannot\|rmgr: Cannot"; then
                echo -e "${YELLOW}SKIP (already removed?)${NC}"
                ((FAILED++)) || true
            else
                echo -e "${GREEN}OK${NC}"
                ((REMOVED++)) || true
            fi
        done

        echo ""
        echo "Removed: $REMOVED rules"
        if [ $FAILED -gt 0 ]; then
            echo "Skipped: $FAILED rules (may have been removed manually)"
        fi
    fi

    # Remove config file
    rm -f "$CONFIG_FILE"
    echo ""
    echo "Removed config file: $CONFIG_FILE"
fi

# Verify cleanup
echo ""
echo "Verifying cleanup..."
echo ""

REMAINING_RULES=$(ethtool -u "$INTERFACE" 2>/dev/null | grep "Filter:" || echo "")
if [ -z "$REMAINING_RULES" ]; then
    echo -e "${GREEN}✓ All flow rules removed${NC}"
    echo ""
    echo "Traffic routing restored to default:"
    echo "  • All packets → Kernel network stack"
    echo "  • No dedicated queues for XDP"
    echo "  • Normal operation resumed ✓"
else
    echo -e "${YELLOW}Remaining flow rules:${NC}"
    ethtool -u "$INTERFACE" | grep -A2 "Filter:"
    echo ""
    if [ "$REMOVE_ALL" = false ]; then
        echo "Note: These may be rules created by other applications."
        echo "Use --all flag to remove all rules."
    fi
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Reset complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
