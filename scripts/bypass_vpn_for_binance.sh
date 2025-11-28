#!/bin/bash
# Temporarily bypass VPN for Binance traffic to test XDP on physical interface

set -e

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

ACTION="${1:-add}"

BINANCE_IPS=(
    "13.115.121.97"
    "3.115.176.195"
    "18.178.34.109"
    "54.168.254.133"
    "43.206.78.33"
    "3.114.160.13"
    "18.180.132.52"
    "35.79.182.144"
)

if [ "$ACTION" = "add" ]; then
    echo "Adding route exceptions to bypass VPN for Binance IPs..."
    echo ""

    for ip in "${BINANCE_IPS[@]}"; do
        # Add route through physical interface (enp108s0)
        ip route add "$ip" via 192.168.0.1 dev enp108s0 metric 50 2>/dev/null && \
            echo "✅ Added route: $ip via enp108s0" || \
            echo "⚠️  Route already exists: $ip"
    done

    echo ""
    echo "✅ Binance traffic will now go through enp108s0"
    echo ""
    echo "Verify with: ip route get 13.115.121.97"
    echo "Should show: dev enp108s0"

elif [ "$ACTION" = "remove" ]; then
    echo "Removing route exceptions (restoring VPN routing)..."
    echo ""

    for ip in "${BINANCE_IPS[@]}"; do
        ip route del "$ip" 2>/dev/null && \
            echo "✅ Removed route: $ip" || \
            echo "⚠️  Route doesn't exist: $ip"
    done

    echo ""
    echo "✅ Binance traffic restored to VPN"

else
    echo "Usage: $0 [add|remove]"
    echo ""
    echo "  add    - Bypass VPN for Binance (route through enp108s0)"
    echo "  remove - Restore VPN routing for Binance"
    exit 1
fi

echo ""
