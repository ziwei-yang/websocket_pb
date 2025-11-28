#!/bin/bash
# scripts/run_test.sh
# Convenience script to run WebSocket integration tests with different transport modes
#
# Usage:
#   ./scripts/run_test.sh socket [interface]
#   ./scripts/run_test.sh xdp [interface]
#   ./scripts/run_test.sh dpdk [port_id]

set -e

MODE=${1:-socket}
INTERFACE=${2:-eth0}
PORT_ID=${2:-0}

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 <mode> [interface|port_id]"
    echo ""
    echo "Modes:"
    echo "  socket    - BSD sockets (default, no special setup needed)"
    echo "  xdp       - XDP (AF_XDP) mode (requires libbpf, huge pages, root)"
    echo "  dpdk      - DPDK mode (requires DPDK setup, NIC binding, root)"
    echo ""
    echo "Examples:"
    echo "  $0 socket                    # Run BSD socket test"
    echo "  $0 xdp enp108s0              # Run XDP test on interface enp108s0"
    echo "  $0 dpdk 0                    # Run DPDK test on port 0"
    echo ""
    exit 1
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    print_usage
fi

echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     WebSocket Integration Test Runner                             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

case "$MODE" in
    socket|bsd)
        echo -e "${YELLOW}Mode:${NC} BSD Sockets (kernel networking)"
        echo -e "${YELLOW}Interface:${NC} Auto-selected by kernel routing table"
        echo ""

        # Build test
        echo "Building BSD socket test..."
        make test-binance

        # Run test
        echo ""
        echo "Running test..."
        ./build/test_binance_integration
        ;;

    xdp)
        echo -e "${YELLOW}Mode:${NC} XDP (AF_XDP)"
        echo -e "${YELLOW}Interface:${NC} $INTERFACE"
        echo ""

        # Check privileges
        if [ "$EUID" -ne 0 ] && ! capsh --print | grep -q cap_net_raw; then
            echo -e "${RED}Error: XDP requires root or CAP_NET_RAW + CAP_BPF${NC}"
            echo "Run with: sudo $0 xdp $INTERFACE"
            exit 1
        fi

        # Check huge pages
        HUGE_PAGES=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
        if [ "$HUGE_PAGES" -lt 256 ]; then
            echo -e "${YELLOW}Warning: Huge pages not configured (found: $HUGE_PAGES, need: 256+)${NC}"
            echo "Setting up huge pages..."
            sudo sh -c 'echo 256 > /proc/sys/vm/nr_hugepages'
        fi

        # Check interface exists
        if ! ip link show "$INTERFACE" &>/dev/null; then
            echo -e "${RED}Error: Interface $INTERFACE not found${NC}"
            echo "Available interfaces:"
            ip link show | grep -E '^[0-9]+:' | awk '{print "  - " $2}' | sed 's/:$//'
            exit 1
        fi

        # Build test
        echo "Building XDP test..."
        USE_XDP=1 make test-xdp-binance

        # Run test
        echo ""
        echo "Running test on interface $INTERFACE..."
        if [ "$EUID" -ne 0 ]; then
            ./build/test_xdp_binance_integration "$INTERFACE"
        else
            sudo ./build/test_xdp_binance_integration "$INTERFACE"
        fi
        ;;

    dpdk)
        echo -e "${YELLOW}Mode:${NC} DPDK (kernel bypass)"
        echo -e "${YELLOW}Port ID:${NC} $PORT_ID"
        echo ""

        # Check privileges
        if [ "$EUID" -ne 0 ]; then
            echo -e "${RED}Error: DPDK requires root privileges${NC}"
            echo "Run with: sudo $0 dpdk $PORT_ID"
            exit 1
        fi

        # Check DPDK setup
        if ! pkg-config --exists libdpdk; then
            echo -e "${RED}Error: DPDK not installed${NC}"
            echo "Install with: sudo apt install dpdk dpdk-dev"
            exit 1
        fi

        # Check huge pages
        HUGE_PAGES=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
        if [ "$HUGE_PAGES" -lt 512 ]; then
            echo -e "${YELLOW}Warning: Insufficient huge pages (found: $HUGE_PAGES, need: 512+)${NC}"
            echo "Configuring huge pages..."
            sudo dpdk-hugepages.py -p 2M -r 2G || sudo sh -c 'echo 1024 > /proc/sys/vm/nr_hugepages'
        fi

        # List DPDK ports
        echo "Checking DPDK-bound NICs..."
        if command -v dpdk-devbind.py &>/dev/null; then
            dpdk-devbind.py --status
        else
            echo -e "${YELLOW}dpdk-devbind.py not found, skipping NIC status check${NC}"
        fi

        # Build test
        echo ""
        echo "Building DPDK test..."
        USE_DPDK=1 make test-dpdk-binance

        # Run test
        echo ""
        echo "Running test on DPDK port $PORT_ID..."
        sudo ./build/test_dpdk_binance_integration
        ;;

    *)
        echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
        echo ""
        print_usage
        ;;
esac

echo ""
echo -e "${GREEN}Test completed!${NC}"
