#!/bin/bash
# Complete XDP + Userspace Stack Integration Test Runner
#
# This script orchestrates the complete testing workflow:
#   1. Check prerequisites (XDP support, root privileges)
#   2. Configure NIC flow steering (optional)
#   3. Build test executable
#   4. Run integration test
#   5. Cleanup flow rules
#
# Usage:
#   sudo ./scripts/test_xdp_complete_stack.sh [--setup-flow] [--cleanup]
#
# Flags:
#   --setup-flow    Configure flow steering before test
#   --cleanup       Remove flow rules after test
#   --no-build      Skip compilation step
#   --interface=X   Network interface (default: eth0)
#   --queue=X       Queue ID (default: 5)
#   --domain=X      Target domain (default: stream.binance.com)

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
INTERFACE="eth0"
QUEUE_ID=5
DOMAIN="stream.binance.com"
SETUP_FLOW=false
CLEANUP=false
NO_BUILD=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --setup-flow)
            SETUP_FLOW=true
            ;;
        --cleanup)
            CLEANUP=true
            ;;
        --no-build)
            NO_BUILD=true
            ;;
        --interface=*)
            INTERFACE="${arg#*=}"
            ;;
        --queue=*)
            QUEUE_ID="${arg#*=}"
            ;;
        --domain=*)
            DOMAIN="${arg#*=}"
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --setup-flow       Configure NIC flow steering before test"
            echo "  --cleanup          Remove flow rules after test"
            echo "  --no-build         Skip compilation step"
            echo "  --interface=NAME   Network interface (default: eth0)"
            echo "  --queue=ID         Queue ID (default: 5)"
            echo "  --domain=NAME      Target domain (default: stream.binance.com)"
            echo ""
            echo "Examples:"
            echo "  sudo $0 --setup-flow --cleanup"
            echo "  sudo $0 --interface=enp0s3 --queue=3"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Try: sudo $0 $@"
    exit 1
fi

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     XDP + Userspace TCP/IP Stack - Integration Test Runner           ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════
# Step 1: Check Prerequisites
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}Step 1: Checking prerequisites...${NC}"
echo ""

# Check if XDP libraries are installed
echo -n "  Checking libbpf... "
if pkg-config --exists libbpf; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "  Install with: sudo apt install libbpf-dev"
    exit 1
fi

echo -n "  Checking libxdp... "
if pkg-config --exists libxdp; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "  Install with: sudo apt install libxdp-dev"
    exit 1
fi

# Check if interface exists
echo -n "  Checking interface $INTERFACE... "
if ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "  Interface $INTERFACE not found"
    exit 1
fi

# Check if interface is up
if ! ip link show "$INTERFACE" | grep -q "state UP"; then
    echo -e "  ${YELLOW}Interface is down, bringing up...${NC}"
    ip link set "$INTERFACE" up
    sleep 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# Step 2: Setup Flow Steering (Optional)
# ═══════════════════════════════════════════════════════════════════════
if [ "$SETUP_FLOW" = true ]; then
    echo -e "${BLUE}Step 2: Setting up NIC flow steering...${NC}"
    echo ""

    if [ ! -f "./scripts/xdp_redirect_flow.sh" ]; then
        echo -e "${RED}Error: xdp_redirect_flow.sh not found${NC}"
        exit 1
    fi

    ./scripts/xdp_redirect_flow.sh "$DOMAIN" "$INTERFACE" "$QUEUE_ID"

    echo ""
else
    echo -e "${BLUE}Step 2: Skipping flow steering setup${NC}"
    echo "  (use --setup-flow to configure)"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# Step 3: Build Test Executable
# ═══════════════════════════════════════════════════════════════════════
if [ "$NO_BUILD" = false ]; then
    echo -e "${BLUE}Step 3: Building test executable...${NC}"
    echo ""

    BUILD_CMD="USE_XDP=1 make test-xdp-userspace-websocket"
    echo "  Build command: $BUILD_CMD"
    echo ""

    if $BUILD_CMD; then
        echo ""
        echo -e "${GREEN}  ✓ Build successful${NC}"
    else
        echo -e "${RED}  ✗ Build failed${NC}"
        exit 1
    fi

    echo ""
else
    echo -e "${BLUE}Step 3: Skipping build${NC}"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# Step 4: Run Integration Test
# ═══════════════════════════════════════════════════════════════════════
echo -e "${BLUE}Step 4: Running integration test...${NC}"
echo ""

TEST_BINARY="./build/test_xdp_userspace_websocket"

if [ ! -f "$TEST_BINARY" ]; then
    echo -e "${RED}Error: Test binary not found: $TEST_BINARY${NC}"
    echo "  Run without --no-build to compile it"
    exit 1
fi

# CPU core pinning (same as queue ID for best performance)
CPU_CORE=$QUEUE_ID

echo "  Test configuration:"
echo "    Interface:  $INTERFACE"
echo "    Queue:      $QUEUE_ID"
echo "    CPU core:   $CPU_CORE (pinned)"
echo "    Domain:     $DOMAIN"
echo ""
echo "  Running: taskset -c $CPU_CORE $TEST_BINARY $INTERFACE $QUEUE_ID"
echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────────────────────${NC}"
echo ""

# Run the test
if taskset -c "$CPU_CORE" "$TEST_BINARY" "$INTERFACE" "$QUEUE_ID"; then
    TEST_RESULT=0
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${GREEN}✓ Test completed successfully${NC}"
else
    TEST_RESULT=$?
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${RED}✗ Test failed with exit code $TEST_RESULT${NC}"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════
# Step 5: Cleanup Flow Rules (Optional)
# ═══════════════════════════════════════════════════════════════════════
if [ "$CLEANUP" = true ]; then
    echo -e "${BLUE}Step 5: Cleaning up flow rules...${NC}"
    echo ""

    if [ ! -f "./scripts/xdp_redirect_reset.sh" ]; then
        echo -e "${YELLOW}Warning: xdp_redirect_reset.sh not found${NC}"
    else
        ./scripts/xdp_redirect_reset.sh "$INTERFACE"
    fi

    echo ""
else
    echo -e "${BLUE}Step 5: Skipping cleanup${NC}"
    echo "  (use --cleanup to remove flow rules)"
    echo ""
    echo "  Flow rules are still active. To remove them:"
    echo "    sudo ./scripts/xdp_redirect_reset.sh $INTERFACE"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                           TEST SUMMARY                                ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Integration test passed${NC}"
    echo ""
    echo "Validated components:"
    echo "  ✓ XDP transport (AF_XDP, UMEM, ring buffers)"
    echo "  ✓ Userspace MAC layer (Ethernet)"
    echo "  ✓ Userspace ARP (gateway resolution)"
    echo "  ✓ Userspace IP layer (no fragmentation, no options)"
    echo "  ✓ Userspace TCP layer (3-way handshake, send/recv)"
    echo "  ✓ Zero-copy packet processing"
else
    echo -e "${RED}❌ Integration test failed${NC}"
    echo ""
    echo "Common issues:"
    echo "  • Interface not configured correctly"
    echo "  • Flow rules not set up (use --setup-flow)"
    echo "  • Permissions issue (run as root)"
    echo "  • Network connectivity problem"
    echo "  • Incompatible NIC driver"
fi

echo ""
echo "For more details, see:"
echo "  • doc/XDP_DATA_FLOW.md"
echo "  • doc/XDP_TRAFFIC_COEXISTENCE.md"
echo "  • scripts/README_XDP_FLOW.md"
echo ""

exit $TEST_RESULT
