#!/bin/bash
# enable_hw_timestamp.sh
# Quick setup script for enabling hardware NIC timestamping

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Hardware NIC Timestamping Setup Script                     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_usage() {
    echo "Usage: sudo $0 <interface>"
    echo ""
    echo "Example:"
    echo "  sudo $0 eth0"
    echo ""
    echo "To find your active interface:"
    echo "  ip route get 8.8.8.8 | grep -oP 'dev \K\S+'"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ Error: This script must be run as root${NC}"
        echo -e "   Try: sudo $0 $1"
        exit 1
    fi
}

check_interface() {
    local iface=$1

    if ! ip link show "$iface" &> /dev/null; then
        echo -e "${RED}❌ Error: Interface '$iface' not found${NC}"
        echo ""
        echo "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  - " $2}'
        exit 1
    fi
}

check_capabilities() {
    local iface=$1

    echo -e "${BLUE}🔍 Step 1: Checking NIC capabilities...${NC}"

    if ! command -v ethtool &> /dev/null; then
        echo -e "${YELLOW}⚠️  ethtool not found. Installing...${NC}"
        apt-get update -qq && apt-get install -y ethtool
    fi

    echo ""
    ethtool -T "$iface"
    echo ""

    # Check if hardware timestamping is supported
    if ethtool -T "$iface" 2>&1 | grep -q "SOF_TIMESTAMPING_RX_HARDWARE"; then
        echo -e "${GREEN}✅ Hardware RX timestamping: SUPPORTED${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Hardware RX timestamping: NOT SUPPORTED${NC}"
        echo -e "   This NIC only supports software timestamping"
        return 1
    fi
}

enable_timestamping() {
    local iface=$1

    echo -e "${BLUE}🔧 Step 2: Enabling hardware timestamping...${NC}"

    if ethtool -K "$iface" rx-timestamping on 2>&1; then
        echo -e "${GREEN}✅ Hardware timestamping enabled${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not enable hardware timestamping (may not be supported)${NC}"
    fi

    echo ""
    echo "Current settings:"
    ethtool -k "$iface" | grep timestamping
    echo ""
}

check_ptp() {
    echo -e "${BLUE}🔍 Step 3: Checking PTP hardware clock...${NC}"

    if ls /dev/ptp* &> /dev/null; then
        echo -e "${GREEN}✅ PTP device(s) found:${NC}"
        ls -la /dev/ptp*
    else
        echo -e "${YELLOW}⚠️  No PTP device found (hardware clock not available)${NC}"
    fi
    echo ""
}

check_kernel() {
    echo -e "${BLUE}🔍 Step 4: Checking kernel version...${NC}"

    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)

    echo "Kernel: $(uname -r)"

    if [ "$major" -gt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -ge 4 ]); then
        echo -e "${GREEN}✅ Kernel version supports hardware timestamping (5.4+ recommended)${NC}"
    elif [ "$major" -ge 4 ]; then
        echo -e "${YELLOW}⚠️  Kernel supports timestamping but upgrade recommended (current: $kernel_version, recommended: 5.4+)${NC}"
    else
        echo -e "${RED}❌ Kernel too old for hardware timestamping (minimum: 3.17, current: $kernel_version)${NC}"
    fi
    echo ""
}

print_test_instructions() {
    local iface=$1

    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ Setup Complete - Testing Instructions                             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "To test hardware timestamping:"
    echo ""
    echo -e "${GREEN}1. Build the test program:${NC}"
    echo "   make test-nic-timestamp"
    echo ""
    echo -e "${GREEN}2. Run the UDP receiver with hardware timestamps:${NC}"
    echo "   sudo ./build/test_nic_timestamp $iface 8888"
    echo ""
    echo -e "${GREEN}3. In another terminal, send test packets:${NC}"
    echo "   echo 'test packet' | nc -u localhost 8888"
    echo ""
    echo -e "${GREEN}4. You should see output like:${NC}"
    echo "   📦 Received packet #1 (12 bytes) from 127.0.0.1:xxxxx"
    echo "   📅 Software timestamp: 123456.789012345 s"
    echo "   ⚡ Hardware timestamp: 123456.789012120 s"
    echo "   ⏱️  SW - HW Delta:     225 ns (0.225 μs)"
    echo ""
    echo -e "${YELLOW}Note: If hardware timestamp shows 'Not available', your NIC${NC}"
    echo -e "${YELLOW}      only supports software timestamps (still useful!)${NC}"
    echo ""
}

print_limitations() {
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║ Important Limitations                                              ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}❌ Hardware NIC timestamps DO NOT work through:${NC}"
    echo "   - SSL/TLS connections (HTTPS, WSS)"
    echo "   - SSH tunnels"
    echo "   - VPNs"
    echo "   - Virtual machines (VMware, VirtualBox, KVM)"
    echo "   - Cloud instances (AWS, Azure, GCP)"
    echo "   - Docker containers"
    echo ""
    echo -e "${GREEN}✅ Hardware NIC timestamps work with:${NC}"
    echo "   - Raw sockets"
    echo "   - Plain UDP"
    echo "   - Unencrypted TCP"
    echo "   - Physical hardware only"
    echo ""
    echo -e "${BLUE}💡 For WebSocket with SSL/TLS (current implementation):${NC}"
    echo "   Use software timestamps at kernel wakeup (already implemented)"
    echo "   Provides ~100-1000ns precision, sufficient for most HFT"
    echo ""
}

# Main execution
main() {
    print_header

    if [ $# -lt 1 ]; then
        print_usage
        exit 1
    fi

    local iface=$1

    check_root "$iface"
    check_interface "$iface"
    check_kernel

    local hw_supported=false
    if check_capabilities "$iface"; then
        hw_supported=true
        enable_timestamping "$iface"
    fi

    check_ptp
    print_test_instructions "$iface"
    print_limitations

    if [ "$hw_supported" = true ]; then
        echo -e "${GREEN}✅ Setup complete! Hardware timestamping is enabled on $iface${NC}"
    else
        echo -e "${YELLOW}⚠️  Setup complete with software timestamps only on $iface${NC}"
    fi
    echo ""
}

main "$@"
