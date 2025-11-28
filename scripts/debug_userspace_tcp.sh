#!/bin/bash
# Debug script for userspace TCP connection hang

set -e

INTERFACE="${1:-enp108s0}"

echo "======================================================================"
echo "  Debugging Userspace TCP Connection Hang"
echo "======================================================================"
echo ""
echo "Interface: $INTERFACE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Build with debug flags
echo "[1/4] Building test with debug symbols..."
g++ -std=c++17 -g -O0 -I./src -DUSE_OPENSSL -DUSE_XDP \
  -o build/xdp_binance_debug test/integration/xdp_binance.cpp \
  -lssl -lcrypto -lbpf -lxdp -lpthread

if [ $? -ne 0 ]; then
    echo "ERROR: Compilation failed"
    exit 1
fi
echo "✅ Build successful"
echo ""

# Check XDP/BPF setup
echo "[2/4] Checking XDP/BPF environment..."
if ! command -v bpftool &> /dev/null; then
    echo "⚠️  WARNING: bpftool not found, can't verify BPF programs"
else
    echo "BPF programs currently loaded:"
    bpftool prog show 2>/dev/null | head -20 || echo "  (none or permission denied)"
fi
echo ""

# Check interface status
echo "[3/4] Checking interface status..."
echo "Interface: $INTERFACE"
ip link show "$INTERFACE" 2>/dev/null || echo "⚠️  WARNING: Interface not found"
echo ""
echo "XDP programs attached:"
ip link show "$INTERFACE" 2>/dev/null | grep -i xdp || echo "  (none)"
echo ""

# Run test with strace to see system calls
echo "[4/4] Running test with timeout and packet capture..."
echo ""
echo "Starting test (60 second timeout)..."
echo "Press Ctrl+C to stop early"
echo ""
echo "======================================================================"
echo ""

# Run with timeout and capture output
timeout 60 stdbuf -oL -eL ./build/xdp_binance_debug "$INTERFACE" 2>&1 | tee /tmp/xdp_debug_output.txt

echo ""
echo "======================================================================"
echo ""
echo "Test completed or timed out"
echo "Output saved to: /tmp/xdp_debug_output.txt"
echo ""

# Analyze output
echo "Analyzing output..."
if grep -q "Phase 3: SSL/TLS Handshake" /tmp/xdp_debug_output.txt; then
    echo "✅ TCP connection succeeded (reached Phase 3)"
elif grep -q "Connecting to.*via userspace TCP" /tmp/xdp_debug_output.txt; then
    echo "❌ TCP connection hung at connection phase"
    echo ""
    echo "Last 20 lines of output:"
    tail -20 /tmp/xdp_debug_output.txt
else
    echo "⚠️  Test did not reach connection phase"
fi

echo ""
echo "======================================================================"
