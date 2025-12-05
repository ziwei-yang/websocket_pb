#!/bin/bash
# test_benchmark_binance.sh
# Build and run Binance WebSocket latency benchmark
#
# Usage:
#   ./bin/test_benchmark_binance.sh                           # BSD socket mode (default)
#   ./bin/test_benchmark_binance.sh USE_XDP=1                 # XDP mode with defaults
#   ./bin/test_benchmark_binance.sh USE_XDP=1 USE_OPENSSL=1   # XDP + OpenSSL
#   ./bin/test_benchmark_binance.sh USE_XDP=1 interface=eth0  # XDP with custom interface
#
# Arguments (order-independent):
#   USE_XDP=1       - Enable XDP zero-copy mode (requires sudo)
#   USE_OPENSSL=1   - Use OpenSSL (default if no SSL lib specified)
#   USE_LIBRESSL=1  - Use LibreSSL
#   USE_WOLFSSL=1   - Use WolfSSL
#   interface=NAME  - Network interface for XDP mode (default: enp108s0)
#   warmup=N        - Number of warmup messages (default: 100)
#   benchmark=N     - Number of benchmark messages (default: 300)
#   cpu=N           - CPU core to pin (default: 1)

set -e

# Default values
USE_XDP=0
USE_OPENSSL=0
USE_LIBRESSL=0
USE_WOLFSSL=0
INTERFACE="enp108s0"
WARMUP=100
BENCHMARK=300
CPU_CORE=1

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        USE_XDP=1)
            USE_XDP=1
            ;;
        USE_OPENSSL=1)
            USE_OPENSSL=1
            ;;
        USE_LIBRESSL=1)
            USE_LIBRESSL=1
            ;;
        USE_WOLFSSL=1)
            USE_WOLFSSL=1
            ;;
        interface=*)
            INTERFACE="${arg#interface=}"
            ;;
        warmup=*)
            WARMUP="${arg#warmup=}"
            ;;
        benchmark=*)
            BENCHMARK="${arg#benchmark=}"
            ;;
        cpu=*)
            CPU_CORE="${arg#cpu=}"
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [USE_XDP=1] [USE_OPENSSL=1] [USE_LIBRESSL=1] [USE_WOLFSSL=1] [interface=NAME] [warmup=N] [benchmark=N] [cpu=N]"
            exit 1
            ;;
    esac
done

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[OK]${NC} $1"; }
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Build environment variables
BUILD_ENV=""
if [[ "$USE_XDP" == "1" ]]; then
    BUILD_ENV="USE_XDP=1"
fi
if [[ "$USE_OPENSSL" == "1" ]]; then
    BUILD_ENV="$BUILD_ENV USE_OPENSSL=1"
fi
if [[ "$USE_LIBRESSL" == "1" ]]; then
    BUILD_ENV="$BUILD_ENV USE_LIBRESSL=1"
fi
if [[ "$USE_WOLFSSL" == "1" ]]; then
    BUILD_ENV="$BUILD_ENV USE_WOLFSSL=1"
fi

echo ""
echo "========================================"
echo "  Binance WebSocket Latency Benchmark"
echo "========================================"
echo ""

if [[ "$USE_XDP" == "1" ]]; then
    print_info "Mode: XDP Zero-Copy (AF_XDP)"
    print_info "Interface: $INTERFACE"
else
    print_info "Mode: BSD Sockets"
fi
print_info "Warmup: $WARMUP messages"
print_info "Benchmark: $BENCHMARK messages"
print_info "CPU Core: $CPU_CORE"
echo ""

# Step 1: Clean and build
print_info "Step 1: Building benchmark..."
if [[ -n "$BUILD_ENV" ]]; then
    eval "$BUILD_ENV make clean" >/dev/null 2>&1
else
    make clean >/dev/null 2>&1
fi

if [[ "$USE_XDP" == "1" ]]; then
    # Build BPF object and benchmark binary
    eval "$BUILD_ENV make src/xdp/bpf/exchange_filter.bpf.o build/benchmark_binance" 2>&1 | tail -5
else
    # Build benchmark binary only
    if [[ -n "$BUILD_ENV" ]]; then
        eval "$BUILD_ENV make build/benchmark_binance" 2>&1 | tail -3
    else
        make build/benchmark_binance 2>&1 | tail -3
    fi
fi

if [[ ! -f "./build/benchmark_binance" ]]; then
    print_error "Build failed: ./build/benchmark_binance not found"
    exit 1
fi
print_status "Build complete"

# XDP-specific setup
if [[ "$USE_XDP" == "1" ]]; then
    # Check if running as root or can sudo
    if [[ $EUID -ne 0 ]]; then
        print_info "XDP mode requires root privileges"
    fi

    # Step 2: Prepare XDP environment
    print_info "Step 2: Preparing XDP environment..."
    sudo ./scripts/xdp_prepare.sh "$INTERFACE" 2>&1 | grep -E "^\[OK\]|^\[WARN\]|^\[ERROR\]" || true
    print_status "XDP environment prepared"

    # Step 3: Setup DNS/routing filter
    print_info "Step 3: Setting up DNS/routing filter..."
    sudo ./scripts/xdp_filter.sh "$INTERFACE" stream.binance.com 2>&1 | grep -E "^\[OK\]|^\[WARN\]|^\[ERROR\]|Primary IP" || true
    print_status "Filter configured"

    # Step 4: Run benchmark with sudo
    echo ""
    print_info "Step 4: Running XDP benchmark..."
    echo "========================================"
    sudo taskset -c "$CPU_CORE" ./build/benchmark_binance "$INTERFACE" "$WARMUP" "$BENCHMARK"

else
    # BSD socket mode - run directly
    echo ""
    print_info "Step 2: Running BSD socket benchmark..."
    echo "========================================"
    taskset -c "$CPU_CORE" ./build/benchmark_binance "$WARMUP" "$BENCHMARK"
fi

echo ""
print_status "Benchmark complete"
