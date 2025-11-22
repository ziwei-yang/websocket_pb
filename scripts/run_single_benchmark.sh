#!/usr/bin/env bash
# run_single_benchmark.sh - Run benchmark for a specific policy combination
#
# Usage:
#   ./scripts/run_single_benchmark.sh [-c core] <ssl_policy> <io_backend> [warmup] [benchmark]
#
# Options:
#   -c core    CPU core to pin to (default: 1)
#
# Examples:
#   ./scripts/run_single_benchmark.sh libressl io_uring
#   ./scripts/run_single_benchmark.sh -c 2 LibreSSL io_uring 50 100
#   ./scripts/run_single_benchmark.sh -c 0 openssl epoll 100 300

set -euo pipefail

# Default values
CPU_CORE="${CPU_CORE:-1}"

# Parse options
while getopts "c:h" opt; do
    case $opt in
        c)
            CPU_CORE="$OPTARG"
            ;;
        h)
            echo "Usage: $0 [-c core] <ssl_policy> <io_backend> [warmup] [benchmark]"
            echo ""
            echo "Options:"
            echo "  -c core    CPU core to pin to (default: 1)"
            echo ""
            echo "Arguments:"
            echo "  ssl_policy      OpenSSL, LibreSSL, or WolfSSL (case-insensitive)"
            echo "  io_backend      select, epoll, or io_uring (case-insensitive)"
            echo "  warmup          Number of warmup messages (default: 50)"
            echo "  benchmark       Number of benchmark messages (default: 100)"
            echo ""
            echo "Examples:"
            echo "  $0 libressl io_uring"
            echo "  $0 -c 2 LibreSSL io_uring 50 100"
            echo "  $0 -c 0 openssl epoll 100 300"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# Parse positional arguments
SSL_POLICY_RAW="${1:-LibreSSL}"
IO_BACKEND_RAW="${2:-io_uring}"
WARMUP_COUNT="${3:-50}"
BENCHMARK_COUNT="${4:-100}"

# Normalize to proper case (case-insensitive input)
# Convert to lowercase first, then capitalize appropriately
SSL_POLICY_LOWER=$(echo "$SSL_POLICY_RAW" | tr '[:upper:]' '[:lower:]')
case "$SSL_POLICY_LOWER" in
    openssl)
        SSL_POLICY="OpenSSL"
        ;;
    libressl)
        SSL_POLICY="LibreSSL"
        ;;
    wolfssl)
        SSL_POLICY="WolfSSL"
        ;;
    *)
        echo "Error: SSL_POLICY must be OpenSSL, LibreSSL, or WolfSSL (got: $SSL_POLICY_RAW)"
        exit 1
        ;;
esac

IO_BACKEND_LOWER=$(echo "$IO_BACKEND_RAW" | tr '[:upper:]' '[:lower:]')
case "$IO_BACKEND_LOWER" in
    select|epoll|io_uring)
        IO_BACKEND="$IO_BACKEND_LOWER"
        ;;
    *)
        echo "Error: IO_BACKEND must be select, epoll, or io_uring (got: $IO_BACKEND_RAW)"
        exit 1
        ;;
esac

# Determine build flags
BUILD_FLAGS=""

case "$SSL_POLICY" in
    OpenSSL)
        BUILD_FLAGS="USE_OPENSSL=1"
        ;;
    LibreSSL)
        BUILD_FLAGS="USE_LIBRESSL=1"
        ;;
    WolfSSL)
        BUILD_FLAGS="USE_WOLFSSL=1"
        ;;
esac

case "$IO_BACKEND" in
    select)
        BUILD_FLAGS="$BUILD_FLAGS USE_IOURING=0 USE_SELECT=1"
        ;;
    epoll)
        BUILD_FLAGS="$BUILD_FLAGS USE_IOURING=0"
        ;;
    io_uring)
        BUILD_FLAGS="$BUILD_FLAGS USE_IOURING=1"
        ;;
esac

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║         Single Policy Benchmark - Custom Configuration            ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  SSL Policy:       $SSL_POLICY"
echo "  IO Backend:       $IO_BACKEND"
echo "  Warmup count:     $WARMUP_COUNT messages"
echo "  Benchmark count:  $BENCHMARK_COUNT messages"
echo "  CPU affinity:     Core $CPU_CORE (taskset -c $CPU_CORE)"
echo "  Build flags:      $BUILD_FLAGS"
echo ""

# Clean build
echo "🧹 Cleaning previous build..."
make clean >/dev/null 2>&1

# Build with specific configuration
echo "🔨 Building: $SSL_POLICY + $IO_BACKEND..."
if ! make $BUILD_FLAGS benchmark-binance >/dev/null 2>&1; then
    echo "❌ Build failed!"
    echo ""
    echo "Possible reasons:"
    echo "  - Missing library (install lib${SSL_POLICY,,}-dev)"
    echo "  - io_uring not available (kernel < 5.1)"
    echo ""
    exit 1
fi

echo "✅ Build successful"
echo ""

# Run benchmark
echo "🚀 Running benchmark..."
echo "────────────────────────────────────────────────────────────────────"
echo ""

if taskset -c "$CPU_CORE" ./build/benchmark_binance "$WARMUP_COUNT" "$BENCHMARK_COUNT"; then
    echo ""
    echo "────────────────────────────────────────────────────────────────────"
    echo "✅ Benchmark complete!"
    echo ""
    echo "To save results to file:"
    echo "  taskset -c $CPU_CORE ./build/benchmark_binance $WARMUP_COUNT $BENCHMARK_COUNT > results.txt"
    echo ""
else
    echo ""
    echo "❌ Benchmark failed or timed out"
    exit 1
fi
