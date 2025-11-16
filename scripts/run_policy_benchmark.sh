#!/usr/bin/env bash
# run_policy_benchmark.sh - Comprehensive policy benchmark for all SSL + IOBackend combinations
# Tests 9 combinations: 3 SSL policies × 3 IO backends

set -euo pipefail

# Configuration
WARMUP_COUNT=${WARMUP_COUNT:-50}
BENCHMARK_COUNT=${BENCHMARK_COUNT:-100}
CPU_CORE=${CPU_CORE:-1}
RESULTS_DIR="./benchmark_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$RESULTS_DIR/policy_benchmark_report_${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║         WebSocket Policy Benchmark Suite - All Combinations       ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Testing Matrix:"
echo "  SSL Policies:  OpenSSL (no kTLS), LibreSSL, WolfSSL"
echo "  IO Backends:   select, epoll, io_uring"
echo "  Total Tests:   9 combinations"
echo ""
echo "Configuration:"
echo "  Warmup count:     $WARMUP_COUNT messages"
echo "  Benchmark count:  $BENCHMARK_COUNT messages"
echo "  CPU affinity:     Core $CPU_CORE (taskset -c $CPU_CORE)"
echo "  Results dir:      $RESULTS_DIR"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to build with specific configuration
build_config() {
    local ssl_policy="$1"
    local io_backend="$2"
    local extra_flags="$3"

    echo -e "${BLUE}[BUILD]${NC} Building: SSL=$ssl_policy, IO=$io_backend"

    # Clean build
    make clean >/dev/null 2>&1

    # Build with specific configuration using make variables
    if make $extra_flags benchmark-binance >/dev/null 2>&1; then
        echo -e "${GREEN}[BUILD]${NC} Success"
        return 0
    else
        echo -e "${RED}[BUILD]${NC} Failed - trying fallback"
        # If build failed, it might be missing library - that's ok, we'll skip it
        return 1
    fi
}

# Function to run benchmark
run_benchmark() {
    local ssl_policy="$1"
    local io_backend="$2"
    local output_file="$3"

    echo -e "${BLUE}[TEST]${NC} Running benchmark..."

    # Run with taskset on specified core
    local cmd="taskset -c $CPU_CORE ./build/benchmark_binance $WARMUP_COUNT $BENCHMARK_COUNT"

    if timeout 120 $cmd > "$output_file" 2>&1; then
        echo -e "${GREEN}[TEST]${NC} Complete"
        return 0
    else
        echo -e "${RED}[TEST]${NC} Failed or timeout"
        return 1
    fi
}

# Function to extract statistics from benchmark output
extract_stats() {
    local output_file="$1"

    # Extract Stage 2→6 (application processing) statistics
    local stage2_6=$(grep "Total (Stage 2→6)" "$output_file" 2>/dev/null | awk '{print $5, $6, $7, $8, $9}')

    # Extract individual stages
    local stage1_2=$(grep "Stage 1→2" "$output_file" 2>/dev/null | awk '{print $5, $6, $7}')
    local stage3_4=$(grep "Stage 3→4" "$output_file" 2>/dev/null | awk '{print $4, $5, $6}')
    local stage4_5=$(grep "Stage 4→5" "$output_file" 2>/dev/null | awk '{print $4, $5, $6}')

    # Extract end-to-end
    local e2e=$(grep "End-to-End" "$output_file" 2>/dev/null | awk '{print $3, $4, $5}')

    # Extract policy info
    local tls_policy=$(grep "TLS Policy:" "$output_file" 2>/dev/null | head -1 | awk -F': ' '{print $2}')
    local io_backend=$(grep "IO Backend:" "$output_file" 2>/dev/null | head -1 | awk -F': ' '{print $2}')

    echo "$stage2_6|$stage1_2|$stage3_4|$stage4_5|$e2e|$tls_policy|$io_backend"
}

# Test configurations
# Format: "SSL_POLICY|IO_BACKEND|MAKE_FLAGS"
CONFIGS=(
    # OpenSSL combinations
    "OpenSSL|select|USE_OPENSSL=1 USE_IOURING=0 USE_SELECT=1"
    "OpenSSL|epoll|USE_OPENSSL=1 USE_IOURING=0"
    "OpenSSL|io_uring|USE_OPENSSL=1 USE_IOURING=1"

    # WolfSSL combinations
    "WolfSSL|select|USE_WOLFSSL=1 USE_IOURING=0 USE_SELECT=1"
    "WolfSSL|epoll|USE_WOLFSSL=1 USE_IOURING=0"
    "WolfSSL|io_uring|USE_WOLFSSL=1 USE_IOURING=1"

    # LibreSSL combinations
    "LibreSSL|select|USE_LIBRESSL=1 USE_IOURING=0 USE_SELECT=1"
    "LibreSSL|epoll|USE_LIBRESSL=1 USE_IOURING=0"
    "LibreSSL|io_uring|USE_LIBRESSL=1 USE_IOURING=1"
)

# Run all benchmarks
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "Starting benchmark suite..."
echo "════════════════════════════════════════════════════════════════════"
echo ""

results=()
test_num=0

for config in "${CONFIGS[@]}"; do
    test_num=$((test_num + 1))
    IFS='|' read -r ssl_policy io_backend make_flags <<< "$config"

    echo -e "${YELLOW}[TEST $test_num/9]${NC} SSL=$ssl_policy, IO=$io_backend"
    echo "─────────────────────────────────────────────────────────────────"

    output_file="$RESULTS_DIR/${ssl_policy}_${io_backend}_${TIMESTAMP}.log"

    # Build
    if ! build_config "$ssl_policy" "$io_backend" "$make_flags"; then
        echo -e "${RED}[SKIP]${NC} Build failed, skipping test"
        results+=("$ssl_policy|$io_backend|BUILD_FAILED")
        echo ""
        continue
    fi

    # Run benchmark
    if ! run_benchmark "$ssl_policy" "$io_backend" "$output_file"; then
        echo -e "${RED}[SKIP]${NC} Benchmark failed"
        results+=("$ssl_policy|$io_backend|TEST_FAILED")
        echo ""
        continue
    fi

    # Extract and save results
    stats=$(extract_stats "$output_file")
    results+=("$ssl_policy|$io_backend|$stats")

    echo -e "${GREEN}[DONE]${NC} Results saved to: $output_file"
    echo ""
done

# Generate report
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "Generating comprehensive report..."
echo "════════════════════════════════════════════════════════════════════"
echo ""

cat > "$REPORT_FILE" << 'EOF_HEADER'
╔════════════════════════════════════════════════════════════════════╗
║     WebSocket Policy Benchmark Report - All Combinations          ║
╚════════════════════════════════════════════════════════════════════╝

EOF_HEADER

# Add configuration info
cat >> "$REPORT_FILE" << EOF
Test Configuration:
  Date:              $(date)
  Warmup messages:   $WARMUP_COUNT
  Benchmark messages: $BENCHMARK_COUNT
  CPU affinity:      Core $CPU_CORE (taskset -c $CPU_CORE)
  Platform:          $(uname -s) $(uname -r)
  CPU:               $(lscpu | grep "Model name" | cut -d':' -f2 | xargs)

════════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY - Application Processing (Stage 2→6)
═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

| SSL Policy | IO Backend  | Min (μs) | Max (μs) | Mean (μs) | Median (μs) | P99 (μs) | Status |
|------------|-------------|----------|----------|-----------|-------------|----------|--------|
EOF

# Parse results and add to summary
for result in "${results[@]}"; do
    IFS='|' read -r ssl io stage2_6 rest <<< "$result"

    if [[ "$stage2_6" == "BUILD_FAILED" || "$stage2_6" == "TEST_FAILED" ]]; then
        printf "| %-10s | %-11s | %-8s | %-8s | %-9s | %-11s | %-8s | FAILED |\n" \
            "$ssl" "$io" "-" "-" "-" "-" "-" >> "$REPORT_FILE"
    else
        IFS=' ' read -r min max mean median stddev <<< "$stage2_6"
        # Extract P99 from detailed data if available
        printf "| %-10s | %-11s | %8s | %8s | %9s | %11s | %8s | ✓      |\n" \
            "$ssl" "$io" "${min:-N/A}" "${max:-N/A}" "${mean:-N/A}" "${median:-N/A}" "${stddev:-N/A}" >> "$REPORT_FILE"
    fi
done

cat >> "$REPORT_FILE" << 'EOF_MID'

════════════════════════════════════════════════════════════════════

DETAILED STAGE BREAKDOWN
════════════════════════════════════════════════════════════════════

EOF_MID

# Add detailed breakdown for each successful test
test_num=0
for result in "${results[@]}"; do
    test_num=$((test_num + 1))
    IFS='|' read -r ssl io stage2_6 stage1_2 stage3_4 stage4_5 e2e tls_pol io_back <<< "$result"

    cat >> "$REPORT_FILE" << EOF

[$test_num] SSL: $ssl | IO Backend: $io
─────────────────────────────────────────────────────────────────────────────
EOF

    if [[ "$stage2_6" == "BUILD_FAILED" || "$stage2_6" == "TEST_FAILED" ]]; then
        echo "  Status: Test failed or skipped" >> "$REPORT_FILE"
    else
        cat >> "$REPORT_FILE" << EOF
  Detected Config: $tls_pol / $io_back

  Application Processing (Stage 2→6): $stage2_6 μs
  NIC→App latency (Stage 1→2):        $stage1_2 μs
  SSL decrypt (Stage 3→4):            $stage3_4 μs
  WS parse (Stage 4→5):               $stage4_5 μs
  End-to-End (Stage 1→6):             $e2e μs

EOF
    fi
done

# Add analysis section
cat >> "$REPORT_FILE" << 'EOF_ANALYSIS'

════════════════════════════════════════════════════════════════════

PERFORMANCE ANALYSIS
════════════════════════════════════════════════════════════════════

Key Insights:

1. SSL Policy Impact:
   - Compare OpenSSL vs LibreSSL vs WolfSSL across same IO backend
   - Focus on Stage 3→4 (SSL decryption) latency

2. IO Backend Impact:
   - Compare select vs epoll vs io_uring with same SSL policy
   - Focus on Stage 2→6 (overall application processing)

3. Optimal Configuration:
   - Lowest mean latency (Stage 2→6)
   - Lowest P99 latency
   - Most consistent performance (lowest StdDev)

════════════════════════════════════════════════════════════════════

RAW DATA FILES
════════════════════════════════════════════════════════════════════

EOF_ANALYSIS

# List all log files
for result in "${results[@]}"; do
    IFS='|' read -r ssl io rest <<< "$result"
    log_file="$RESULTS_DIR/${ssl}_${io}_${TIMESTAMP}.log"
    if [[ -f "$log_file" ]]; then
        echo "  ${ssl}_${io}: $log_file" >> "$REPORT_FILE"
    fi
done

echo "" >> "$REPORT_FILE"
echo "════════════════════════════════════════════════════════════════════" >> "$REPORT_FILE"
echo "Report generated: $(date)" >> "$REPORT_FILE"
echo "════════════════════════════════════════════════════════════════════" >> "$REPORT_FILE"

# Display report
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Report generated successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Report file: $REPORT_FILE"
echo ""
echo "Quick summary:"
cat "$REPORT_FILE" | grep -A 20 "EXECUTIVE SUMMARY"
echo ""
echo "View full report:"
echo "  cat $REPORT_FILE"
echo "  less $REPORT_FILE"
echo ""
