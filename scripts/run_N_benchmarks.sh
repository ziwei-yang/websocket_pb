#!/usr/bin/env bash
# run_N_benchmarks.sh - Run N benchmark iterations and save results

set -euo pipefail

# Configuration
N_RUNS=${1:-50}
CPU_CORE=${CPU_CORE:-1}
RESULTS_DIR="./benchmark_results"
BATCH_ID=$(date +%Y%m%d_%H%M%S)
TIMESTAMPS_FILE="$RESULTS_DIR/batch_${BATCH_ID}_timestamps.txt"
LOG_FILE="$RESULTS_DIR/batch_${BATCH_ID}_log.txt"

echo "╔════════════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║     Running $N_RUNS Benchmark Iterations on CPU Core $CPU_CORE              ║" | tee -a "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Batch ID: $BATCH_ID" | tee -a "$LOG_FILE"
echo "Start time: $(date)" | tee -a "$LOG_FILE"
echo "Estimated duration: ~$((N_RUNS * 3)) minutes" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

> "$TIMESTAMPS_FILE"  # Clear timestamps file

for i in $(seq 1 $N_RUNS); do
    echo "────────────────────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
    echo "[RUN $i/$N_RUNS] Starting at $(date +%H:%M:%S)" | tee -a "$LOG_FILE"
    
    # Run benchmark silently, extract only the report timestamp
    REPORT_LINE=$(CPU_CORE=$CPU_CORE ./scripts/run_policy_benchmark.sh 2>&1 | grep "Report file:")
    TIMESTAMP=$(echo "$REPORT_LINE" | grep -oP '\d{8}_\d{6}' | head -1)
    
    if [[ -n "$TIMESTAMP" ]]; then
        echo "$TIMESTAMP" >> "$TIMESTAMPS_FILE"
        echo "[RUN $i/$N_RUNS] ✓ Complete - $TIMESTAMP" | tee -a "$LOG_FILE"
    else
        echo "[RUN $i/$N_RUNS] ✗ WARNING - Could not extract timestamp" | tee -a "$LOG_FILE"
    fi
    
    # Progress indicator
    PERCENT=$((i * 100 / N_RUNS))
    ELAPSED=$((i * 3))
    REMAINING=$(((N_RUNS - i) * 3))
    echo "Progress: $i/$N_RUNS ($PERCENT%) | Elapsed: ~${ELAPSED}min | Remaining: ~${REMAINING}min" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
done

echo "════════════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo "✅ All $N_RUNS runs completed at $(date)" | tee -a "$LOG_FILE"
echo "Timestamps saved to: $TIMESTAMPS_FILE" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "════════════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"

# Run analysis if Python script exists
if [[ -f "./scripts/analyze_batch.py" ]]; then
    echo "" | tee -a "$LOG_FILE"
    echo "Running statistical analysis..." | tee -a "$LOG_FILE"
    python3 ./scripts/analyze_batch.py "$TIMESTAMPS_FILE" | tee -a "$LOG_FILE"
fi
