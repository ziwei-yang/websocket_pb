#!/usr/bin/env bash
# monitor_and_analyze.sh - Monitor 50-run batch and auto-analyze when complete

set -euo pipefail

BATCH_ID="20251116_203443"
TIMESTAMPS_FILE="./benchmark_results/batch_${BATCH_ID}_timestamps.txt"
LOG_FILE="./benchmark_results/batch_${BATCH_ID}_log.txt"
ANALYSIS_OUTPUT="./benchmark_results/50_RUN_ANALYSIS_${BATCH_ID}.txt"

CHECK_INTERVAL=300  # Check every 5 minutes
MAX_CHECKS=36       # Max 3 hours of monitoring

echo "════════════════════════════════════════════════════════════════════"
echo "  Automated 50-Run Benchmark Monitor"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "Batch ID: $BATCH_ID"
echo "Check interval: ${CHECK_INTERVAL}s (5 minutes)"
echo "Max monitoring time: $((MAX_CHECKS * CHECK_INTERVAL / 60)) minutes"
echo ""

for ((check=1; check<=MAX_CHECKS; check++)); do
    # Check if benchmarks are still running
    if ! ps aux | grep -E "run_N_benchmarks|run_policy_benchmark" | grep -v grep > /dev/null; then
        echo "[$check] $(date +%H:%M:%S) - Benchmarks appear to have stopped"

        # Check completion
        if [[ -f "$TIMESTAMPS_FILE" ]]; then
            COMPLETED=$(wc -l < "$TIMESTAMPS_FILE")
            echo "[$check] Completed runs: $COMPLETED/50"

            if [[ $COMPLETED -eq 50 ]]; then
                echo ""
                echo "✅ All 50 runs COMPLETE! Running statistical analysis..."
                echo ""

                # Run analysis and save to file
                python3 ./scripts/analyze_batch.py "$TIMESTAMPS_FILE" | tee "$ANALYSIS_OUTPUT"

                echo ""
                echo "════════════════════════════════════════════════════════════════════"
                echo "📊 Analysis complete! Results saved to:"
                echo "    $ANALYSIS_OUTPUT"
                echo "════════════════════════════════════════════════════════════════════"
                exit 0
            else
                echo "⚠️ WARNING: Only $COMPLETED/50 runs completed"
                echo "Running partial analysis..."
                python3 ./scripts/analyze_batch.py "$TIMESTAMPS_FILE" | tee "${ANALYSIS_OUTPUT}.partial"
                exit 1
            fi
        else
            echo "❌ ERROR: No timestamps file found"
            exit 1
        fi
    fi

    # Still running - show progress
    if [[ -f "$TIMESTAMPS_FILE" ]]; then
        COMPLETED=$(wc -l < "$TIMESTAMPS_FILE")
        PERCENT=$((COMPLETED * 100 / 50))
        REMAINING=$((50 - COMPLETED))
        EST_REMAINING=$((REMAINING * 3))

        echo "[$check] $(date +%H:%M:%S) - Progress: $COMPLETED/50 ($PERCENT%) | Est. remaining: ~${EST_REMAINING}min"
    else
        echo "[$check] $(date +%H:%M:%S) - Starting..."
    fi

    # Wait before next check (unless last check)
    if [[ $check -lt $MAX_CHECKS ]]; then
        sleep $CHECK_INTERVAL
    fi
done

echo ""
echo "⚠️ Monitoring timeout reached after $MAX_CHECKS checks"
echo "   Benchmarks may still be running. Check manually with:"
echo "   ./scripts/check_batch_status.sh"
