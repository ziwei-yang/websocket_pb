#!/usr/bin/env bash
# check_batch_status.sh - Check status of running batch benchmark and show results if complete

set -euo pipefail

BATCH_ID="20251116_203443"
TIMESTAMPS_FILE="./benchmark_results/batch_${BATCH_ID}_timestamps.txt"
LOG_FILE="./benchmark_results/batch_${BATCH_ID}_log.txt"

echo "════════════════════════════════════════════════════════════════════"
echo "  50-Run Benchmark Batch Status Check"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Check if benchmarks are still running
if ps aux | grep -E "run_N_benchmarks|run_policy_benchmark" | grep -v grep > /dev/null; then
    echo "Status: 🏃 RUNNING"
    echo ""

    # Count completed runs
    if [[ -f "$TIMESTAMPS_FILE" ]]; then
        COMPLETED=$(wc -l < "$TIMESTAMPS_FILE")
        PERCENT=$((COMPLETED * 100 / 50))
        REMAINING=$((50 - COMPLETED))
        EST_REMAINING=$((REMAINING * 3))

        echo "Progress: $COMPLETED/50 runs complete ($PERCENT%)"
        echo "Remaining: $REMAINING runs (~${EST_REMAINING} minutes)"
        echo ""
        echo "Latest progress:"
        tail -15 "$LOG_FILE" 2>/dev/null || echo "  (log not available yet)"
    else
        echo "Progress: Starting..."
    fi
else
    echo "Status: ✅ COMPLETE or ⚠️ STOPPED"
    echo ""

    # Check if we have results
    if [[ -f "$TIMESTAMPS_FILE" ]]; then
        COMPLETED=$(wc -l < "$TIMESTAMPS_FILE")
        echo "Runs completed: $COMPLETED/50"

        if [[ $COMPLETED -eq 50 ]]; then
            echo ""
            echo "All 50 runs complete! Running statistical analysis..."
            echo ""
            python3 ./scripts/analyze_batch.py "$TIMESTAMPS_FILE"
        elif [[ $COMPLETED -gt 0 ]]; then
            echo ""
            echo "⚠️ WARNING: Only $COMPLETED runs completed (expected 50)"
            echo "Run partial analysis anyway? (y/n)"
            read -r response
            if [[ "$response" == "y" ]]; then
                python3 ./scripts/analyze_batch.py "$TIMESTAMPS_FILE"
            fi
        else
            echo "❌ No completed runs found"
        fi
    else
        echo "❌ No timestamp file found - benchmarks may not have started"
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "Monitor commands:"
echo "  tail -f $LOG_FILE"
echo "  watch -n 10 'wc -l $TIMESTAMPS_FILE'"
echo ""
