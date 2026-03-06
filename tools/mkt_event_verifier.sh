#!/bin/bash
# tools/mkt_event_verifier.sh
# Orchestrates MktEvent sampling and verification.
#
# Usage:
#   ./tools/mkt_event_verifier.sh [exchange] [symbol] [count] [--verbose]
#   ./tools/mkt_event_verifier.sh Binance BTC-USDT 1024
#   ./tools/mkt_event_verifier.sh Binance BTC-USDT 1024 --verbose
set -e

EXCHANGE="${1:-Binance}"
SYMBOL="${2:-BTC-USDT}"
COUNT="${3:-1024}"
VERBOSE=""
if [ "$4" = "--verbose" ]; then VERBOSE="--verbose"; fi

RING_HDR="/dev/shm/hft/mkt_event.${EXCHANGE}.${SYMBOL}.hdr"
if [ ! -f "$RING_HDR" ]; then
    echo "ERROR: No alive MktEvent ring found at $RING_HDR"
    echo "  Is the pipeline running?"
    exit 1
fi

# Check MSG_INBOX files exist
if [ ! -f "/dev/shm/pipeline/msg_inbox_0.dat" ]; then
    echo "ERROR: No MSG_INBOX files found in /dev/shm/pipeline/"
    echo "  Pipeline must be built with file-backed MSG_INBOX support"
    exit 1
fi

# Build mkt_sampling if needed
echo "Building mkt_sampling..."
make build-mkt-sampling

# Run sampling
echo "Sampling ${COUNT} frames from ${EXCHANGE} ${SYMBOL}..."
./build/mkt_sampling "$EXCHANGE" "$SYMBOL" "$COUNT"

# Run JS verifier
echo ""
echo "Running JS verifier..."
node tools/mkt_verifer_binance_usdm.js $VERBOSE wsframes.txt mktevents.txt
