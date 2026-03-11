# 010: Stale Depth Fragment Published After Snapshot (DUP_SEQ)

## Summary

When a depth diff has >19 entries, the handler overflow-publishes fragments
mid-parse and keeps the remainder in `pending_depth_[ch]`. If a depth20
snapshot arrives in the same batch (before `on_batch_end()`), the snapshot
is published to the ring while the stale fragment remains buffered. The
subsequent `on_batch_end()` then publishes the stale fragment *after* the
snapshot, creating a non-monotonic sequence in the ring.

## Symptom

47 `DUP_SEQ` errors in test 271 log, all `BOOK` type. Every DUP is a delta
fragment with sequence X appearing after a snapshot with sequence Y > X.
Pattern: 27 unique snapshots caused 47 DUPs (1-3 DUPs per snapshot across
Dp, D1, D2 depth channels).

## Root Cause

### Normal flow (depth diff with >19 entries)

```
feed_frame("depth@250ms", seq=X, 30 entries)
  -> parse bids, hit 19 entries -> publish frag1 (19 deltas, seq=X) to ring
  -> remaining 11 entries       -> store in pending_depth_[ch1]

idle() / on_batch_end()
  -> publish frag2 (11 deltas, seq=X) from pending_depth_[ch1]
```

Ring order: `[frag1@X, frag2@X]` -- correct, same seq.

### Bug scenario (snapshot interleaves before on_batch_end)

```
feed_frame("depth@250ms", seq=X, 30 entries)
  -> publish frag1 (19 deltas, seq=X) to ring
  -> remaining 11 entries -> store in pending_depth_[ch1]

feed_frame("depth20", seq=Y, 10 entries)    <- Y > X, same batch!
  -> publish snapshot (seq=Y) to ring       <- frag2 still in pending_depth_!

idle() / on_batch_end()
  -> publish frag2 (11 deltas, seq=X) from pending_depth_[ch1]
```

Ring order: `[frag1@X, snapshot@Y, frag2@X]` -- **broken**.
Downstream dedup sees frag2@X after snapshot@Y where X < Y -> `DUP_SEQ`.

## Fix

Flush all pending depth channels before processing a snapshot. Applied to
all 4 handler implementations:

### C++ JSON handler (`src/msg/01_binance_usdm_json.hpp`)

```cpp
case UsdmStreamType::DEPTH_PARTIAL:
    // ...
    bool is_snapshot = (type == UsdmStreamType::DEPTH_PARTIAL);
    if (is_snapshot) {
        // Flush pending deltas before snapshot to prevent stale
        // fragments from being published after the snapshot
        for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
            if (pending_depth_[ch].has_pending) publish_pending_depth(ch, true);
    }
```

### C++ SimdJSON handler (`src/msg/03_binance_usdm_simdjson.hpp`)

Same fix as JSON handler.

### C++ SBE handler (`src/msg/00_binance_spot_sbe.hpp`)

Had existing flush guard that excluded snapshots:
```cpp
// Before (bug):
if (has_pending_depth_ &&
    state.msg_type != DEPTH_DIFF_STREAM && state.msg_type != DEPTH_SNAPSHOT_STREAM)
    publish_pending_depth(true);

// After (fix):
if (has_pending_depth_ && state.msg_type != DEPTH_DIFF_STREAM)
    publish_pending_depth(true);
```

### JS verifier (`tools/mkt_verifer_binance_usdm.js`)

Added `this.builder.flushDepthBeforeTrades()` call before snapshot dedup check.

## Regression Test

`test_stream_depth_overflow_then_snapshot_ordering` in
`test/unittest/msg_binance_usdm/test_usdm_json_parser.cpp`:

1. Feed large depth diff (25 bids + 5 asks = 30 entries, seq=600000)
   -> overflows at 19, frag2 stays in `pending_depth_`
2. Feed depth20 snapshot (5+5 entries, seq=700000) before `idle()`
3. Call `idle()`
4. Assert all delta fragments appear before the snapshot in the ring
5. Assert delta total = 30, snapshot = 5 bids + 5 asks
6. Assert sequence ordering: delta seq < snapshot seq

Runs for both `BinanceUSDMJsonParser` and `BinanceUSDMSimdjsonParser`.

## Verification

100/100 runs of `mkt_event_verifier.sh` passed with 0 failures after fix.

## Files Changed

| File | Change |
|------|--------|
| `src/msg/01_binance_usdm_json.hpp` | Flush pending depth before snapshot |
| `src/msg/03_binance_usdm_simdjson.hpp` | Flush pending depth before snapshot |
| `src/msg/00_binance_spot_sbe.hpp` | Remove snapshot exclusion from flush guard |
| `tools/mkt_verifer_binance_usdm.js` | Flush pending depth before snapshot |
| `test/unittest/msg_binance_usdm/test_usdm_json_parser.cpp` | Regression test |

## Date

2026-03-08
