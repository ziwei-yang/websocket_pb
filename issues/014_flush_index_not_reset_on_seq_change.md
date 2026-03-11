# 014: flush_index Not Reset on Sequence Change

## Symptom

18 false `[FLUSH_GAP]` warnings in `271_binance_usdm_2url_dpdk_packetio_inline_ws.log`.
When consecutive depth diff WS messages with different sequences arrive in the same RX
batch, dedup reports `flush_gap` because the first MktEvent of the new sequence has a
non-zero `flush_index` (e.g. `count2=48` instead of `0`).

## Root Cause

In `flush_depth_deltas_json()` (and the SBE/JS equivalents), when a new depth diff
arrives with a different sequence than the currently pending depth, the old sequence's
pending entries are not flushed before starting the new one. The code only checks for
connection switch (`pd.ci != ci`) and overflow (`pd.count + publish_count > MAX_DELTAS`),
but never checks for sequence change (`pd.seq != state.sequence`).

This means `pd.flush_count` from the old sequence carries into the new sequence's
MktEvents. The dedup layer (which tracks `ob_expected_flush[ch]`) correctly detects the
gap — the first event of a new sequence should always have `flush_index == 0`, but
instead inherits the accumulated count from the previous sequence.

The bug exists in all 3 parser implementations:
1. `flush_depth_deltas_json()` — affects both JSON and simdjson parsers
2. `flush_sbe_depth_deltas()` — SBE binary parser
3. `emitBookDelta()` — JS verifier

## Fix

Before the overflow check, add a sequence-change check: if pending has entries from a
different sequence, publish them (completing the old sequence) and reset `has_pending`
so the new sequence starts fresh with `flush_count = 0`.

```cpp
// Sequence change: flush old seq's pending entries before starting new seq
if (pd.has_pending && pd.seq != state.sequence) {
    self.publish_pending_depth(ch, true);
    pd.has_pending = false;
}
```

Same pattern in all 3 files.

## Known Limitation: uint8_t flush_index Wrap-around

`flush_count` in `PendingDepth`, `InterleaveState`, and `MktEvent::count2` are all
`uint8_t`. If a single depth diff produces >255 flushes (>5120 entries at MAX_DELTAS=20),
`flush_count++` wraps to 0 via unsigned overflow. The dedup layer would see
`flush_index=0` and flag a false `[FLUSH_GAP]` (expected 256, got 0). In practice this
cannot happen on Binance (depth@100ms caps at ~1000 levels, ~50 flushes), so no fix is
applied. If needed, widen `flush_count` to `uint16_t` internally and saturate at 255
when writing to `count2`.

## Files

- `src/msg/01_binance_usdm_json.hpp` — `flush_depth_deltas_json()`
- `src/msg/00_binance_spot_sbe.hpp` — `flush_depth_deltas()`
- `tools/mkt_verifer_binance_usdm.js` — `emitBookDelta()`
- `test/unittest/msg_binance_usdm/test_usdm_json_parser.cpp` — new test
- `test/unittest/msg_binance_sbe/test_sbe_handler.cpp` — new test
- `tools/mkt_verifer_binance_usdm.test.js` — new test
