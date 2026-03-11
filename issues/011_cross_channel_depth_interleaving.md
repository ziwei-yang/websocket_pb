# 011: Cross-Channel Depth Interleaving in MktEvent Ring

## Summary

When multiple connections stream depth updates for different channels
(depth@100ms=ch0/Dp, depth@250ms=ch1/D1, depth@500ms=ch2/D2), the MktEvent
ring can contain interleaved fragments: `[ch0@seq_A, ch1@seq_B, ch0@seq_A]`
where `seq_B < seq_A`. This is **correct behavior**, not a bug — each channel
has an independent sequence space tracked by `last_book_seq_[ch]`.

## How It Happens

### Transport poll cycle (`10_tcp_ssl_process.hpp:437`)

```
transport_.poll();                          // receive packets for ALL connections
for ci in conn_order:
    process_ssl_read_for_conn(ci, ...)      // decrypt ALL available TLS records
    while (process_ssl_read_for_conn(...))  // drain loop
    end_rx_cycle(ci)                        // → on_batch_end(ci)
```

Each connection is fully drained before moving to the next. However, a single
WS frame can span multiple TCP segments arriving in different poll cycles.

### Interleaving scenario

```
Poll cycle N:
  conn0: 1st TCP segment of large depth@100ms frame (seq=44875)
    → handler starts streaming parse → overflow at MAX_DELTAS=19
    → publishes ch0 frag1 (19 entries) to ring
    → remaining parsed entries → pending_depth_[0]
  end_rx_cycle(0) → on_batch_end → flush pending_depth_[0] to ring

  conn1: complete depth@250ms frame (seq=44441)
    → handler parses ch1, 5 entries → pending_depth_[1]
  end_rx_cycle(1) → on_batch_end → flush pending_depth_[1] to ring

Poll cycle N+1:
  conn0: remaining TCP segments arrive
    → handler resumes streaming (state.phase != IDLE)
    → parses remaining entries → pending_depth_[0]
  end_rx_cycle(0) → on_batch_end → flush pending_depth_[0] to ring
```

Ring order: `[ch0@44875, ch0@44875, ch1@44441, ch0@44875]`

The ch1 events with seq=44441 appear between ch0 events with seq=44875.
This looks like a non-monotonic sequence if you ignore channel IDs.

## Why It's Correct

### Per-channel sequence tracking (`01_binance_usdm_json.hpp:1435-1445`)

```cpp
uint8_t ch = depth_channel_index(type);    // 0=100ms, 1=250ms, 2=500ms
if (e.sequence <= last_book_seq_[ch]) {    // per-channel check
    // discard as dup
}
last_book_seq_[ch] = e.sequence;           // per-channel update
```

Channel 0 (`last_book_seq_[0]`) and Channel 1 (`last_book_seq_[1]`) are
completely independent. Setting `last_book_seq_[0] = 44875` has zero effect
on `last_book_seq_[1]`, so ch1's seq=44441 passes dedup correctly.

### Re-check dedup for streaming continuations (`line 1324-1331`)

When conn0 resumes parsing across TCP segments:

```cpp
} else if (is_depth_diff_type(type)) {
    uint8_t ch = depth_channel_index(type);
    if (state.sequence < last_book_seq_[ch]) {  // re-check: superseded?
        state.deduped = true;
        state.phase = JsonParseState::DONE;
        return;
    }
}
```

This only checks the same channel — a ch0 continuation is checked against
`last_book_seq_[0]`, not `last_book_seq_[1]`.

## Log Appearance (False Positive Warning)

The main timeline log line shows `Dp` for ALL depth diffs regardless of
actual channel (from `WSFrameInfo.mkt_event_type = BOOK_DELTA`):

```
conn7 ... | 219 Dp @ ... | #44875 <-     ← main line says "Dp" (generic)
                          |  19 Dp Σ ...  ← continuation: actual channel IS Dp (ch0)
conn5 ... |  60 Dp @ ... | #44441 <-     ← main line says "Dp" (MISLEADING)
                          |  19 D1 Σ ...  ← continuation: actual channel is D1 (ch1)!
```

Only the MktEvent continuation lines (indented, with `Σ`) show the true
`depth_channel()` value. The `find_interleaved_depth.sh` script was updated
to parse continuation lines instead of main lines for accurate detection.

## Detection Script

`tools/find_interleaved_depth.sh` — fixed to use continuation lines:

```bash
# Before (false positives): used main-line "Dp" label
next unless /\|\s*(X?)\s*(\d*)\s*(Dp|D1|D2|OB)\s+@/;

# After (correct): uses continuation-line actual channel
next unless /\|\s*(\d+)\s+(Dp|D1|D2)\s+.*\|\s.*#(\d+)/;
```

Result: 26 "non-monotonic" cases detected by old script → 0 found by
corrected script. All 26 were cross-channel false positives.

## Unit Tests

`test/unittest/msg_binance_usdm/test_usdm_json_parser.cpp`:

| Test | Verifies |
|------|----------|
| `test_cross_conn_depth_channel_no_dedup` | ch0 seq=44875 + ch1 seq=44441 → both published (no cross-channel dedup) |
| `test_cross_conn_same_channel_dedup` | ch0 seq=200 + ch0 seq=150 → seq=150 deduped (same-channel dedup works) |
| `test_cross_conn_depth_channel_interleave_ordering` | Uses `feed_fragment` + `on_batch_end` per poll cycle to prove ring order `[ch0, ch1, ch0]` |

## Files

| File | Relevance |
|------|-----------|
| `src/msg/01_binance_usdm_json.hpp:1435-1445` | Per-channel `last_book_seq_[ch]` dedup |
| `src/msg/01_binance_usdm_json.hpp:1324-1331` | Re-check dedup during streaming continuation |
| `src/pipeline/10_tcp_ssl_process.hpp:437-560` | Transport poll loop: per-connection drain + `end_rx_cycle` |
| `src/pipeline/21_ws_core.hpp:459-589` | WS frame parsing: partial frame → `publish_partial_frame_info` → handler |
| `tools/find_interleaved_depth.sh` | Non-monotonic sequence detection (uses continuation lines) |
| `test/unittest/msg_binance_usdm/test_usdm_json_parser.cpp` | 3 new cross-connection tests |

## Date

2026-03-08
