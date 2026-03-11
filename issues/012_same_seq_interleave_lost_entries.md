# 012: Multi-Connection Same-SEQ Interleave — Lost Depth Entries

## Summary

When N connections receive the same depth delta (same sequence number), the
**first connection to claim the seq wins** and all subsequent connections with
that seq are **fully discarded** — even if the "losing" connection parses
entries faster due to different packet fragmentation. This silently drops
valid depth entries that arrived sooner on the losing connection.

## Date

2026-03-09

## How It Could Be an Issue

### The Setup

With `CONN_PER_IP=2` and 8 IPs, 8 public-stream connections subscribe to the
same depth channels (`btcusdt@depth@100ms`, `btcusdt@depth`, etc.). Each
connection receives **identical** depth delta messages from Binance, but with
different TCP segmentation and NIC arrival timing.

### The Race Condition

A large depth delta (e.g. 181 entries, ~4KB) arrives across **3 TCP packets**
on all 8 connections:

```
conn_f: pkt1 arrives → parse 60 entries → FLUSH (committed=60)
                                          ↑ claims seq, sets last_book_seq_[ch]
conn_5: pkt1 arrives → parse 60 entries → DISCARDED (seq <= last_book_seq_[ch])
conn_1: pkt1 arrives → parse 60 entries → DISCARDED
conn_3: pkt1 arrives → parse 60 entries → DISCARDED

conn_f: pkt2 arrives → parse 69 entries → FLUSH (committed=129)
conn_5: pkt2 arrives → DISCARDED (already rejected at re-check)

conn_f: pkt3 arrives → parse 52 entries → FLUSH (committed=181, DONE)
```

### The Lost Opportunity

If `conn_5`'s pkt2 arrived **before** `conn_f`'s pkt2:

```
conn_f: pkt1 → FLUSH 60 entries (committed=60)
conn_5: pkt1 → skip (cumul=60 ≤ committed=60)
conn_5: pkt2 → parse 69 entries → cumul=129 > committed=60
              → VERIFY entry[59] matches boundary → PASS
              → PUBLISH entries 61-129 (committed=129)    ← FASTER!
conn_f: pkt2 → skip (cumul=129 ≤ committed=129)
conn_f: pkt3 → cumul=181 > committed=129
              → VERIFY entry[128] → PUBLISH entries 130-181
```

**Result**: entries 61-129 arrive sooner from `conn_5`, reducing latency for
those entries by the gap between `conn_5`'s pkt2 and `conn_f`'s pkt2.

### Measured Impact

From `./log/271_binance_usdm_2url_dpdk_packetio_inline_ws.log` (pre-fix):

- **1,517** unique depth delta sequences observed
- **1,355** had multiple connections (89%) — all losers fully discarded
- Multi-packet sequences (3+ packets, 100+ entries): **~30%** of depth deltas
- Inter-packet gaps: typically 150-300us between packets
- **Potential latency savings**: 150-300us per interleaved flush for large deltas

### Why It Was Silent

The old dedup check was:

```cpp
if (e.sequence <= last_book_seq_[ch]) {
    // discard entire message — no entries published
}
```

No warning, no counter, no visibility. The entries just disappeared. The
downstream consumer saw only the winning connection's entries, with gaps
during the winner's inter-packet delays.

## How We Resolved It

### `InterleaveState` Tracking

Added per-channel state to track committed progress across connections:

```cpp
struct InterleaveState {
    int64_t  seq = 0;
    uint16_t committed_count = 0;   // entries committed for this seq
    bool     finished = false;      // any connection fully parsed this seq
    websocket::msg::DeltaEntry boundary_entry{};  // entry at committed_count-1

    void reset(int64_t new_seq) {
        seq = new_seq; committed_count = 0; finished = false;
        boundary_entry = {};
    }
};
```

### Skip + Verify Algorithm

When a connection flushes depth entries for a seq already claimed:

```
cumul = total entries parsed so far (bids_count + asks_count)
prev_cumul = cumul - current_delta_count
committed = interleave.committed_count

if cumul <= committed:
    skip all → return                    // nothing new

if prev_cumul < committed:
    // Boundary crossing — verify entry[committed_count-1] matches
    boundary_idx = committed - 1 - prev_cumul
    if delta_buf[boundary_idx] != cached boundary_entry:
        WARN "interleave mismatch"       // reject this connection
        return

    skip = committed - prev_cumul        // skip already-published entries
else:
    skip = 0                             // all entries are new

publish delta_buf[skip .. end]
update committed_count and boundary_entry
```

### Dedup Check Changes

```cpp
// OLD: discard if seq <= last_book_seq (too aggressive)
if (e.sequence <= last_book_seq_[ch]) { discard; }

// NEW: only discard if strictly older, or same-seq and fully finished
if (e.sequence < last_book_seq_[ch]) { discard; }
if (e.sequence == last_book_seq_[ch]) {
    if (interleave_[ch].finished) { discard; }  // fast-path: done
    // else: allow — flush logic handles skip+verify
}
```

### Boundary Verification

The key safety mechanism: when a losing connection crosses the committed
boundary, we verify that its `entry[committed_count-1]` matches the cached
boundary entry from the winner. This confirms both connections are parsing
the same data. On mismatch (should never happen with identical feeds):
- Log a warning
- Discard the losing connection's entries for this seq
- Do NOT set `finished=true` — let the original winner continue

### Files Changed

| File | Change |
|------|--------|
| `src/msg/01_binance_usdm_json.hpp` | `InterleaveState` struct, skip+verify in `flush_depth_deltas_json()`, dedup changes |
| `src/msg/03_binance_usdm_simdjson.hpp` | `interleave_[]` member, dedup changes (flush shared via template) |
| `src/msg/00_binance_spot_sbe.hpp` | `InterleaveState` struct, skip+verify in `flush_depth_deltas()`, dedup changes |
| `tools/mkt_verifer_binance_usdm.js` | JS mirror of all C++ changes |

### Tests Added

| Test | Verifies |
|------|----------|
| `test_interleave_basic` | conn0 finishes → conn1 same seq fully deduped |
| `test_interleave_conn1_faster` | conn0 partial, conn1 complete → conn1 fills remaining |
| `test_interleave_boundary_verify_pass` | Same entries → all skipped (no dup publish) |
| `test_interleave_boundary_verify_fail` | Different entries → conn2 rejected |
| `test_interleave_finished_fast_path` | conn0 finishes → conn1 immediate discard at initial dedup |
| `test_sbe_interleave_basic` | SBE: conn0 finishes → conn1 deduped |
| `test_sbe_interleave_conn1_faster` | SBE: fragment interleaving with binary protocol |
| `test_sbe_interleave_finished_fast_path` | SBE: immediate discard |

### Detection Script

`tools/find_same_seq_interleave.py` — analyzes timeline logs to find
same-SEQ multi-connection depth events, showing where interleaving would
have helped (pre-fix) or did help (post-fix).

## Event Types Not Affected

| Type | Reason |
|------|--------|
| Trades (`Td`) | Per-trade-id dedup already interleaves correctly |
| BBO (`OB`) | Single snapshot per seq, no multi-packet fragmentation concern |
| Liquidation (`Lq`) | Single event per message |
| Mark Price (`Mp`) | Single event per message |

## Commit

`1276cbe` — "Add multi-connection same-SEQ interleave for depth deltas"
