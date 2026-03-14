# 016: DPDK TX Pool FIFO Head-of-Line Blocking

## Symptom

TX pool drains from 2048 → 0 over ~3 seconds during sustained market data
bursts, despite ACK frames being "fire-and-forget" (immediately marked acked).
475 warnings in a 15+ minute run of test271 (16-conn Binance USDM DPDK):

```
[WARN][DPDK-PIO] claim_tx_frames: TX pool full (2048/2048)     × 240
[TRANSPORT] WARNING: Failed to send ACK (TX frame pool full)    × 235
```

Two exhaustion events observed. Both show identical profile:

| Phase          | Duration | Drain rate     |
|----------------|----------|----------------|
| 2048 → 2000   | ~2000ms  | oscillates (partial recoveries) |
| 2000 → 100    | ~900ms   | ~2.1 frames/ms |
| 100 → 0       | ~12ms    | ~8.3 frames/ms |
| **Total drain**| **~3s**  | ~5000 msgs     |
| **Recovery**   | **45-95ms** | instant burst  |

The NIC transmitted and completed every ACK frame on the wire.
The issue is entirely in the software FIFO accounting.

## Root Cause: FIFO Head-of-Line Blocking

The TX pool is a FIFO with `tx_alloc_pos_` and `tx_free_pos_` pointers.
`tx_free_pos_` can only advance through **contiguous** acked slots:

```cpp
// mark_frame_acked() — FIFO release
frame_acked_[relative_idx] = true;
while (tx_free_pos_ < tx_alloc_pos_) {
    if (!frame_acked_[tx_free_pos_ % kTxPoolSize]) break;  // ← HOL block
    tx_free_pos_++;
}
```

Two TX paths exist with different lifetimes:

| Path | Claim | Free | Lifetime |
|------|-------|------|----------|
| `commit_ack_frame` (pure ACK) | `claim_tx_frames(1)` | `mark_frame_acked` immediately | ~0 (fire-and-forget) |
| `send()` (data/pong/SYN/FIN) | `claim_tx_frames(1)` | `mark_frame_acked` when **remote TCP ACK arrives** | 1 RTT + processing delay |

When a data frame (e.g. WS pong response) sits at FIFO position N:

```
FIFO:  [N:pong] [N+1:ack✓] [N+2:ack✓] [N+3:ack✓] ... [N+2047:ack✓]
        ^                                                              ^
   tx_free_pos_ (stuck)                                     tx_alloc_pos_
```

- Each subsequent ACK frame: `tx_alloc_pos_++`, bit set, but `tx_free_pos_`
  blocked at N (pong not yet acked by server)
- Pool shrinks by 1 per ACK sent, even though ACK frames are "freed"
- After ~2048 ACKs → pool exhausted

## Why "No Recycling" for ~1 Second

The server's ACK of our pong arrives on the wire within ~1 RTT (~1ms). But in
the inline WS model (single processing thread), the ACK sits in the RX queue
behind thousands of market data packets from all 16 connections.

Timeline during burst:
```
t=0:     Pong sent on conn 3 (FIFO pos N). Pool = 2048.
t+0-2s:  Pool oscillates near 2000. Occasional idle gaps let
         other pong ACKs arrive → partial FIFO recovery.
t+2s:    Burst intensifies. No idle gaps. Pong ACK for conn 3
         is queued behind ~2000 data packets in the RX ring.
t+2-3s:  Each data packet processed → ACK sent → pool -= 1.
         tx_free_pos_ stuck at N. Pool 2000 → 0.
t+3s:    Pool exhausted. ACKs fail. Data stops flowing.
         Thread goes idle → processes conn 3's ACK response.
         mark_frame_acked(N) → tx_free_pos_ jumps through
         all 2048 acked slots. Pool → 2048 in 45-95ms.
```

The NIC completed and recycled every TX mbuf promptly. The stall is
`tx_free_pos_` waiting for the **remote server's TCP ACK** of one data
frame to be **processed by our single-threaded RX loop**.

## Why 3 Seconds Matches

- 16 connections × ~100 msgs/s/conn = ~1600 msgs/s aggregate
- Each msg generates 1-4 ACK frames → ~680-2000 TX claims/s
- 2048 pool / ~680 claims/s ≈ **3 seconds** to exhaust

## Possible Fixes

1. **Separate FIFO per frame type**: Data frames (retransmit-tracked) use a
   small dedicated pool. ACK frames use the main pool. No HOL blocking.

2. **Non-FIFO free list**: Replace the ordered FIFO with a free-list that
   reclaims slots out of order. `mark_frame_acked` returns the slot directly
   without waiting for contiguous predecessors.

3. **Priority RX processing**: When TX pool is low, prioritize processing
   packets that carry ACK flags for our outstanding `snd_una` gaps, to
   unblock the FIFO head faster.

4. **Eager retransmit-queue drain on ACK**: When processing any connection's
   RX and finding an ACK that advances `snd_una`, immediately scan all
   connections' retransmit queues for newly-freeable frames.

## Chosen Fix: Split TX UMEM into Data Pool + ACK Pool

**Fix**: Split TX UMEM into two independent FIFO pools:
- **TX_DATA** — retransmit-tracked frames (SYN, DATA, FIN, PONG). Freed when remote TCP ACK arrives.
- **TX_ACK** — fire-and-forget frames (pure TCP ACK, DUP-ACK). Freed immediately after commit.

Both pools keep the FIFO release mechanism (contiguous `tx_free_pos_` advancement).
Separate pools mean a stuck data frame cannot block ACK frame recycling.

Also unify pool size definitions: all three PacketIO implementations (DPDK, XDP, Disruptor)
use `pipeline_config.hpp` constants scaled by `PIPELINE_MAX_CONN`.

### UMEM Layout

Before (MAX_CONN=1):
```
[RX=2048 | TX=2048]  total=4096 frames
```

After (MAX_CONN=1):
```
[RX=4096 | TX_DATA=2048 | TX_ACK=2048]  total=8192 frames
```

After (MAX_CONN=16):
```
[RX=65536 | TX_DATA=32768 | TX_ACK=32768]  total=131072 frames
```

### TX Caller Classification (transport.hpp)

| Caller | Method | Pool | Lifetime |
|--------|--------|------|----------|
| SYN (x4 overloads) | `claim_tx_frames` -> `retransmit_queue_.add_ref` | TX_DATA | Until remote ACK |
| DATA send | `claim_tx_frames` -> `retransmit_queue_.add_ref` | TX_DATA | Until remote ACK |
| FIN | `claim_tx_frames` -> `retransmit_queue_.add_ref` | TX_DATA | Until remote ACK |
| Pure ACK | `commit_ack_frame` -> `mark_ack_frame_acked` immediately | TX_ACK | Instant |
| ACK reception | `retransmit_queue_.remove_acked` -> `mark_frame_acked` | (frees TX_DATA) | -- |
| Reconnect reset | `retransmit_queue_.drain_all` -> `mark_frame_acked` | (frees TX_DATA) | -- |

**No changes needed in transport.hpp** — `claim_tx_frames` already routes to data pool,
`commit_ack_frame` already routes to ACK pool. The split is entirely within PacketIO.

### Files Changed

| File | Change |
|------|--------|
| `src/pipeline/pipeline_config.hpp` | Add PIPELINE_MAX_CONN, TX_ACK_POOL_SIZE, scale all pools |
| `src/pipeline/pipeline_data.hpp` | Remove MAX_CONN capture, keep #undef |
| `src/pipeline/dpdk_packet_io.hpp` | ACK pool members, new commit_ack_frame, mark_ack_frame_acked |
| `src/xdp/xdp_transport.hpp` | Remove DEFAULT_, add ACK pool, new commit_ack_frame method |
| `src/xdp/xdp_packet_io.hpp` | Delegate commit_ack_frame to XDPTransport |
| `src/pipeline/disruptor_packet_io.hpp` | ACK pool members, new commit_ack_frame, mark_ack_frame_acked |
| `src/pipeline/01_dpdk_poll_process.hpp` | Resize tx_shinfo_ and tx_hdr_pool_ for both pools |
| `src/pipeline/00_xdp_poll_process.hpp` | Update comp_size for both TX pools |
| `test/unittest/test_tx_pool_fifo.cpp` | Add MockDualPool + 8 new tests |
| `src/pipeline/websocket_pipeline.hpp` | Heap-allocate TransportProcess (stack overflow with large MaxConn) |
| `src/policy/transport.hpp` | Reorder includes (CACHE_LINE_SIZE conflict), fix -Werror unused params |
| `test/pipeline/03_disruptor_packetio_tcp.cpp` | Fix FRAME_SIZE→NIC_MTU template arg bug |
| `test/pipeline/271_...inline_ws.cpp` | Default MAX_CONN=16 so build works without --max-conn |

Full implementation plan: `.claude/plans/whimsical-questing-hammock.md`
