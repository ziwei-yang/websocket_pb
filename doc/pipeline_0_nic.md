# Pipeline Process 0: XDP Poll (Core 2)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [Transport Process (Core 4)](pipeline_1_trans.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

---

## Overview

XDP Poll is a **thin, fast data mover** between NIC and shared memory. It does NOT parse ETH/IP/TCP - all protocol stack work is done by Transport Process. This separation enables future replacement with DPDK poll process.

**Key Responsibilities**:
1. Collect TX frames from Transport's outbox rings → submit to NIC
2. Receive RX frames from NIC → publish to RAW_INBOX for Transport
3. Reclaim consumed UMEM frames → refill fill_ring
4. Handle TX completion → return frames to appropriate pools
5. Inline trickle packets for igc driver TX completion

---

## Code Reuse

```cpp
// XDP components (production-tested, reuse as-is - see pipeline_architecture.md Section 11.3)
#include <xdp/xdp_transport.hpp>  // XDPTransport, XDPConfig - UMEM/ring management
#include <xdp/xdp_frame.hpp>      // XDPFrame, xdp_user_metadata (8-byte timestamp)
#include <xdp/bpf_loader.hpp>     // BPFLoader for stats

// Disruptor IPC (from 01_shared_headers/disruptor/)
#include <disruptor/disruptor.hpp>  // ring_buffer, sequencer, event_processor

// Pipeline data structures
#include <pipeline/pipeline_data.hpp>  // UMEMFrameDescriptor, TxFrameState

// Timing
#include <core/timing.hpp>        // rdtscp()
```

**Note**: `XDPTransport` from `xdp/xdp_transport.hpp` provides complete UMEM/ring management including:
- Frame pool architecture (RX/TX 50/50 split)
- Zero-copy retransmit API (`alloc_tx_frame_idx()`, `mark_frame_acked()`, `retransmit_frame()`)
- igc driver RX trickle workaround
- BPF program loading and configuration

The XDP Poll Process can use `XDPTransport` directly or implement a thin wrapper for pipeline-specific needs.

---

## Class Definition (Fork-First Architecture)

In fork-first architecture, XDP Poll creates its own XSK socket fresh after fork.
This avoids XSK socket inheritance issues that caused `rx=0` packets.

```cpp
template<typename RawInboxProd, typename RawOutboxCons,
         typename AckOutboxCons, typename PongOutboxCons>
class XDPPollProcess {
    // XDP socket and rings (created fresh in init_fresh())
    int xsk_fd_;
    struct xsk_socket* xsk_ = nullptr;
    struct xsk_umem* umem_obj_ = nullptr;
    struct xsk_ring_prod tx_ring_;
    struct xsk_ring_cons rx_ring_;
    struct xsk_ring_cons comp_ring_;
    struct xsk_ring_prod fill_ring_;

    // UMEM (shared memory, mapped from parent)
    uint8_t* umem_;
    size_t umem_size_;

    // BPF loader (owned by XDP Poll in fork-first architecture)
    std::unique_ptr<websocket::xdp::BPFLoader> bpf_loader_;

    // Shared state (includes TCP state and TX frame allocation)
    // See pipeline_data.hpp for WebsocketStateShm definition
    WebsocketStateShm* tcp_state_;  // Note: TCPStateShm is alias for WebsocketStateShm

    // Ring buffer producers/consumers (IPC rings from parent)
    RawInboxProd* raw_inbox_prod_;
    RawOutboxCons* raw_outbox_consumer_;
    AckOutboxCons* ack_outbox_consumer_;
    PongOutboxCons* pong_outbox_consumer_;

    // Note: TxFrameState is now merged into WebsocketStateShm.tx_frame
    // Access via: tcp_state_->tx_frame.ack_release_pos, etc.

    // Trickle packet (pre-built static frame, allocated OUTSIDE RX/TX pools)
    // Address calculation uses compile-time FRAME_SIZE constant
    uint64_t trickle_frame_addr_;  // = TOTAL_UMEM_FRAMES * FRAME_SIZE

    // RX frame tracking
    int64_t last_released_ = 0;

    // Config
    struct Config {
        const char* interface;
        uint32_t queue_id = 0;
        uint32_t frame_size = FRAME_SIZE;  // Must equal compile-time FRAME_SIZE
        bool zero_copy = true;
    };

public:
    // ========================================================================
    // init_fresh() - Creates XSK socket from scratch (fork-first architecture)
    // Called in XDP Poll child process after fork
    // ========================================================================
    bool init_fresh(void* umem_area, size_t umem_size, const Config& config,
                    const char* bpf_path,
                    RawInboxProd* raw_inbox_prod,
                    RawOutboxCons* raw_outbox_cons,
                    AckOutboxCons* ack_outbox_cons,
                    PongOutboxCons* pong_outbox_cons,
                    WebsocketStateShm* tcp_state);

    void run();
    void cleanup();

private:
    bool load_and_attach_bpf(const char* bpf_path);
    void refill_rx_frame(uint64_t addr);
    void return_frame_to_pool(uint32_t frame_idx);
    void send_trickle_packet();
    void advance_tx_release_positions();
    void advance_msg_release_pos();
    void advance_pong_release_pos();
};
```

---

## init_fresh() Implementation (Fork-First)

Creates XSK socket from scratch in child process. This is the fork-first approach:
no socket inheritance from parent, avoiding rx=0 issues.

```cpp
template<typename ...>
bool XDPPollProcess<...>::init_fresh(void* umem_area, size_t umem_size,
                                      const Config& config, const char* bpf_path,
                                      RawInboxProd* raw_inbox_prod, ...) {
    umem_ = static_cast<uint8_t*>(umem_area);
    umem_size_ = umem_size;

    // Store IPC ring pointers (created by parent before fork)
    raw_inbox_producer_ = raw_inbox_prod;
    raw_outbox_consumer_ = raw_outbox_cons;
    ack_outbox_consumer_ = ack_outbox_cons;
    pong_outbox_consumer_ = pong_outbox_cons;
    tcp_state_ = tcp_state;

    // 1. Create UMEM from shared memory area
    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = config.frame_size,
        .frame_headroom = XDP_PACKET_HEADROOM,
        .flags = 0
    };
    int ret = xsk_umem__create(&umem_obj_, umem_, umem_size_,
                                &fill_ring_, &comp_ring_, &umem_cfg);
    if (ret) return false;

    // 2. Load and attach BPF program
    if (!load_and_attach_bpf(bpf_path)) return false;

    // 3. Create XSK socket (no program load - BPF already attached)
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .xdp_flags = config.zero_copy ? XDP_FLAGS_DRV_MODE : 0,
        .bind_flags = config.zero_copy ? XDP_ZEROCOPY : XDP_COPY,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
    };
    ret = xsk_socket__create(&xsk_, config.interface, config.queue_id,
                              umem_obj_, &rx_ring_, &tx_ring_, &xsk_cfg);
    if (ret) return false;
    xsk_fd_ = xsk_socket__fd(xsk_);

    // 4. Register XSK in BPF xsks_map
    bpf_loader_->register_xsk_socket(xsk_);

    // 5. Populate fill_ring with RX frames
    uint32_t idx;
    if (xsk_ring_prod__reserve(&fill_ring_, RX_FRAMES, &idx) == RX_FRAMES) {
        for (size_t i = 0; i < RX_FRAMES; i++) {
            *xsk_ring_prod__fill_addr(&fill_ring_, idx + i) = i * config.frame_size;
        }
        xsk_ring_prod__submit(&fill_ring_, RX_FRAMES);
    }

    // 6. Build trickle packet at reserved UMEM address
    // Use compile-time FRAME_SIZE constant (config.frame_size must equal FRAME_SIZE)
    trickle_frame_addr_ = TOTAL_UMEM_FRAMES * FRAME_SIZE;
    build_trickle_packet();

    // 7. Signal XDP ready (XSK socket created, BPF attached)
    tcp_state_->set_handshake_xdp_ready();
    printf("[XDP-POLL] XSK socket created, signaling xdp_ready\n");

    return true;
}
```

---

## Main Loop

```cpp
void XDPPollProcess::run() {
    constexpr uint32_t TX_BATCH_SIZE = 32;
    constexpr uint32_t RX_BATCH = 32;
    uint8_t trickle_counter = 0;

    // Fork-first: use is_running() helper with ProcessId enum
    while (tcp_state_->is_running(PROC_XDP_POLL)) {
        bool data_moved = false;
        uint32_t tx_batch_count = 0;
        uint32_t tx_batch_idx;

        // Reserve TX ring space for batch
        xsk_ring_prod__reserve(&tx_ring_, TX_BATCH_SIZE, &tx_batch_idx);

        // Reusable lambda for collecting TX frames from any outbox
        auto collect_tx_frames = [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
            if (tx_batch_count >= TX_BATCH_SIZE) return false;
            auto* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, tx_batch_idx + tx_batch_count);
            tx_desc->addr = desc.umem_addr;
            tx_desc->len = desc.frame_len;
            ++tx_batch_count;
            data_moved = true;
            return true;
        };

        // 1-3. Collect from all TX outboxes using shared lambda
        raw_outbox_consumer_.process_manually(collect_tx_frames);
        ack_outbox_consumer_.process_manually(collect_tx_frames);
        pong_outbox_consumer_.process_manually(collect_tx_frames);

        // 4. Submit TX batch + kick + commit consumers
        // CRITICAL: Only commit after successful TX submission
        if (tx_batch_count > 0) {
            xsk_ring_prod__submit(&tx_ring_, tx_batch_count);
            sendto(xsk_fd_, NULL, 0, MSG_DONTWAIT, NULL, 0);
            // Now safe to commit consumers (frames are in flight to NIC)
            raw_outbox_consumer_.commit_manually();
            ack_outbox_consumer_.commit_manually();
            pong_outbox_consumer_.commit_manually();
        }

        // 5. RX: rx_ring → RAW_INBOX - uses try_claim + publish
        //    NO separate build_descriptor() - inline for minimal overhead
        //    Capture NIC timestamp + XDP Poll cycle for latency tracking
        //    CRITICAL: RAW_INBOX full is a fatal error - Transport is too slow
        uint32_t idx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &idx);
        for (uint32_t i = 0; i < nb_pkts; i++) {
            const auto* rx_desc = xsk_ring_cons__rx_desc(&rx_ring_, idx + i);
            int64_t slot = raw_inbox_producer_.try_claim();
            if (slot < 0) {
                // FATAL: RAW_INBOX full - Transport process is not keeping up
                // This is a critical error that indicates system overload
                // Crash immediately to prevent silent data loss
                std::abort();  // Or: raise(SIGABRT);
            }

            auto& desc = raw_inbox_producer_[slot];
            desc.umem_addr = rx_desc->addr;
            desc.frame_len = rx_desc->len;
            desc.frame_type = FRAME_TYPE_RX;
            desc.consumed = 0;  // Will be set to 1 by Transport after SSL_read

            // Fetch NIC HW timestamp from BPF metadata (8 bytes before packet)
            desc.nic_timestamp_ns = *(uint64_t*)(umem_ + rx_desc->addr - 8);

            // Capture XDP Poll timestamp (using rdtscp() from core/timing.hpp)
            desc.nic_frame_poll_cycle = rdtscp();

            raw_inbox_producer_.publish(slot);
        }
        if (nb_pkts > 0) {
            xsk_ring_cons__release(&rx_ring_, nb_pkts);
            data_moved = true;
        }

        // 6. (idle) Reclaim consumed RX UMEM → fill_ring
        //    NOTE: Read Transport's consumer sequence via producer's consumer_sequence() method
        //    This is the implementation pattern from src/pipeline/xdp_poll_process.hpp
        if (!data_moved) {
            int64_t consumer_pos = raw_inbox_prod_->consumer_sequence();

            // Release frames that Transport has consumed
            // SAFETY: Only release up to consumer_pos (what Transport has processed)
            // last_released_ tracks how many frames XDP Poll has returned to fill_ring
            //
            // Invariant: last_released_ <= consumer_pos <= producer_pos
            //   - last_released_: XDP Poll's release cursor (how many we've recycled)
            //   - consumer_pos: Transport's consumption cursor (how many it has processed)
            //   - producer_pos: XDP Poll's publish cursor (how many we've received)
            //
            // We can safely release frames in range [last_released_, consumer_pos)
            // because Transport has finished reading them.
            while (last_released_ < consumer_pos) {
                // Read descriptor from RAW_INBOX ring buffer at last_released_ position
                auto& desc = raw_inbox_prod_->ring_buffer()[last_released_ & (RAW_INBOX_SIZE - 1)];
                refill_rx_frame(desc.umem_addr);
                ++last_released_;
            }
        }

        // 7. (idle) comp_ring → reclaim TX UMEM by address range
        //    CRITICAL SAFETY: comp_ring means NIC sent frame, but TCP ACK may not be received yet
        //    For MSG frames (retransmittable), MUST verify frame is ACKed before releasing
        //    For ACK/PONG frames (control, no retransmit), can release immediately
        if (!data_moved) {
            uint32_t n = xsk_ring_cons__peek(&comp_ring_, COMP_BATCH, &idx);
            for (uint32_t i = 0; i < n; i++) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring_, idx + i);

                // FRAME INDEX DERIVATION: addr→frame_idx
                // =====================================
                // comp_ring returns UMEM addresses (byte offsets into UMEM buffer).
                // To identify which pool a frame belongs to, we derive frame_idx:
                //   frame_idx = addr / FRAME_SIZE
                //
                // UMEM layout: [RX frames][ACK frames][PONG frames][MSG frames][Trickle]
                // So frame_idx directly maps to pool:
                //   [0, RX_FRAMES)           → RX pool (error if in comp_ring)
                //   [RX_FRAMES, RX+ACK)      → ACK pool
                //   [RX+ACK, RX+ACK+PONG)    → PONG pool
                //   [RX+ACK+PONG, ...)       → MSG pool
                //
                // Compare with Transport's position→frame_idx:
                //   frame_idx = BASE + (alloc_pos % POOL_SIZE)
                // where BASE is the starting frame index for that pool.
                uint32_t frame_idx = addr / FRAME_SIZE;

                // Skip trickle frame (reserved, not part of any pool)
                if (addr == trickle_frame_addr_) {
                    continue;
                }

                // Derive pool from address range
                if (frame_idx < RX_FRAMES) {
                    // RX frame - should never appear in comp_ring (RX only)
                    // This indicates a bug - abort
                    std::abort();
                } else if (frame_idx < RX_FRAMES + ACK_FRAMES) {
                    // ACK frame - control frame, no retransmit needed, release immediately
                    return_frame_to_pool(frame_idx);
                } else if (frame_idx < RX_FRAMES + ACK_FRAMES + PONG_FRAMES) {
                    // PONG frame - must wait for TCP ACK before release (like MSG)
                    //
                    // COMP_RING FLOW FOR PONG/MSG FRAMES:
                    // 1. comp_ring: NIC signals frame was SENT (DMA complete)
                    // 2. But we can't release yet - need TCP ACK for retransmit support
                    // 3. Transport marks pong_acked[] when TCP ACK covers this segment
                    // 4. advance_tx_release_positions() (step 8) advances position counters
                    //
                    // We don't track comp_ring completion explicitly - the acked[] flag
                    // subsumes it (can only be ACKed if it was sent)
                } else {
                    // MSG frame - same flow as PONG (see above)
                    // Transport marks msg_acked[] when TCP ACK covers this segment
                }
            }
            xsk_ring_cons__release(&comp_ring_, n);
        }

        // 8. (idle) Release ACKed TX frames sequentially
        //    Transport marks frames as ACKed, XDP Poll releases them
        if (!data_moved) {
            advance_tx_release_positions();
        }

        // 9. (always) Inline RX trickle for igc driver TX completion stall
        if ((++trickle_counter & 0x07) == 0) {
            send_trickle_packet();  // 43-byte self-addressed UDP to trigger NAPI
        }
    }
}
```

---

## TX Frame ACK Tracking and Release

**Design**: With large UMEM buffer, use sequential allocation with position-based ACK tracking:
1. **Transport Process**: Advances `acked_pos` when TCP ACK received
2. **XDP Poll Process**: During idle, releases frames where `release_pos < acked_pos`

**Shared State** (in shared memory between Transport and XDP Poll):

See [pipeline_architecture.md Section 3.5.1](pipeline_architecture.md#351-txframestate-shared-memory) for the canonical `TxFrameState` struct definition.

**Key fields used by XDP Poll**:
- `ack_release_pos`: XDP Poll advances when ACK frame sent (immediate release after comp_ring)
- `pong_release_pos`, `pong_acked_pos`: XDP Poll advances release when `release_pos < acked_pos`
- `msg_release_pos`, `msg_acked_pos`: XDP Poll advances release when `release_pos < acked_pos`

**UMEM Pool Split** (consistent with `xdp_transport.hpp`):
- **RX Pool**: Frames 0 to (N/2-1) for FILL/RX rings
- **TX Pool**: Frames N/2 to N-1 for sequential TX allocation

**Note**: `xdp_transport.hpp` uses a simple RX/TX 50/50 split. The pipeline extends this with logical sub-pools within the TX pool:
- ACK frames (control, no retransmit - pure TCP ACKs don't consume sequence space)
- PONG frames (data, ACK-based release - PONGs consume TCP sequence space and need retransmit)
- MSG frames (data, ACK-based release - application data needs retransmit)

**XDP Poll Process** (advances release positions during idle):
```cpp
// In idle section - advance release positions for MSG/PONG frames
// See advance_tx_release_positions() helper function
if (!data_moved) {
    advance_tx_release_positions();
}
```

**Transport Process** (advances acked_pos when TCP ACK received):
```cpp
// When TCP ACK covers MSG frames up to a position:
// NOTE: TCP ACKs are cumulative - simply advance the acked position
void TransportProcess::set_msg_acked_pos(uint64_t acked_pos) {
    tx_state_->msg_acked_pos.store(acked_pos, std::memory_order_release);
}

// When TCP ACK covers PONG frames up to a position:
void TransportProcess::set_pong_acked_pos(uint64_t acked_pos) {
    tx_state_->pong_acked_pos.store(acked_pos, std::memory_order_release);
}
```

**Benefits**:
- Simple position comparison (no bitmap operations)
- Single atomic store for ACK, single atomic load for release
- Natural flow: allocate sequential, release sequential after ACK

---

## BPF Metadata for NIC Timestamps

**Production BPF Program**: `src/xdp/bpf/exchange_filter.bpf.c` (DO NOT MODIFY - production tested)

The BPF program uses `bpf_xdp_metadata_rx_timestamp()` kfunc to extract NIC hardware RX timestamp and stores it in metadata space before the packet data:

```
┌─────────────────────────────────────────────────────────────┐
│                    UMEM Frame Layout                         │
├─────────────────────────────────────────────────────────────┤
│ [addr - 8]    uint64_t rx_timestamp_ns  (NIC HW timestamp)  │
│ [addr]        Ethernet frame starts here                    │
│               (rx_desc->addr points here)                   │
└─────────────────────────────────────────────────────────────┘
```

**Key BPF Features** (from `exchange_filter.bpf.c`):
- Filters **incoming TCP packets only** (outgoing goes through kernel)
- Matches source IP + source port via BPF maps (`exchange_ips`, `exchange_ports`)
- Uses `bpf_xdp_adjust_meta()` to reserve 8 bytes for `xdp_user_metadata`
- Calls `bpf_xdp_metadata_rx_timestamp()` kfunc for NIC HW timestamp
- Redirects matched packets to AF_XDP via `bpf_redirect_map(&xsks_map, ...)`

**Timestamp Extraction** (from `exchange_filter.bpf.c` lines 267-285):
```c
// Extract NIC hardware RX timestamp into metadata area
ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_user_metadata));
if (ret == 0) {
    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct xdp_user_metadata *meta = data_meta;
    if ((void *)(meta + 1) <= data) {
        __u64 timestamp = 0;
        ret = bpf_xdp_metadata_rx_timestamp(ctx, &timestamp);
        if (ret == 0 && timestamp != 0) {
            meta->rx_timestamp_ns = timestamp;
        }
    }
}
```

**Requirements**:
- Kernel 6.3+ for `bpf_xdp_metadata_rx_timestamp` kfunc
- Kernel 6.5+ for igc driver HW timestamp support
- `BPF_F_XDP_DEV_BOUND_ONLY` flag when loading
- NIC driver must support XDP zero-copy mode

**Timestamp Format**: Nanoseconds (PHC clock, typically synced to PTP or system time).

---

## Helper Functions

### refill_rx_frame()
```cpp
void XDPPollProcess::refill_rx_frame(uint64_t addr) {
    uint32_t idx;
    if (xsk_ring_prod__reserve(&fill_ring_, 1, &idx) == 1) {
        *xsk_ring_prod__fill_addr(&fill_ring_, idx) = addr;
        xsk_ring_prod__submit(&fill_ring_, 1);
    }
}
```

### return_frame_to_pool()
```cpp
void XDPPollProcess::return_frame_to_pool(uint32_t frame_idx) {
    // Derive pool from frame index based on UMEM partitioning
    // NOTE: No separate allocator classes - simple position-based allocation
    //       Transport picks frames by incrementing position (abort on full)
    //       XDP Poll releases by advancing release position
    //
    // DESIGN DECISION: Sequential release for ACK frames (tolerate potential race)
    // ============================================================================
    // ACK frames are released via position increment (fetch_add) which assumes sequential
    // release order. In practice, comp_ring returns frames in submission order, so this
    // works correctly.
    //
    // POTENTIAL RACE: If comp_ring returns frames out-of-order (e.g., frame 5 before frame 4),
    // calling fetch_add(1) for frame 5 would advance release_pos past unreleased frame 4.
    // This could cause Transport to think more frames are available than actually free.
    //
    // WHY WE TOLERATE THIS:
    // 1. comp_ring out-of-order is extremely rare (NIC DMA completion is typically FIFO)
    // 2. With large UMEM (4096+ frames), the "skipped" slot is just temporarily unavailable
    // 3. The slot becomes available on the next allocation wrap-around
    // 4. For HFT, we can size the buffer large enough that this never causes exhaustion
    // 5. The simplicity of position-based allocation (no free-list, no locks, no bitmap)
    //    outweighs the theoretical edge case
    //
    // MITIGATION: Size ACK_FRAMES generously (default 1/8 of total = 512 frames).
    // At 1M ACKs/sec with rare out-of-order, we'd need hundreds of consecutive
    // out-of-order completions to exhaust the pool - practically impossible.
    //
    // DEBUG ASSERTION: In debug builds, verify FIFO ordering assumption
    // If comp_ring returns out-of-order, abort with diagnostic info
#ifdef PIPELINE_DEBUG
    static thread_local uint64_t last_ack_addr = 0;
    if (last_ack_addr != 0 && addr < last_ack_addr) {
        fprintf(stderr, "[FATAL] comp_ring out-of-order: addr=%lu < last_ack_addr=%lu\n",
                addr, last_ack_addr);
        std::abort();
    }
    last_ack_addr = addr;
#endif
    //
    if (frame_idx < RX_FRAMES) {
        // RX frame - refill to fill_ring (should never happen via comp_ring)
        refill_rx_frame(frame_idx * FRAME_SIZE);
    } else if (frame_idx < RX_FRAMES + ACK_FRAMES) {
        // ACK frame - advance ACK pool release position (no retransmit, immediate release)
        // NOTE: Sequential release by design - see comment above
        tx_state_->ack_release_pos.fetch_add(1, std::memory_order_release);
    } else if (frame_idx < RX_FRAMES + ACK_FRAMES + PONG_FRAMES) {
        // PONG frame - should NOT be released here (uses sequential ACK-based release)
        // This branch should never execute - PONG positions advanced via advance_pong_release_pos()
        std::abort();  // Bug: PONG frame in immediate comp_ring reclaim path
    } else {
        // MSG frame - should NOT be released here (uses sequential ACK-based release)
        // This branch should never execute - MSG positions advanced via advance_msg_release_pos()
        std::abort();  // Bug: MSG frame in immediate comp_ring reclaim path
    }
}
```

### send_trickle_packet()

**Purpose**: The igc driver (Intel I225/I226) may stall TX completions in RX-only workloads.
Sending a minimal UDP packet triggers NAPI poll, which processes pending TX completions.

**Frame Details**: Pre-built 43-byte static frame stored in reserved UMEM region (NOT part of RX/TX pools):
- Ethernet header (14 bytes): src=local_mac, dst=local_mac, type=0x0800 (IPv4)
- IP header (20 bytes): src=127.0.0.1, dst=127.0.0.1, TTL=1, protocol=UDP
- UDP header (8 bytes): src_port=65534, dst_port=65534, len=9, checksum=0
- Payload (1 byte): 0x00

```cpp
void XDPPollProcess::send_trickle_packet() {
    // Pre-built 43-byte self-addressed UDP packet (in 64-byte aligned frame)
    // Stored at trickle_frame_addr_ (reserved UMEM region, excluded from pool reclaim)
    // This triggers NAPI processing on igc driver to complete TX
    // Packet is dropped by stack but forces TX completion interrupt

    uint32_t idx;
    if (xsk_ring_prod__reserve(&tx_ring_, 1, &idx) == 1) {
        auto* desc = xsk_ring_prod__tx_desc(&tx_ring_, idx);
        desc->addr = trickle_frame_addr_;  // Pre-built trickle packet
        desc->len = 43;                     // Actual packet size (not padded size)
        xsk_ring_prod__submit(&tx_ring_, 1);
        sendto(xsk_fd_, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
}
```

**UMEM Layout for Trickle Frame**:
```
UMEM_BUFFER:
├── RX Frames      [0, RX_FRAMES * FRAME_SIZE)
├── ACK TX Frames  [ACK_START, ACK_END)
├── PONG TX Frames [PONG_START, PONG_END)
├── MSG TX Frames  [MSG_START, MSG_END)
└── Trickle Frame  [TRICKLE_ADDR, TRICKLE_ADDR + 64)  ← Reserved, not part of any pool
```

**Initialization**: Build trickle packet once during setup, store at reserved address.

### advance_tx_release_positions()
```cpp
// Advance TX frame release positions based on Transport's ACK progress.
//
// NOTE ON NAMING: This function advances position counters, not "releases frames to a pool".
// The position-based allocation scheme works as follows:
//   - Transport allocates frames at `alloc_pos % POOL_SIZE`, then increments alloc_pos
//   - Transport sets `acked_pos` when TCP ACK confirms delivery
//   - XDP Poll advances `release_pos` up to `acked_pos`
//   - Transport can allocate if `alloc_pos - release_pos < POOL_SIZE`
//
// So "release" here means "mark position as reusable" not "return to free pool".
//
void XDPPollProcess::advance_tx_release_positions() {
    // Advance MSG frame release position
    advance_msg_release_pos();

    // Advance PONG frame release position
    advance_pong_release_pos();
}

void XDPPollProcess::advance_msg_release_pos() {
    // Uses position-based tracking: advance release_pos up to acked_pos
    uint64_t release_pos = tx_state_->msg_release_pos.load(std::memory_order_relaxed);
    uint64_t acked_pos = tx_state_->msg_acked_pos.load(std::memory_order_acquire);

    // Advance release position to match acked position
    // This marks those positions as available for Transport to reuse
    while (release_pos < acked_pos) {
        release_pos++;
        tx_state_->msg_release_pos.store(release_pos, std::memory_order_release);
    }
}

void XDPPollProcess::advance_pong_release_pos() {
    // Uses position-based tracking: advance release_pos up to acked_pos
    uint64_t release_pos = tx_state_->pong_release_pos.load(std::memory_order_relaxed);
    uint64_t acked_pos = tx_state_->pong_acked_pos.load(std::memory_order_acquire);

    // Advance release position to match acked position
    // This marks those positions as available for Transport to reuse
    while (release_pos < acked_pos) {
        release_pos++;
        tx_state_->pong_release_pos.store(release_pos, std::memory_order_release);
    }
}
```

---

## Ring Buffer Interactions

| Ring | Role | API |
|------|------|-----|
| RAW_INBOX | Producer | `try_claim()` + `publish()` |
| RAW_OUTBOX | Consumer | `process_manually()` + `commit_manually()` |
| ACK_OUTBOX | Consumer | `process_manually()` + `commit_manually()` |
| PONG_OUTBOX | Consumer | `process_manually()` + `commit_manually()` |

---

## Critical Error Handling

| Condition | Action |
|-----------|--------|
| RAW_INBOX full | `std::abort()` - Transport is not keeping up |
| TX ring reserve fails | Skip TX batch, retry next iteration |
| comp_ring empty | Normal - no TX completions pending |

---

## Performance Considerations

1. **Batch processing**: Process up to 32 TX frames per iteration
2. **Lazy commit**: Only commit consumers after successful TX submission
3. **Idle-time reclaim**: RX UMEM and TX completion processed during idle
4. **Inline trickle**: Every 8 iterations to prevent igc driver stalls
5. **Zero-copy timestamps**: NIC timestamp read directly from BPF metadata

---

## Segregated Testing

XDP Poll must be verified in isolation before integration with other pipeline processes.
This section describes the test strategy using a remote TCP echo server.

### Test Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Test Harness (Single Process)                      │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────┐   ┌──────────────────┐   ┌───────────────────────────┐  │
│  │ Main Thread  │   │ XDP Poll Thread  │   │ Stub Consumer Thread      │  │
│  │              │   │                  │   │                           │  │
│  │ - Setup      │   │ XDPPollProcess   │   │ - try_consume()           │  │
│  │ - Inject TX  │   │ - init_fresh()   │   │ - Advance consumer seq    │  │
│  │ - Verify     │   │ - run()          │   │ - Log received frames     │  │
│  │ - Metrics    │   │ - (trickle OFF)  │   │ - Update metrics          │  │
│  └──────────────┘   └──────────────────┘   └───────────────────────────┘  │
│         │                    │                         │                   │
│         ▼                    ▼                         ▼                   │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                       Shared Memory                                  │  │
│  │ ┌───────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐  │  │
│  │ │ UMEM  │ │RAW_INBOX  │ │RAW_OUTBOX │ │ACK_OUTBOX │ │Websocket   │  │  │
│  │ │       │ │Prod+Cons  │ │Prod+Cons  │ │(stub)     │ │StateShm    │  │  │
│  │ └───────┘ └───────────┘ └───────────┘ └───────────┘ └────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                       │
└────────────────────────────────────┼───────────────────────────────────────┘
                                     │
                                     ▼
                           ┌──────────────────┐
                           │  enp108s0 NIC    │
                           │  (local network) │
                           └──────────────────┘
                                     │
                                     │ (Internet/LAN)
                                     ▼
                           ┌──────────────────┐
                           │  Echo Server     │
                           │  139.162.79.171  │
                           │  Port 12345      │
                           └──────────────────┘
```

### Test Environment Setup

**Echo Server Setup** (on remote machine):
```bash
# Simple TCP echo server using ncat
ncat -l 12345 -k -c 'cat'

# Or using socat
socat TCP-LISTEN:12345,fork,reuseaddr EXEC:cat
```

**Safety Requirements**:
- Use dedicated test interface (`enp108s0`), never the default route interface
- Add route ONLY for echo server IP via test interface
- Never modify default route or touch other interfaces (VPN must remain functional)

**Interface Configuration** (automatic via test script):
```bash
# The test script automatically:
# 1. Checks echo server connectivity
# 2. Adds route for echo server via test interface
# 3. Cleans up on exit
./scripts/test_pipeline_xdp_poll.sh enp108s0
```

### BPF Map Configuration for Test

The test configures BPF maps to filter echo server traffic:

```cpp
// Configure BPF maps for echo server test
void configure_bpf_for_test(BPFLoader* bpf) {
    // Set local IP (destination filter - our interface IP)
    bpf->set_local_ip(local_interface_ip);

    // Add echo server IP (source filter - incoming packets from server)
    bpf->add_exchange_ip("139.162.79.171");

    // Add echo server port (source port filter)
    bpf->add_exchange_port(12345);
}
```

**BPF Filter Logic** (from `exchange_filter.bpf.c`):
- Packet must be IPv4 TCP
- Destination IP must match `local_ip` map (our interface IP)
- Source IP must be in `exchange_ips` map (echo server IP)
- Source port must be in `exchange_ports` map (12345)

### TCP Frame Construction

The test uses `src/stack/UserspaceStack` for TCP packet building and parsing.
This validates the userspace TCP/IP stack implementation with real network traffic.

**Include and initialization**:
```cpp
#include "../../src/stack/userspace_stack.hpp"
using namespace userspace_stack;

// Member variables
UserspaceStack stack_;
TCPParams tcp_params_;

// In setup():
stack_.init(local_ip_str, gateway_ip_str, netmask_str, local_mac);

// Initialize TCP params for connection
tcp_params_.local_ip = stack_.get_local_ip();
tcp_params_.remote_ip = IPLayer::string_to_ip(echo_server_ip);
tcp_params_.local_port = UserspaceStack::generate_port();
tcp_params_.remote_port = echo_port;
tcp_params_.snd_nxt = UserspaceStack::generate_isn();
tcp_params_.rcv_wnd = 65535;
```

**Building TCP packets**:
```cpp
// Build SYN packet (for handshake initiation)
size_t len = stack_.build_syn(frame_ptr, FRAME_SIZE, tcp_params_);

// Build ACK packet (after receiving SYN-ACK)
tcp_params_.rcv_nxt = server_seq + 1;  // ACK the server's SYN
tcp_params_.snd_nxt = client_seq + 1;  // Our seq advanced by 1 (SYN consumes seq)
size_t len = stack_.build_ack(frame_ptr, FRAME_SIZE, tcp_params_);

// Build DATA packet (PSH+ACK with payload)
size_t len = stack_.build_data(frame_ptr, FRAME_SIZE, tcp_params_, payload, payload_len);
tcp_params_.snd_nxt += payload_len;  // Advance seq by data length
```

**Parsing TCP packets**:
```cpp
// Parse received frame
TCPParseResult parsed = stack_.parse_tcp(
    frame_ptr, frame_len,
    tcp_params_.local_port,   // Expected dest port
    tcp_params_.remote_ip,    // Expected source IP
    tcp_params_.remote_port   // Expected source port
);

if (!parsed.valid) {
    // Frame didn't match filters or was malformed
    return;
}

// Check TCP flags
if (parsed.flags & TCP_FLAG_SYN && parsed.flags & TCP_FLAG_ACK) {
    // SYN-ACK received - extract server's sequence number
    uint32_t server_seq = parsed.seq;
    // ... send ACK to complete handshake
}
```

**TCPParams structure** (from `src/stack/tcp/tcp_state.hpp`):
```cpp
struct TCPParams {
    uint32_t snd_una = 0;    // Send unacknowledged
    uint32_t snd_nxt = 0;    // Send next (used as seq in outgoing packets)
    uint32_t snd_wnd = 0;    // Send window
    uint32_t rcv_nxt = 0;    // Receive next (used as ack in outgoing packets)
    uint32_t rcv_wnd = 65535;// Receive window

    uint16_t local_port = 0;
    uint16_t remote_port = 0;
    uint32_t local_ip = 0;   // Host byte order
    uint32_t remote_ip = 0;  // Host byte order
};
```

### Test Cases

#### Test 1: TCP Handshake with Echo Server

Complete TCP 3-way handshake using UserspaceStack:

```cpp
bool test_tcp_handshake() {
    // Initialize TCP params for new connection
    tcp_params_.local_port = UserspaceStack::generate_port();
    tcp_params_.snd_nxt = UserspaceStack::generate_isn();

    // Step 1: Send SYN
    inject_syn_frame();

    // Step 2: Wait for SYN-ACK
    if (!wait_for_rx(1, TIMEOUT_NS)) {
        printf("FAIL: Timeout waiting for SYN-ACK\n");
        return false;
    }

    // Step 3: Parse SYN-ACK and send ACK
    auto parsed = stack_.parse_tcp(frame_ptr, frame_len,
                                   tcp_params_.local_port,
                                   tcp_params_.remote_ip,
                                   tcp_params_.remote_port);
    if (!parsed.valid || !(parsed.flags & TCP_FLAG_SYN)) {
        printf("FAIL: Invalid SYN-ACK\n");
        return false;
    }

    // Update TCP state and send ACK
    tcp_params_.rcv_nxt = parsed.seq + 1;
    tcp_params_.snd_nxt += 1;  // SYN consumed 1 seq
    inject_ack_frame();

    printf("PASS: TCP handshake completed\n");
    return true;
}
```

#### Test 2: Timestamp Population

Verifies NIC hardware timestamp extraction:

```cpp
bool test_timestamp_populated() {
    uint64_t ts = metrics.last_rx_timestamp.load();

    if (ts == 0) {
        printf("WARN: No HW timestamp (driver may not support)\n");
        return true;  // Warning, not failure
    }

    printf("PASS: HW timestamp populated: %lu ns\n", ts);
    return true;
}
```

#### Test 3: fill_ring Reclaim

Verifies UMEM frame recycling:

```cpp
bool test_fill_ring_reclaim() {
    uint32_t initial_producer = xdp_poll->fill_ring_producer();

    // Wait for idle-time reclaim
    usleep(500000);  // 500ms

    uint32_t final_producer = xdp_poll->fill_ring_producer();
    int64_t released = xdp_poll->last_released_seq();

    if (released > 0) {
        printf("PASS: Frame reclaim working (released %ld frames)\n", released);
        return true;
    }

    printf("WARN: No frames reclaimed (may need more traffic)\n");
    return true;
}
```

#### Test 4: TX/RX Ring Functionality

Verifies ring buffer producer/consumer flow:

```cpp
bool test_tx_rx_rings() {
    printf("TX submitted:     %lu\n", metrics.tx_submitted.load());
    printf("RX consumed:      %lu\n", metrics.rx_consumed.load());
    printf("XDP RX packets:   %lu\n", xdp_poll.rx_packets());
    printf("XDP TX completes: %lu\n", xdp_poll.tx_completions());

    if (metrics.rx_consumed.load() > 0) {
        printf("PASS: TX/RX ring functionality verified\n");
        return true;
    }

    printf("WARN: No RX packets - check BPF filter and routing\n");
    return true;
}
```

### Build and Run

**Using the test script** (recommended):
```bash
# 1. Start echo server on remote machine
# On 139.162.79.171:
ncat -l 12345 -k -c 'cat'

# 2. Run test script (handles setup/cleanup)
./scripts/test_pipeline_xdp_poll.sh enp108s0

# The script will:
# - Check echo server connectivity
# - Add route for echo server via enp108s0
# - Build and run test
# - Clean up route on exit
```

**Manual execution**:
```bash
# 1. Build
make USE_XDP=1 build-test-pipeline-xdp-poll

# 2. Add route (if not using script)
GATEWAY=$(ip route show dev enp108s0 | grep via | awk '{print $3}' | head -1)
sudo ip route add 139.162.79.171/32 via $GATEWAY dev enp108s0

# 3. Run
sudo ./build/test_pipeline_xdp_poll enp108s0 build/exchange_filter.bpf.o 139.162.79.171 12345

# 4. Cleanup
sudo ip route del 139.162.79.171/32
```

### Success Criteria

| Test | Criteria | Priority |
|------|----------|----------|
| TCP handshake | Receive SYN-ACK within 10s | P0 |
| Timestamp populated | `nic_timestamp_ns != 0` (or warning) | P1 |
| fill_ring reclaim | Frames returned to fill_ring | P1 |
| TX/RX rings | Both TX and RX counters > 0 | P0 |
| BPF stats | `exchange_packets` > 0 | P1 |

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Echo server not reachable | Server not running | Start `ncat -l 12345 -k -c 'cat'` on remote |
| No RX frames | Route not via test interface | Check `ip route get 139.162.79.171` |
| No RX frames | BPF filter mismatch | Verify local_ip, exchange_ip, exchange_port |
| Timestamp = 0 | NIC doesn't support HW timestamps | Expected on some NICs |
| Gateway MAC not found | ARP cache empty | Ping gateway first to populate ARP |
| BPF attach fails | Another XDP program attached | `sudo ip link set enp108s0 xdp off` |
