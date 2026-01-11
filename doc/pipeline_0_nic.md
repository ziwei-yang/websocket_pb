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
template<typename RingProducer,
         typename OutboxConsumer,
         bool TrickleEnabled = true,
         uint32_t FrameHeadroom = 256,
         uint32_t FrameSize = 2048>
struct XDPPollProcess {
    // Compile-time constants from template args
    static constexpr bool kTrickleEnabled = TrickleEnabled;
    static constexpr uint32_t kFrameHeadroom = FrameHeadroom;
    static constexpr uint32_t kFrameSize = FrameSize;
    static constexpr uint32_t kQueueId = 0;  // Always queue 0

public:
    // ========================================================================
    // Constructor - Takes interface name only
    // ========================================================================
    explicit XDPPollProcess(const char* interface) : interface_(interface) {}

    // ========================================================================
    // init() - Creates XSK socket from scratch (fork-first architecture)
    // Called in XDP Poll child process after fork
    // ========================================================================
    bool init(void* umem_area, size_t umem_size,
              const char* bpf_path,
              RingProducer* raw_inbox_prod,
              OutboxConsumer* raw_outbox_cons,
              OutboxConsumer* ack_outbox_cons,
              OutboxConsumer* pong_outbox_cons,
              ConnStateShm* conn_state);

    void run();
    void cleanup();

    // Accessors
    websocket::xdp::BPFLoader* get_bpf_loader();
    struct xsk_socket* get_xsk_socket();
    int get_xsk_fd() const;
    uint32_t fill_ring_producer() const;
    uint32_t fill_ring_consumer() const;
    int64_t last_released_seq() const;
    uint64_t last_rx_timestamp() const;
    uint64_t rx_packets() const;
    uint64_t tx_completions() const;

private:
    // Main loop helper methods
    bool submit_tx_batch();
    bool process_rx();
    void process_completions();
    void reclaim_rx_frames();
    void send_trickle();

    // Initialization helpers
    bool get_interface_mac();
    void create_trickle_socket();
    void build_trickle_packet();

    // XDP state
    struct xsk_socket* xsk_ = nullptr;
    struct xsk_umem* umem_ = nullptr;
    struct xsk_ring_prod fill_ring_;
    struct xsk_ring_cons comp_ring_;
    struct xsk_ring_cons rx_ring_;
    struct xsk_ring_prod tx_ring_;
    int xsk_fd_ = -1;

    // BPF loader (owns BPF program lifecycle)
    std::unique_ptr<websocket::xdp::BPFLoader> bpf_loader_;

    // Configuration
    void* umem_area_ = nullptr;
    size_t umem_size_ = 0;
    const char* interface_ = nullptr;
    unsigned int ifindex_ = 0;

    // Ring pointers (IPC rings from parent)
    RingProducer* raw_inbox_prod_ = nullptr;
    OutboxConsumer* raw_outbox_cons_ = nullptr;
    OutboxConsumer* ack_outbox_cons_ = nullptr;
    OutboxConsumer* pong_outbox_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // Trickle state (AF_PACKET socket for igc driver workaround)
    int trickle_fd_ = -1;
    uint8_t local_mac_[6];
    uint8_t trickle_packet_[64];
    size_t trickle_packet_len_ = 0;

    // Stats
    uint64_t rx_packets_ = 0;
    uint64_t tx_completions_ = 0;

    // RX frame tracking (via consumer sequence)
    int64_t last_released_seq_ = -1;
    uint64_t last_rx_timestamp_ns_ = 0;
};
```

---

## init() Implementation (Fork-First)

Creates XSK socket from scratch in child process. This is the fork-first approach:
no socket inheritance from parent, avoiding rx=0 issues.

```cpp
template<typename RingProducer, typename OutboxConsumer,
         bool TrickleEnabled, uint32_t FrameHeadroom, uint32_t FrameSize>
bool XDPPollProcess<...>::init(void* umem_area, size_t umem_size,
                               const char* bpf_path,
                               RingProducer* raw_inbox_prod, ...) {
    umem_area_ = umem_area;
    umem_size_ = umem_size;

    // Store IPC ring pointers (created by parent before fork)
    raw_inbox_prod_ = raw_inbox_prod;
    raw_outbox_cons_ = raw_outbox_cons;
    ack_outbox_cons_ = ack_outbox_cons;
    pong_outbox_cons_ = pong_outbox_cons;
    conn_state_ = conn_state;

    // 1. Create UMEM from shared memory area
    // Uses compile-time kFrameSize and kFrameHeadroom
    struct xsk_umem_config umem_cfg = {
        .fill_size = RX_FRAMES,       // Must match RX pool size
        .comp_size = TX_POOL_SIZE,    // Must match TX pool size
        .frame_size = kFrameSize,     // Compile-time template param
        .frame_headroom = kFrameHeadroom,
        .flags = 0
    };
    int ret = xsk_umem__create(&umem_, umem_area_, umem_size_,
                                &fill_ring_, &comp_ring_, &umem_cfg);
    if (ret) return false;

    // Initialize cached pointers for fill ring (producer ring)
    fill_ring_.cached_prod = *fill_ring_.producer;
    fill_ring_.cached_cons = *fill_ring_.consumer + fill_ring_.size;

    // Initialize cached pointers for completion ring (consumer ring)
    // These are NOT initialized by xsk_umem__create, causing garbage reads
    comp_ring_.cached_cons = *comp_ring_.consumer;
    comp_ring_.cached_prod = *comp_ring_.producer;

    // 2. Load and attach BPF program
    if (bpf_path) {
        bpf_loader_ = std::make_unique<websocket::xdp::BPFLoader>();
        bpf_loader_->load(interface_, bpf_path);
        bpf_loader_->attach();
    }

    // 3. Create XSK socket - always zero-copy mode
    // queue_id is always 0 (kQueueId), zero_copy is always true
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .xdp_flags = 0,
        .bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,  // Always zero-copy
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
    };
    ret = xsk_socket__create(&xsk_, interface_, kQueueId,
                              umem_, &rx_ring_, &tx_ring_, &xsk_cfg);
    if (ret) return false;
    xsk_fd_ = xsk_socket__fd(xsk_);

    // Initialize RX ring cached values (consumer ring)
    rx_ring_.cached_cons = *rx_ring_.consumer;
    rx_ring_.cached_prod = *rx_ring_.producer;

    // 4. Register XSK in BPF xsks_map
    bpf_loader_->register_xsk_socket(xsk_);

    // 4.5. Enable SO_BUSY_POLL for lower latency
    int busy_poll = 1;
    setsockopt(xsk_fd_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    int budget = 32;
    setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
    int usec = 50;  // 50us busy poll interval
    setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL, &usec, sizeof(usec));

    // 5. Populate fill_ring with RX frames
    uint32_t idx;
    if (xsk_ring_prod__reserve(&fill_ring_, RX_FRAMES, &idx) == RX_FRAMES) {
        for (uint32_t i = 0; i < RX_FRAMES; i++) {
            *xsk_ring_prod__fill_addr(&fill_ring_, idx++) = i * kFrameSize;
        }
        xsk_ring_prod__submit(&fill_ring_, RX_FRAMES);
    }

    // 6. Build trickle packet and create AF_PACKET socket
    if constexpr (kTrickleEnabled) {
        create_trickle_socket();
    }

    // 7. Signal XDP ready (XSK socket created, BPF attached)
    conn_state_->set_handshake_xdp_ready();
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

    // Direct flag access for main loop (explicit memory ordering)
    while (conn_state_->running[PROC_XDP_POLL].flag.load(std::memory_order_acquire)) {
        bool data_moved = false;

        // 1. Collect and submit TX packets
        data_moved |= submit_tx_batch();

        // 2. RX: rx_ring → RAW_INBOX - uses try_claim + publish
        data_moved |= process_rx();

        // 3. (always) Inline trickle for igc driver TX completion stall
        if ((++trickle_counter & 0x07) == 0) {
            send_trickle();  // 43-byte self-addressed UDP to trigger NAPI
        }

        // 4. (idle) comp_ring → reclaim TX UMEM by address range
        if (!data_moved) {
            process_completions();
        }

        // 5. (idle) Release ACKed PONG/MSG frames
        if (!data_moved) {
            release_acked_tx_frames();
        }

        // 6. (idle) Reclaim consumed RX UMEM → fill_ring
        if (!data_moved) {
            reclaim_rx_frames();
        }
    }
}
```

### submit_tx_batch()

Collects frames from all TX outboxes, submits to NIC, then commits consumers:

```cpp
bool XDPPollProcess::submit_tx_batch() {
    uint32_t tx_idx = 0;
    uint32_t tx_count = 0;
    uint32_t available = 0;

    // First check if any outbox has data before reserving TX slots
    bool has_raw = raw_outbox_cons_ && raw_outbox_cons_->has_data();
    bool has_ack = ack_outbox_cons_ && ack_outbox_cons_->has_data();
    bool has_pong = pong_outbox_cons_ && pong_outbox_cons_->has_data();

    if (!has_raw && !has_ack && !has_pong) {
        return false;  // Nothing to send
    }

    // Reserve TX ring slots - must always get full batch
    available = xsk_ring_prod__reserve(&tx_ring_, TX_BATCH_SIZE, &tx_idx);
    if (available < TX_BATCH_SIZE) {
        fprintf(stderr, "[XDP-TX] FATAL: TX ring reserve failed: got %u, need %u\n",
                available, TX_BATCH_SIZE);
        fprintf(stderr, "[XDP-TX] prod=%u cons=%u cached_prod=%u cached_cons=%u\n",
                *tx_ring_.producer, *tx_ring_.consumer,
                tx_ring_.cached_prod, tx_ring_.cached_cons);
        abort();
    }

    // Reusable lambda for collecting TX frames from any outbox
    auto collect_tx_frames = [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
        (void)seq;
        if (tx_count >= available) return false;

        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, tx_idx++);
        tx_desc->addr = desc.umem_addr;
        tx_desc->len = desc.frame_len;
        tx_desc->options = 0;
        tx_count++;
        return true;
    };

    // Collect from all TX outboxes using shared lambda
    if (has_raw && tx_count < available) {
        raw_outbox_cons_->process_manually(collect_tx_frames);
    }
    if (has_ack && tx_count < available) {
        ack_outbox_cons_->process_manually(collect_tx_frames);
    }
    if (has_pong && tx_count < available) {
        pong_outbox_cons_->process_manually(collect_tx_frames);
    }

    // Submit whatever we collected
    xsk_ring_prod__submit(&tx_ring_, tx_count);

    // Cancel reservation for unused slots
    if (tx_count < available) {
        tx_ring_.cached_prod -= (available - tx_count);
    }

    if (tx_count > 0) {
        // Conditional kick: only wake kernel if driver needs it
        if (xsk_ring_prod__needs_wakeup(&tx_ring_)) {
            sendto(xsk_fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        }

        // Commit consumers ONLY after successful TX submission
        if (has_raw) raw_outbox_cons_->commit_manually();
        if (has_ack) ack_outbox_cons_->commit_manually();
        if (has_pong) pong_outbox_cons_->commit_manually();

        return true;  // Data moved
    } else {
        tx_ring_.cached_prod -= available;
        return false;
    }
}
```

### process_rx()

Receives frames from rx_ring, publishes to RAW_INBOX with timestamps:

```cpp
bool XDPPollProcess::process_rx() {
    uint32_t rx_idx;
    uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &rx_idx);

    if (nb_pkts == 0) return false;

    uint64_t poll_cycle = rdtscp();

    for (uint32_t i = 0; i < nb_pkts; i++) {
        const struct xdp_desc* rx_desc = xsk_ring_cons__rx_desc(&rx_ring_, rx_idx++);

        // Claim slot in RAW_INBOX
        int64_t slot = raw_inbox_prod_->try_claim();
        if (slot < 0) {
            // FATAL: RAW_INBOX full - Transport process is not keeping up
            abort();
        }

        // Write directly to claimed slot
        auto& desc = (*raw_inbox_prod_)[slot];
        desc.umem_addr = rx_desc->addr;
        desc.frame_len = rx_desc->len;
        desc.nic_frame_poll_cycle = poll_cycle;
        desc.frame_type = FRAME_TYPE_RX;
        desc.consumed = 0;

        // Read NIC timestamp from metadata (8 bytes before packet data)
        uint64_t* ts_ptr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(umem_area_) + rx_desc->addr - 8);
        desc.nic_timestamp_ns = *ts_ptr;
        last_rx_timestamp_ns_ = desc.nic_timestamp_ns;  // Track for testing

        raw_inbox_prod_->publish(slot);
    }

    xsk_ring_cons__release(&rx_ring_, nb_pkts);
    rx_packets_ += nb_pkts;
    return true;  // Data moved
}
```

### process_completions()

Processes TX completion ring during idle time:

```cpp
void XDPPollProcess::process_completions() {
    uint32_t comp_idx;
    uint32_t nb_completed = xsk_ring_cons__peek(&comp_ring_, COMP_BATCH, &comp_idx);

    if (nb_completed == 0) return;

    for (uint32_t i = 0; i < nb_completed; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring_, comp_idx++);
        uint32_t frame_idx = addr_to_frame_idx(addr, kFrameSize);

        // Determine pool and handle accordingly
        if (frame_idx < RX_POOL_END) {
            // RX frame in comp_ring - should NEVER happen
            abort();
        } else if (frame_idx < ACK_POOL_END) {
            // ACK frame - release now (no retransmit needed)
            conn_state_->tx_frame.ack_release_pos.fetch_add(1, std::memory_order_release);
        } else if (frame_idx < PONG_POOL_END) {
            // PONG frame - release after TCP ACK (handled by Transport)
        } else {
            // MSG frame - release after TCP ACK (handled by Transport)
        }
    }

    xsk_ring_cons__release(&comp_ring_, nb_completed);
    tx_completions_ += nb_completed;
}
```

### reclaim_rx_frames()

Reclaims consumed RX frames to fill_ring during idle time:

```cpp
void XDPPollProcess::reclaim_rx_frames() {
    // Read Transport's consumer sequence
    int64_t consumer_pos = raw_inbox_prod_->consumer_sequence();

    // Nothing to reclaim if consumer hasn't advanced
    if (consumer_pos <= last_released_seq_) return;

    int64_t to_reclaim = consumer_pos - last_released_seq_;
    if (to_reclaim <= 0) return;

    // Reserve fill ring slots
    uint32_t fill_idx;
    uint32_t available = xsk_ring_prod__reserve(&fill_ring_, (uint32_t)to_reclaim, &fill_idx);
    if (available == 0) return;

    // Reclaim frames from RAW_INBOX ring buffer
    uint32_t reclaimed = 0;
    for (int64_t pos = last_released_seq_ + 1; pos <= consumer_pos && reclaimed < available; pos++) {
        const auto& desc = (*raw_inbox_prod_)[pos];
        *xsk_ring_prod__fill_addr(&fill_ring_, fill_idx++) = desc.umem_addr & ~(uint64_t)(kFrameSize - 1);
        reclaimed++;
    }

    if (reclaimed > 0) {
        xsk_ring_prod__submit(&fill_ring_, reclaimed);
        last_released_seq_ += reclaimed;
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

**XDP Poll Process** (advances release positions in `process_completions()`):
```cpp
// In idle section - process completion ring and release TX frames
// ACK frames: immediate release (ack_release_pos.fetch_add(1))
// PONG/MSG frames: XDP Poll advances release_pos when release_pos < acked_pos
if (!data_moved) {
    process_completions();
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

### send_trickle()

**Purpose**: The igc driver (Intel I225/I226) may stall TX completions in RX-only workloads.
Sending a minimal UDP packet triggers NAPI poll, which processes pending TX completions.

**Implementation**: Uses a separate AF_PACKET raw socket (not XDP tx_ring) for simplicity:
- Avoids UMEM frame allocation complexity
- Works regardless of XDP socket state
- Trickle packets bypass XDP entirely (sent via kernel stack)

**Frame Details**: Pre-built 43-byte self-addressed UDP packet stored in process memory:
- Ethernet header (14 bytes): src=local_mac, dst=local_mac, type=0x0800 (IPv4)
- IP header (20 bytes): src=127.0.0.1, dst=127.0.0.1, TTL=1, protocol=UDP
- UDP header (8 bytes): src_port=65534, dst_port=65534, len=9, checksum=0
- Payload (1 byte): 0x00

```cpp
void XDPPollProcess::send_trickle() {
    if constexpr (!kTrickleEnabled) return;
    if (trickle_fd_ < 0) return;
    // Send via AF_PACKET socket (separate from XDP tx_ring)
    ::send(trickle_fd_, trickle_packet_, trickle_packet_len_, MSG_DONTWAIT);
}
```

**Initialization**:
1. Create AF_PACKET raw socket bound to interface
2. Build trickle packet once during setup, store in `trickle_packet_[64]` buffer

**Note**: MSG and PONG frame release is handled by Transport Process when it receives TCP ACKs. XDP Poll only releases ACK frames immediately via `ack_release_pos.fetch_add()`.

### cleanup()

Cleans up XDP resources:

```cpp
void XDPPollProcess::cleanup() {
    if (trickle_fd_ >= 0) {
        ::close(trickle_fd_);
        trickle_fd_ = -1;
    }
    if (xsk_) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }
    if (umem_) {
        xsk_umem__delete(umem_);
        umem_ = nullptr;
    }
    if (bpf_loader_) {
        bpf_loader_->detach();
        bpf_loader_.reset();
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
| TX ring reserve fails | `std::abort()` - TX ring full indicates NIC not draining (misconfiguration) |
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

**TCPParams structure** (from `src/stack/tcp/conn_state.hpp`):
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
