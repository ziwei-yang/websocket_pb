// pipeline/xdp_poll_process.hpp
// XDP Poll Process - Kernel interface for zero-copy packet I/O
// Runs on dedicated CPU core, handles UMEM frame management
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <memory>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include "../xdp/bpf_loader.hpp"

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// XDPPollProcess - Core XDP packet I/O handler
//
// Template Parameters:
//   RingProducer   - Producer type for RAW_INBOX (UMEMFrameDescriptor)
//   OutboxConsumer - Consumer type for all outbox rings (UMEMFrameDescriptor)
//                    Uses frame_type field to distinguish ACK/PONG/MSG frames
//   TrickleEnabled - Enable trickle packets (igc driver workaround), default true
//   FrameHeadroom  - XDP metadata headroom (e.g., 256 for timestamps), default 256
//   FrameSize      - UMEM frame size, default 2048 (for MTU 1500)
//
// Responsibilities:
// 1. Collect TX packets from outbox rings (RAW_OUTBOX, ACK_OUTBOX, PONG_OUTBOX)
// 2. Submit TX batch to kernel, kick sendto()
// 3. Receive RX packets from rx_ring, publish to RAW_INBOX with timestamps
// 4. Reclaim consumed RX frames back to fill_ring
// 5. Process completion ring for TX frames
// 6. Send trickle packets for igc driver NAPI workaround
// ============================================================================

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

    // ========================================================================
    // Constructor
    // ========================================================================

    explicit XDPPollProcess(const char* interface) : interface_(interface) {}

    // ========================================================================
    // Initialization (with BPF loading)
    // ========================================================================

    bool init(void* umem_area, size_t umem_size,
              const char* bpf_path,
              RingProducer* raw_inbox_prod,
              OutboxConsumer* raw_outbox_cons,
              OutboxConsumer* ack_outbox_cons,
              OutboxConsumer* pong_outbox_cons,
              ConnStateShm* conn_state) {

        umem_area_ = umem_area;
        umem_size_ = umem_size;
        raw_inbox_prod_ = raw_inbox_prod;
        raw_outbox_cons_ = raw_outbox_cons;
        ack_outbox_cons_ = ack_outbox_cons;
        pong_outbox_cons_ = pong_outbox_cons;
        conn_state_ = conn_state;

        // Get interface index
        ifindex_ = if_nametoindex(interface_);
        if (ifindex_ == 0) {
            fprintf(stderr, "[XDP-POLL] Interface not found: %s\n", interface_);
            return false;
        }

        // Get interface MAC for trickle packets
        if (!get_interface_mac()) {
            fprintf(stderr, "[XDP-POLL] Failed to get MAC for %s\n", interface_);
            return false;
        }

        // Load and attach BPF program if path provided
        if (bpf_path) {
            try {
                bpf_loader_ = std::make_unique<websocket::xdp::BPFLoader>();
                bpf_loader_->load(interface_, bpf_path);
                bpf_loader_->attach();
                printf("[XDP-POLL] BPF program loaded and attached\n");
            } catch (const std::exception& e) {
                fprintf(stderr, "[XDP-POLL] BPF loading failed: %s\n", e.what());
                bpf_loader_.reset();
                return false;
            }
        }

        // Configure UMEM
        // Fill ring needs to be large enough for RX_FRAMES (32768)
        // Completion ring needs to handle TX completions (ACK + PONG + MSG frames)
        struct xsk_umem_config umem_cfg = {};
        umem_cfg.fill_size = RX_FRAMES;     // Must match RX pool size (32768)
        umem_cfg.comp_size = TX_POOL_SIZE;  // Must match TX pool size (32768)
        umem_cfg.frame_size = kFrameSize;
        umem_cfg.frame_headroom = kFrameHeadroom;
        umem_cfg.flags = 0;

        int ret = xsk_umem__create(&umem_, umem_area_, umem_size_,
                                   &fill_ring_, &comp_ring_, &umem_cfg);
        if (ret) {
            fprintf(stderr, "[XDP-POLL] Failed to create UMEM: %s\n", strerror(-ret));
            if (bpf_loader_) bpf_loader_->detach();
            return false;
        }

        // Initialize cached pointers for fill ring (producer ring)
        // xsk_umem__create should do this but we ensure it's correct
        fill_ring_.cached_prod = *fill_ring_.producer;
        fill_ring_.cached_cons = *fill_ring_.consumer + fill_ring_.size;

        // Initialize cached pointers for completion ring (consumer ring)
        // These are NOT initialized by xsk_umem__create, causing garbage reads
        comp_ring_.cached_cons = *comp_ring_.consumer;
        comp_ring_.cached_prod = *comp_ring_.producer;

        // Note: rx_ring_ cached values are initialized by xsk_socket__create,
        // but we'll initialize them after socket creation to be safe

#if DEBUG
        fprintf(stderr, "[XDP-POLL] comp_ring after init: prod=%u cons=%u mask=%u cached_prod=%u cached_cons=%u\n",
                *comp_ring_.producer, *comp_ring_.consumer, comp_ring_.mask,
                comp_ring_.cached_prod, comp_ring_.cached_cons);
        fflush(stderr);
#endif

        // Configure XDP socket - always zero-copy mode
        struct xsk_socket_config xsk_cfg = {};
        xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        xsk_cfg.xdp_flags = 0;
        xsk_cfg.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

        ret = xsk_socket__create(&xsk_, interface_, kQueueId,
                                 umem_, &rx_ring_, &tx_ring_, &xsk_cfg);
        if (ret) {
            fprintf(stderr, "[XDP-POLL] Failed to create XSK socket: %s\n", strerror(-ret));
            xsk_umem__delete(umem_);
            if (bpf_loader_) bpf_loader_->detach();
            return false;
        }

        xsk_fd_ = xsk_socket__fd(xsk_);

        // Initialize RX ring cached values (consumer ring)
        // xsk_socket__create may not initialize these
        rx_ring_.cached_cons = *rx_ring_.consumer;
        rx_ring_.cached_prod = *rx_ring_.producer;

        fprintf(stderr, "[XDP-POLL] XSK created: fd=%d tx_size=%u rx_size=%u\n",
                xsk_fd_, xsk_cfg.tx_size, xsk_cfg.rx_size);
        fprintf(stderr, "[XDP-POLL] TX ring: prod=%u cons=%u mask=%u\n",
                *tx_ring_.producer, *tx_ring_.consumer, tx_ring_.mask);
        fprintf(stderr, "[XDP-POLL] TX ring: size=%u flags=%u cached_prod=%u cached_cons=%u\n",
                tx_ring_.size, *tx_ring_.flags, tx_ring_.cached_prod, tx_ring_.cached_cons);
        fprintf(stderr, "[XDP-POLL] Ring addresses: fill=%p tx=%p rx=%p comp=%p\n",
                (void*)&fill_ring_, (void*)&tx_ring_, (void*)&rx_ring_, (void*)&comp_ring_);
        fprintf(stderr, "[XDP-POLL] Fill ring: prod=%u cons=%u mask=%u cached_prod=%u cached_cons=%u\n",
                *fill_ring_.producer, *fill_ring_.consumer, fill_ring_.mask,
                fill_ring_.cached_prod, fill_ring_.cached_cons);
        fflush(stderr);

        // Register XSK socket with BPF program
        if (bpf_loader_) {
            try {
                bpf_loader_->register_xsk_socket(xsk_);
                printf("[XDP-POLL] XSK socket registered with BPF\n");
            } catch (const std::exception& e) {
                fprintf(stderr, "[XDP-POLL] Failed to register XSK: %s\n", e.what());
                cleanup();
                return false;
            }
        }

        // Enable SO_BUSY_POLL (budget=32, interval=50us for lower latency)
        int busy_poll = 1;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        int budget = 32;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
        int usec = 50;  // 50us busy poll interval
        setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL, &usec, sizeof(usec));

        // Populate fill ring with RX pool frames
        printf("[XDP-POLL] Populating fill ring with %zu frames (fill_size=%u)...\n",
               RX_FRAMES, umem_cfg.fill_size);
        uint32_t idx = 0;
        ret = xsk_ring_prod__reserve(&fill_ring_, RX_FRAMES, &idx);
        if (ret != static_cast<int>(RX_FRAMES)) {
            fprintf(stderr, "[XDP-POLL] Failed to populate fill ring: reserved %d of %zu\n",
                    ret, RX_FRAMES);
            cleanup();
            return false;
        }

        for (uint32_t i = 0; i < RX_FRAMES; i++) {
            *xsk_ring_prod__fill_addr(&fill_ring_, idx++) = i * kFrameSize;
        }
        xsk_ring_prod__submit(&fill_ring_, RX_FRAMES);

        fprintf(stderr, "[XDP-POLL] After fill ring submit:\n");
        fprintf(stderr, "[XDP-POLL]   Fill: cached_prod=%u cached_cons=%u\n",
                fill_ring_.cached_prod, fill_ring_.cached_cons);
        fprintf(stderr, "[XDP-POLL]   TX:   cached_prod=%u cached_cons=%u\n",
                tx_ring_.cached_prod, tx_ring_.cached_cons);
        fflush(stderr);

        // Create trickle socket
        if constexpr (kTrickleEnabled) {
            create_trickle_socket();
        }

        // Signal XDP ready for fork-first architecture
        if (conn_state_) {
            conn_state_->set_handshake_xdp_ready();
        }

        printf("[XDP-POLL] Initialized on %s queue %u\n", interface_, kQueueId);
        return true;
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        printf("[XDP-POLL] Starting main loop\n");
        uint8_t trickle_counter = 0;

        while (conn_state_->running[PROC_XDP_POLL].flag.load(std::memory_order_acquire)) {
            bool data_moved = false;

            // 1. Collect and submit TX packets
            data_moved |= submit_tx_batch();

            // 2. Process RX packets
            data_moved |= process_rx();

            // 3. Trickle (every 8 iterations) - always runs
            if ((++trickle_counter & 0x07) == 0) {
                send_trickle();
            }

            // 4. (idle) Process completion ring - only when no data moved
            if (!data_moved) {
                process_completions();
            }

            // 5. (idle) Release ACKed PONG/MSG frames - only when no data moved
            if (!data_moved) {
                release_acked_tx_frames();
            }

            // 6. (idle) Reclaim consumed RX frames - only when no data moved
            if (!data_moved) {
                reclaim_rx_frames();
            }
        }

        printf("[XDP-POLL] Main loop ended\n");
    }

    // ========================================================================
    // TX Path
    // ========================================================================

    bool submit_tx_batch() {
        uint32_t tx_idx = 0;
        uint32_t tx_count = 0;
        uint32_t available = 0;

        // First check if any outbox has data before reserving TX slots
        // This avoids reserving slots we won't use (which would desync cached_prod)
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
        // Returns true to continue, false to stop (when TX batch is full)
        auto collect_tx_frames = [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
            (void)seq;  // Unused
            if (tx_count >= available) return false;  // TX batch full

            struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, tx_idx++);
            tx_desc->addr = desc.umem_addr;
            tx_desc->len = desc.frame_len;
            tx_desc->options = 0;
            tx_count++;

#if DEBUG
            fprintf(stderr, "[XDP-TX] Collected frame: addr=0x%lx len=%u\n",
                    (unsigned long)desc.umem_addr, desc.frame_len);
            fflush(stderr);
#endif
            return true;  // Continue processing
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

        // Cancel reservation for unused slots (fix cached_prod desync)
        if (tx_count < available) {
            tx_ring_.cached_prod -= (available - tx_count);
        }

        if (tx_count > 0) {
#if DEBUG
            static uint32_t tx_submit_count = 0;
            tx_submit_count += tx_count;
            fprintf(stderr, "[XDP-TX] Submitted %u frames (total: %u)\n", tx_count, tx_submit_count);
            fflush(stderr);
#endif

            // Conditional kick: only wake kernel if driver needs it (XDP_USE_NEED_WAKEUP)
            if (xsk_ring_prod__needs_wakeup(&tx_ring_)) {
                [[maybe_unused]] int ret = sendto(xsk_fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
#if DEBUG
                fprintf(stderr, "[XDP-TX] Kicked kernel: sendto ret=%d errno=%d tx_prod=%u tx_cons=%u\n",
                        ret, ret < 0 ? errno : 0,
                        *tx_ring_.producer, *tx_ring_.consumer);
                fflush(stderr);
#endif
            }

            // Commit consumers ONLY after successful TX submission
            // This ensures frames are in flight to NIC before we mark them consumed
            if (has_raw) raw_outbox_cons_->commit_manually();
            if (has_ack) ack_outbox_cons_->commit_manually();
            if (has_pong) pong_outbox_cons_->commit_manually();

            return true;  // Data moved
        } else {
            // We had data but couldn't collect any frames
            // cached_prod already reset by lines 362-365 above
            return false;
        }
    }

    // ========================================================================
    // RX Path
    // ========================================================================

    bool process_rx() {
        uint32_t rx_idx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &rx_idx);

        if (nb_pkts == 0) return false;
#if DEBUG
        static uint32_t total_rx = 0;
        total_rx += nb_pkts;
        fprintf(stderr, "[XDP-RX] Received %u packets (total: %u)\n", nb_pkts, total_rx);
        fflush(stderr);
#endif

        uint64_t poll_cycle = rdtscp();

        for (uint32_t i = 0; i < nb_pkts; i++) {
            const struct xdp_desc* rx_desc = xsk_ring_cons__rx_desc(&rx_ring_, rx_idx++);

            // Claim slot in RAW_INBOX (zero-copy: write directly to ring buffer)
            int64_t slot = raw_inbox_prod_->try_claim();
            if (slot < 0) {
                // RAW_INBOX full - critical error in HFT
                fprintf(stderr, "[XDP-POLL] FATAL: RAW_INBOX full\n");
                abort();
            }

            // Write directly to claimed slot (zero-copy)
            auto& desc = (*raw_inbox_prod_)[slot];
            desc.umem_addr = rx_desc->addr;
            desc.frame_len = rx_desc->len;
            desc.nic_frame_poll_cycle = poll_cycle;
            desc.frame_type = FRAME_TYPE_RX;
            desc.consumed = 0;

            // Read NIC timestamp from metadata (if available)
            // Timestamp stored 8 bytes before packet data
            // BPF program uses bpf_xdp_adjust_meta() to store timestamp
            // Layout: [xdp_user_metadata (8 bytes)][packet data]
            //         ^                            ^
            //         data_meta                    data (rx_desc->addr)
            uint64_t* ts_ptr = reinterpret_cast<uint64_t*>(
                static_cast<uint8_t*>(umem_area_) + rx_desc->addr - 8);
            desc.nic_timestamp_ns = *ts_ptr;
            last_rx_timestamp_ns_ = desc.nic_timestamp_ns;  // Track for testing
#if DEBUG
            fprintf(stderr, "[XDP-RX] Frame addr=%lu ts_ptr=%p raw_ts=%lu slot=%ld\n",
                    rx_desc->addr, (void*)ts_ptr, desc.nic_timestamp_ns, slot);
            fflush(stderr);
#endif

            // Publish the claimed slot
            raw_inbox_prod_->publish(slot);

            // RX frames reclaimed via consumer sequence tracking in reclaim_rx_frames()
        }

        xsk_ring_cons__release(&rx_ring_, nb_pkts);
        rx_packets_ += nb_pkts;
        return true;  // Data moved
    }

    // ========================================================================
    // Completion Processing
    // ========================================================================

    void process_completions() {
        uint32_t comp_idx;
        uint32_t nb_completed = xsk_ring_cons__peek(&comp_ring_, COMP_BATCH, &comp_idx);

        if (nb_completed == 0) return;

#if DEBUG
        static uint32_t total_completions = 0;
        static bool first_logged = false;
        total_completions += nb_completed;
        if (!first_logged) {
            // Only log first few batches to avoid spam
            fprintf(stderr, "[XDP-COMP] Got %u completions (total: %u) prod=%u cons=%u\n",
                    nb_completed, total_completions, *comp_ring_.producer, *comp_ring_.consumer);
            if (total_completions > 100) first_logged = true;
        }
        fflush(stderr);
#endif

        for (uint32_t i = 0; i < nb_completed; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring_, comp_idx++);
            uint32_t frame_idx = addr_to_frame_idx(addr, kFrameSize);

#if DEBUG
            // Verify FIFO ordering: completion addresses should be in order
            // This helps detect TX ring corruption or out-of-order completions
            // Design doc specifies abort on FIFO violation (indicates NIC/driver bug)
            if (last_comp_addr_ != 0 && addr < last_comp_addr_) {
                fprintf(stderr, "[XDP-COMP] FATAL: Out-of-order completion! prev=0x%lx curr=0x%lx\n",
                        last_comp_addr_, addr);
                fprintf(stderr, "[XDP-COMP] comp_ring FIFO assumption violated - indicates NIC/driver bug\n");
                std::abort();
            }
            last_comp_addr_ = addr;

            static bool addr_logged = false;
            if (!addr_logged) {
                fprintf(stderr, "[XDP-COMP] addr=0x%lx frame_idx=%u\n", addr, frame_idx);
                if (i > 3) addr_logged = true;
            }
#endif

            // Determine pool and handle accordingly
            if (frame_idx < RX_POOL_END) {
                // RX frame in comp_ring - should NEVER happen
                // RX frames are returned via fill_ring, not comp_ring
                fprintf(stderr, "[XDP-COMP] BUG: RX frame 0x%lx (idx=%u) in comp_ring!\n",
                        addr, frame_idx);
                std::abort();
            } else if (frame_idx < ACK_POOL_END) {
                // ACK frame - release now (no retransmit needed, NIC confirmed send)
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

    // ========================================================================
    // Release ACKed TX Frames (helper, called from process_completions)
    // Advances release_pos for PONG/MSG frames when Transport has ACKed them
    // ========================================================================

    void release_acked_tx_frames() {
        // PONG frames: advance pong_release_pos up to pong_acked_pos
        uint64_t pong_release = conn_state_->tx_frame.pong_release_pos.load(std::memory_order_relaxed);
        uint64_t pong_acked = conn_state_->tx_frame.pong_acked_pos.load(std::memory_order_acquire);
        while (pong_release < pong_acked) {
            conn_state_->tx_frame.pong_release_pos.fetch_add(1, std::memory_order_release);
            pong_release++;
        }

        // MSG frames: advance msg_release_pos up to msg_acked_pos
        uint64_t msg_release = conn_state_->tx_frame.msg_release_pos.load(std::memory_order_relaxed);
        uint64_t msg_acked = conn_state_->tx_frame.msg_acked_pos.load(std::memory_order_acquire);
        while (msg_release < msg_acked) {
            conn_state_->tx_frame.msg_release_pos.fetch_add(1, std::memory_order_release);
            msg_release++;
        }
    }

    // ========================================================================
    // RX Frame Reclaim
    // ========================================================================

    void reclaim_rx_frames() {
        // Read Transport's consumer sequence to know which frames are safe to reclaim
        // Transport advances consumer sequence after processing each frame
        int64_t consumer_pos = raw_inbox_prod_->consumer_sequence();

        // Nothing to reclaim if consumer hasn't advanced past our last release
        if (consumer_pos <= last_released_seq_) return;

        // Calculate how many frames to reclaim
        int64_t to_reclaim = consumer_pos - last_released_seq_;
        if (to_reclaim <= 0) return;

        // Reserve fill ring slots
        uint32_t fill_idx;
        uint32_t available = xsk_ring_prod__reserve(&fill_ring_, static_cast<uint32_t>(to_reclaim), &fill_idx);
        if (available == 0) return;

        // Reclaim frames from RAW_INBOX ring buffer
        // Read descriptor addresses from the ring at positions [last_released_seq_+1, consumer_pos]
        uint32_t reclaimed = 0;
        for (int64_t pos = last_released_seq_ + 1; pos <= consumer_pos && reclaimed < available; pos++) {
            // Get descriptor from ring buffer at this position
            const auto& desc = (*raw_inbox_prod_)[pos];
            uint64_t addr = desc.umem_addr;

            // Return frame to fill ring (mask to frame boundary)
            *xsk_ring_prod__fill_addr(&fill_ring_, fill_idx++) = addr & ~(static_cast<uint64_t>(kFrameSize) - 1);
            reclaimed++;
        }

        if (reclaimed > 0) {
            xsk_ring_prod__submit(&fill_ring_, reclaimed);
            last_released_seq_ += reclaimed;
        }
    }

    // ========================================================================
    // Trickle (igc driver workaround)
    // ========================================================================

    void send_trickle() {
        if constexpr (!kTrickleEnabled) return;
        if (trickle_fd_ < 0) return;
        ::send(trickle_fd_, trickle_packet_, trickle_packet_len_, MSG_DONTWAIT);
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    websocket::xdp::BPFLoader* get_bpf_loader() { return bpf_loader_.get(); }
    const websocket::xdp::BPFLoader* get_bpf_loader() const { return bpf_loader_.get(); }

    struct xsk_socket* get_xsk_socket() { return xsk_; }
    int get_xsk_fd() const { return xsk_fd_; }

    // Fill ring state (for testing)
    uint32_t fill_ring_producer() const { return *fill_ring_.producer; }
    uint32_t fill_ring_consumer() const { return *fill_ring_.consumer; }

    // Debug accessors
    uint32_t tx_ring_debug_cached_prod() const { return tx_ring_.cached_prod; }
    uint32_t tx_ring_debug_cached_cons() const { return tx_ring_.cached_cons; }

    // Last released sequence (for frame reclaim tracking)
    int64_t last_released_seq() const { return last_released_seq_; }

    // Last RX timestamp (for latency measurement)
    uint64_t last_rx_timestamp() const { return last_rx_timestamp_ns_; }

    // Stats
    uint64_t rx_packets() const { return rx_packets_; }
    uint64_t tx_completions() const { return tx_completions_; }

    // ========================================================================
    // Cleanup
    // ========================================================================

    void cleanup() {
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

private:
    // ========================================================================
    // Private Helper Functions
    // ========================================================================

    bool get_interface_mac() {
        int tmp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_fd < 0) return false;

        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, interface_, IFNAMSIZ - 1);

        if (ioctl(tmp_fd, SIOCGIFHWADDR, &ifr) < 0) {
            ::close(tmp_fd);
            return false;
        }
        ::close(tmp_fd);

        memcpy(local_mac_, ifr.ifr_hwaddr.sa_data, 6);
        return true;
    }

    void create_trickle_socket() {
        trickle_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (trickle_fd_ < 0) return;

        struct sockaddr_ll sll = {};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex_;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(trickle_fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
            ::close(trickle_fd_);
            trickle_fd_ = -1;
            return;
        }

        build_trickle_packet();
    }

    void build_trickle_packet() {
        memset(trickle_packet_, 0, sizeof(trickle_packet_));

        // Ethernet header
        memcpy(trickle_packet_, local_mac_, 6);      // dst MAC = self
        memcpy(trickle_packet_ + 6, local_mac_, 6);  // src MAC = self
        trickle_packet_[12] = 0x08;                   // EtherType = IPv4
        trickle_packet_[13] = 0x00;

        // IP header (minimal)
        uint8_t* ip = trickle_packet_ + 14;
        ip[0] = 0x45;  // version=4, IHL=5
        ip[2] = 0x00; ip[3] = 0x1D;  // total length = 29
        ip[6] = 0x40;  // Don't Fragment
        ip[8] = 0x01;  // TTL = 1
        ip[9] = 0x11;  // UDP
        ip[12] = 127; ip[13] = 0; ip[14] = 0; ip[15] = 1;  // src = 127.0.0.1
        ip[16] = 127; ip[17] = 0; ip[18] = 0; ip[19] = 1;  // dst = 127.0.0.1

        // IP checksum
        uint32_t sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += (ip[i] << 8) | ip[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t checksum = ~sum;
        ip[10] = checksum >> 8;
        ip[11] = checksum & 0xFF;

        // UDP header
        uint8_t* udp = ip + 20;
        udp[0] = 0xFF; udp[1] = 0xFE;  // src port = 65534
        udp[2] = 0xFF; udp[3] = 0xFE;  // dst port = 65534
        udp[4] = 0x00; udp[5] = 0x09;  // length = 9
        udp[8] = 0x00;  // payload

        trickle_packet_len_ = 43;
    }

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

    // Ring pointers
    RingProducer* raw_inbox_prod_ = nullptr;
    OutboxConsumer* raw_outbox_cons_ = nullptr;
    OutboxConsumer* ack_outbox_cons_ = nullptr;
    OutboxConsumer* pong_outbox_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // RX frame reclaim tracking (via consumer sequence, no local buffer needed)

    // Trickle
    int trickle_fd_ = -1;
    uint8_t local_mac_[6];
    uint8_t trickle_packet_[64];
    size_t trickle_packet_len_ = 0;

    // Stats
    uint64_t rx_packets_ = 0;
    uint64_t tx_completions_ = 0;

    // For testing/debugging
    int64_t last_released_seq_ = -1;
    uint64_t last_rx_timestamp_ns_ = 0;

#if DEBUG
    // For FIFO ordering verification (design doc: abort on out-of-order)
    uint64_t last_comp_addr_ = 0;
#endif
};

}  // namespace websocket::pipeline
