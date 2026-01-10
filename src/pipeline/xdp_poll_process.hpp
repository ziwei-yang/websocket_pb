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

#ifdef USE_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include "../xdp/bpf_loader.hpp"
#endif

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

#ifdef USE_XDP

// ============================================================================
// XDPPollProcess - Core XDP packet I/O handler
//
// Template Parameters:
//   RingProducer       - Producer type for RAW_INBOX (UMEMFrameDescriptor)
//   RawOutboxConsumer  - Consumer type for RAW_OUTBOX (UMEMFrameDescriptor)
//   AckOutboxConsumer  - Consumer type for ACK_OUTBOX (AckDescriptor)
//   PongOutboxConsumer - Consumer type for PONG_OUTBOX (PongDescriptor)
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
         typename RawOutboxConsumer,
         typename AckOutboxConsumer = RawOutboxConsumer,
         typename PongOutboxConsumer = RawOutboxConsumer>
struct XDPPollProcess {
    // ========================================================================
    // Configuration
    // ========================================================================

    struct Config {
        const char* interface;
        uint32_t queue_id;
        uint32_t frame_size;
        uint32_t frame_headroom = 0;  // XDP metadata headroom (e.g., 256 for timestamps)
        bool zero_copy;
        bool trickle_enabled = true;  // Enable trickle by default (igc driver workaround)
    };

    // ========================================================================
    // Initialization - Legacy API (without BPF)
    // ========================================================================

    bool init(void* umem_area, size_t umem_size, const Config& config,
              RingProducer* raw_inbox_prod,
              RawOutboxConsumer* raw_outbox_cons,
              AckOutboxConsumer* ack_outbox_cons,
              PongOutboxConsumer* pong_outbox_cons,
              TCPStateShm* tcp_state) {

        return init_internal(umem_area, umem_size, config, nullptr,
                             raw_inbox_prod, raw_outbox_cons,
                             ack_outbox_cons, pong_outbox_cons, tcp_state);
    }

    // ========================================================================
    // Initialization - Fork-first API (with BPF loading)
    // ========================================================================

    bool init_fresh(void* umem_area, size_t umem_size, const Config& config,
                    const char* bpf_path,
                    RingProducer* raw_inbox_prod,
                    RawOutboxConsumer* raw_outbox_cons,
                    AckOutboxConsumer* ack_outbox_cons,
                    PongOutboxConsumer* pong_outbox_cons,
                    TCPStateShm* tcp_state) {

        return init_internal(umem_area, umem_size, config, bpf_path,
                             raw_inbox_prod, raw_outbox_cons,
                             ack_outbox_cons, pong_outbox_cons, tcp_state);
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        printf("[XDP-POLL] Starting main loop\n");

        while (tcp_state_->running[PROC_XDP_POLL].flag.load(std::memory_order_acquire)) {
            // 1. Collect and submit TX packets
            submit_tx_batch();

            // 2. Process RX packets
            process_rx();

            // 3. Process completion ring
            process_completions();

            // 4. Trickle (every N iterations)
            if ((++iteration_count_ & (TRICKLE_INTERVAL_ITERATIONS - 1)) == 0) {
                send_trickle();
            }

            // 5. Reclaim consumed RX frames (idle work)
            reclaim_rx_frames();
        }

        printf("[XDP-POLL] Main loop ended\n");
    }

    // ========================================================================
    // TX Path
    // ========================================================================

    void submit_tx_batch() {
        uint32_t tx_idx = 0;
        uint32_t tx_count = 0;
        uint32_t available = 0;

        // First check if any outbox has data before reserving TX slots
        // This avoids reserving slots we won't use (which would desync cached_prod)
        bool has_raw = raw_outbox_cons_ && raw_outbox_cons_->has_data();
        bool has_ack = ack_outbox_cons_ && ack_outbox_cons_->has_data();
        bool has_pong = pong_outbox_cons_ && pong_outbox_cons_->has_data();

        if (!has_raw && !has_ack && !has_pong) {
            return;  // Nothing to send
        }

        // Reserve TX ring slots
        available = xsk_ring_prod__reserve(&tx_ring_, TX_BATCH_SIZE, &tx_idx);
        if (available == 0) {
#if DEBUG
            static int reserve_fail_count = 0;
            if (++reserve_fail_count % 100000 == 1) {
                uint32_t real_cons = __atomic_load_n(tx_ring_.consumer, __ATOMIC_ACQUIRE);
                fprintf(stderr, "[XDP-TX] TX ring full (count=%d): prod=%u cons=%u real_cons=%u\n",
                        reserve_fail_count, tx_ring_.cached_prod, tx_ring_.cached_cons, real_cons);
                fflush(stderr);
            }
#endif
            return;
        }

        // Collect from RAW_OUTBOX (data packets from Transport)
        if (has_raw) {
            tx_count += collect_from_raw_outbox(&tx_idx, available - tx_count);
        }

        // Collect from ACK_OUTBOX (pure ACKs)
        if (tx_count < available && has_ack) {
            tx_count += collect_from_ack_outbox(&tx_idx, available - tx_count);
        }

        // Collect from PONG_OUTBOX (encrypted PONGs)
        if (tx_count < available && has_pong) {
            tx_count += collect_from_pong_outbox(&tx_idx, available - tx_count);
        }

        // Submit whatever we collected
        xsk_ring_prod__submit(&tx_ring_, tx_count);

        // Cancel reservation for unused slots (fix cached_prod desync)
        if (tx_count < available) {
            // Roll back cached_prod for slots we reserved but didn't use
            tx_ring_.cached_prod -= (available - tx_count);
        }

        if (tx_count > 0) {
#if DEBUG
            static uint32_t tx_submit_count = 0;
            tx_submit_count += tx_count;
            fprintf(stderr, "[XDP-TX] Submitted %u frames (total: %u)\n", tx_count, tx_submit_count);
            fflush(stderr);
#endif

            // Always kick kernel for TX (some drivers need this)
            int ret = sendto(xsk_fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
#if DEBUG
            bool need_wakeup = xsk_ring_prod__needs_wakeup(&tx_ring_);
            fprintf(stderr, "[XDP-TX] Kicked kernel: sendto ret=%d errno=%d need_wakeup=%d tx_prod=%u tx_cons=%u cached_prod=%u cached_cons=%u comp_prod=%u comp_cons=%u\n",
                    ret, ret < 0 ? errno : 0, need_wakeup,
                    *tx_ring_.producer, *tx_ring_.consumer,
                    tx_ring_.cached_prod, tx_ring_.cached_cons,
                    *comp_ring_.producer, *comp_ring_.consumer);
            fflush(stderr);
#endif
        } else {
            // We had data but couldn't collect any - reset cached_prod
            // This happens when outbox reported has_data but try_consume failed
            tx_ring_.cached_prod -= available;  // Undo the reservation
        }
    }

    uint32_t collect_from_raw_outbox(uint32_t* tx_idx, uint32_t max_count) {
        uint32_t count = 0;
        UMEMFrameDescriptor desc;

        while (count < max_count && raw_outbox_cons_->try_consume(desc)) {
            struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, (*tx_idx)++);
            tx_desc->addr = desc.umem_addr;
            tx_desc->len = desc.frame_len;
            tx_desc->options = 0;
            count++;
#if DEBUG
            fprintf(stderr, "[XDP-TX] Collected RAW frame: addr=0x%lx len=%u\n",
                    (unsigned long)desc.umem_addr, desc.frame_len);
            fflush(stderr);
#endif
        }

        return count;
    }

    uint32_t collect_from_ack_outbox(uint32_t* tx_idx, uint32_t max_count) {
        uint32_t count = 0;
        AckDescriptor desc;

        while (count < max_count && ack_outbox_cons_->try_consume(desc)) {
            struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, (*tx_idx)++);
            tx_desc->addr = desc.umem_addr;
            tx_desc->len = desc.frame_len;
            tx_desc->options = 0;

            // ACK frames can be immediately released (no retransmit)
            uint32_t frame_idx = addr_to_frame_idx(desc.umem_addr, config_.frame_size);
            if (frame_idx >= ACK_POOL_START && frame_idx < ACK_POOL_END) {
                tcp_state_->tx_frame.ack_release_pos.fetch_add(1, std::memory_order_relaxed);
            }

            count++;
        }

        return count;
    }

    uint32_t collect_from_pong_outbox(uint32_t* tx_idx, uint32_t max_count) {
        uint32_t count = 0;
        PongDescriptor desc;

        while (count < max_count && pong_outbox_cons_->try_consume(desc)) {
            struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, (*tx_idx)++);
            tx_desc->addr = desc.umem_addr;
            tx_desc->len = desc.frame_len;
            tx_desc->options = 0;
            count++;
        }

        return count;
    }

    // ========================================================================
    // RX Path
    // ========================================================================

    void process_rx() {
        uint32_t rx_idx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &rx_idx);

        if (nb_pkts == 0) return;
#if DEBUG
        static uint32_t total_rx = 0;
        total_rx += nb_pkts;
        fprintf(stderr, "[XDP-RX] Received %u packets (total: %u)\n", nb_pkts, total_rx);
        fflush(stderr);
#endif

        uint64_t poll_cycle = rdtsc();

        for (uint32_t i = 0; i < nb_pkts; i++) {
            const struct xdp_desc* rx_desc = xsk_ring_cons__rx_desc(&rx_ring_, rx_idx++);

            UMEMFrameDescriptor desc;
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
            fprintf(stderr, "[XDP-RX] Frame addr=%lu ts_ptr=%p raw_ts=%lu\n",
                    rx_desc->addr, (void*)ts_ptr, desc.nic_timestamp_ns);
            fflush(stderr);
#endif

            // Publish to RAW_INBOX
#if DEBUG
            fprintf(stderr, "[XDP-RX] Publishing to RAW_INBOX: addr=%lu len=%u raw_inbox_prod=%p\n",
                    desc.umem_addr, desc.frame_len, (void*)raw_inbox_prod_);
            fflush(stderr);
#endif
            if (!raw_inbox_prod_->try_publish(desc)) {
                // RAW_INBOX full - critical error in HFT
                fprintf(stderr, "[XDP-POLL] FATAL: RAW_INBOX full\n");
                abort();
            }
#if DEBUG
            fprintf(stderr, "[XDP-RX] Published successfully\n");
            fflush(stderr);
#endif

            // Track RX frame for later reclaim
            pending_rx_frames_[pending_rx_count_++] = rx_desc->addr;
            if (pending_rx_count_ >= sizeof(pending_rx_frames_) / sizeof(pending_rx_frames_[0])) {
                // Force reclaim if buffer full
                reclaim_rx_frames();
            }
        }

        xsk_ring_cons__release(&rx_ring_, nb_pkts);
        rx_packets_ += nb_pkts;
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
            uint32_t frame_idx = addr_to_frame_idx(addr, config_.frame_size);

#if DEBUG
            static bool addr_logged = false;
            if (!addr_logged) {
                fprintf(stderr, "[XDP-COMP] addr=0x%lx frame_idx=%u\n", addr, frame_idx);
                if (i > 3) addr_logged = true;
            }
#endif

            // Determine pool and handle accordingly
            if (frame_idx < RX_POOL_END) {
                // RX frame - should not happen (RX frames go through RAW_INBOX)
            } else if (frame_idx < ACK_POOL_END) {
                // ACK frame - already released in collect_from_ack_outbox
            } else if (frame_idx < PONG_POOL_END) {
                // PONG frame - release after completion (needs ACK tracking)
                // Transport will advance release pos when ACKed
            } else {
                // MSG frame - release after ACK (handled by Transport)
            }
        }

        xsk_ring_cons__release(&comp_ring_, nb_completed);
        tx_completions_ += nb_completed;
    }

    // ========================================================================
    // RX Frame Reclaim
    // ========================================================================

    void reclaim_rx_frames() {
        if (pending_rx_count_ == 0) return;

        // Check which frames have been consumed by Transport
        uint32_t reclaimed = 0;
        uint32_t fill_idx;

        uint32_t available = xsk_ring_prod__reserve(&fill_ring_, pending_rx_count_, &fill_idx);
        if (available == 0) return;

        for (uint32_t i = 0; i < pending_rx_count_ && reclaimed < available; i++) {
            // For now, immediately reclaim (Transport marks consumed via descriptor)
            // In production: check consumed flag in descriptor
            uint64_t addr = pending_rx_frames_[i];
            *xsk_ring_prod__fill_addr(&fill_ring_, fill_idx++) = addr & ~(config_.frame_size - 1);
            reclaimed++;
        }

        if (reclaimed > 0) {
            xsk_ring_prod__submit(&fill_ring_, reclaimed);
            last_released_seq_ += reclaimed;  // Track for testing

            // Shift remaining pending frames
            if (reclaimed < pending_rx_count_) {
                memmove(pending_rx_frames_, pending_rx_frames_ + reclaimed,
                        (pending_rx_count_ - reclaimed) * sizeof(uint64_t));
            }
            pending_rx_count_ -= reclaimed;
        }
    }

    // ========================================================================
    // Trickle (igc driver workaround)
    // ========================================================================

    void send_trickle() {
        if (!config_.trickle_enabled || trickle_fd_ < 0) return;
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
    // Internal Initialization
    // ========================================================================

    bool init_internal(void* umem_area, size_t umem_size, const Config& config,
                       const char* bpf_path,
                       RingProducer* raw_inbox_prod,
                       RawOutboxConsumer* raw_outbox_cons,
                       AckOutboxConsumer* ack_outbox_cons,
                       PongOutboxConsumer* pong_outbox_cons,
                       TCPStateShm* tcp_state) {

        umem_area_ = umem_area;
        umem_size_ = umem_size;
        config_ = config;
        raw_inbox_prod_ = raw_inbox_prod;
        raw_outbox_cons_ = raw_outbox_cons;
        ack_outbox_cons_ = ack_outbox_cons;
        pong_outbox_cons_ = pong_outbox_cons;
        tcp_state_ = tcp_state;

        // Get interface index
        ifindex_ = if_nametoindex(config.interface);
        if (ifindex_ == 0) {
            fprintf(stderr, "[XDP-POLL] Interface not found: %s\n", config.interface);
            return false;
        }

        // Get interface MAC for trickle packets
        if (!get_interface_mac()) {
            fprintf(stderr, "[XDP-POLL] Failed to get MAC for %s\n", config.interface);
            return false;
        }

        // Load and attach BPF program if path provided
        if (bpf_path) {
            try {
                bpf_loader_ = std::make_unique<websocket::xdp::BPFLoader>();
                bpf_loader_->load(config.interface, bpf_path);
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
        umem_cfg.frame_size = config.frame_size;
        umem_cfg.frame_headroom = config.frame_headroom;
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

        // Configure XDP socket
        struct xsk_socket_config xsk_cfg = {};
        xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        xsk_cfg.xdp_flags = 0;
        xsk_cfg.bind_flags = config.zero_copy
            ? (XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)
            : XDP_COPY;

        ret = xsk_socket__create(&xsk_, config.interface, config.queue_id,
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

        // Enable SO_BUSY_POLL
        int busy_poll = 1;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        int budget = 64;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
        int usec = 1000;
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
            *xsk_ring_prod__fill_addr(&fill_ring_, idx++) = i * config.frame_size;
        }
        xsk_ring_prod__submit(&fill_ring_, RX_FRAMES);

        fprintf(stderr, "[XDP-POLL] After fill ring submit:\n");
        fprintf(stderr, "[XDP-POLL]   Fill: cached_prod=%u cached_cons=%u\n",
                fill_ring_.cached_prod, fill_ring_.cached_cons);
        fprintf(stderr, "[XDP-POLL]   TX:   cached_prod=%u cached_cons=%u\n",
                tx_ring_.cached_prod, tx_ring_.cached_cons);
        fflush(stderr);

        // Create trickle socket
        create_trickle_socket();

        // Signal XDP ready for fork-first architecture
        if (tcp_state_) {
            tcp_state_->set_handshake_xdp_ready();
        }

        printf("[XDP-POLL] Initialized on %s queue %u\n", config.interface, config.queue_id);
        return true;
    }

    bool get_interface_mac() {
        int tmp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_fd < 0) return false;

        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, config_.interface, IFNAMSIZ - 1);

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
    Config config_;
    unsigned int ifindex_ = 0;

    // Ring pointers
    RingProducer* raw_inbox_prod_ = nullptr;
    RawOutboxConsumer* raw_outbox_cons_ = nullptr;
    AckOutboxConsumer* ack_outbox_cons_ = nullptr;
    PongOutboxConsumer* pong_outbox_cons_ = nullptr;
    TCPStateShm* tcp_state_ = nullptr;

    // RX frame reclaim tracking
    uint64_t pending_rx_frames_[256];
    uint32_t pending_rx_count_ = 0;

    // Trickle
    int trickle_fd_ = -1;
    uint8_t local_mac_[6];
    uint8_t trickle_packet_[64];
    size_t trickle_packet_len_ = 0;

    // Stats
    uint64_t rx_packets_ = 0;
    uint64_t tx_completions_ = 0;
    uint32_t iteration_count_ = 0;

    // For testing/debugging
    int64_t last_released_seq_ = -1;
    uint64_t last_rx_timestamp_ns_ = 0;
};

#else  // !USE_XDP

template<typename RingProducer,
         typename RawOutboxConsumer,
         typename AckOutboxConsumer = RawOutboxConsumer,
         typename PongOutboxConsumer = RawOutboxConsumer>
struct XDPPollProcess {
    struct Config {
        const char* interface;
        uint32_t queue_id;
        uint32_t frame_size;
        uint32_t frame_headroom = 0;
        bool zero_copy;
        bool trickle_enabled = true;
    };

    bool init(...) { return false; }
    bool init_fresh(...) { return false; }
    void run() {}
    void cleanup() {}
    void* get_bpf_loader() { return nullptr; }
    uint32_t fill_ring_producer() const { return 0; }
    uint32_t fill_ring_consumer() const { return 0; }
    int64_t last_released_seq() const { return -1; }
    uint64_t last_rx_timestamp() const { return 0; }
    uint64_t rx_packets() const { return 0; }
    uint64_t tx_completions() const { return 0; }
};

#endif  // USE_XDP

}  // namespace websocket::pipeline
