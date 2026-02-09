// pipeline/00_xdp_poll_process.hpp
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
#include <ctime>
#include "../xdp/bpf_loader.hpp"

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "../core/timing.hpp"
#include "../xdp/packet_frame_descriptor.hpp"

namespace websocket::pipeline {

// ============================================================================
// XDPPollProcess - Core XDP packet I/O handler
//
// Template Parameters:
//   RingProducer   - Producer type for RAW_INBOX (PacketFrameDescriptor)
//   OutboxConsumer - Consumer type for all outbox rings (PacketFrameDescriptor)
//                    Uses frame_type field to distinguish ACK/PONG/MSG frames
//   TrickleEnabled - Enable trickle packets (igc driver workaround), default true
//   FrameHeadroom  - XDP metadata headroom (e.g., 256 for timestamps), default 256
//   MTU            - NIC MTU, frame size computed via calculate_frame_size()
//
// Responsibilities:
// 1. Collect TX packets from RAW_OUTBOX (unified outbox for all TX types)
// 2. Submit TX batch to kernel, kick sendto()
// 3. Receive RX packets from rx_ring, publish to RAW_INBOX with timestamps
// 4. Reclaim consumed RX frames back to fill_ring
// 5. Process completion ring for TX frames
// 6. Send trickle packets for igc driver NAPI workaround
// ============================================================================

template<typename RingProducer,
         typename OutboxConsumer,
         bool TrickleEnabled = true,
         bool Profiling = false,
         uint32_t FrameHeadroom = 256,
         uint32_t MTU = NIC_MTU>
struct XDPPollProcess {
    // Compile-time constants from template args
    static constexpr bool kTrickleEnabled = TrickleEnabled;
    static constexpr bool kProfiling = Profiling;
    static constexpr uint32_t kFrameHeadroom = FrameHeadroom;
    static constexpr uint32_t kFrameSize = calculate_frame_size(MTU);
    static constexpr uint32_t kQueueId = 0;  // Always queue 0

    // Pre-reserve TX slots: min(256, TX_RING_SIZE/4) to avoid exhausting small rings
    static constexpr uint32_t TX_PRESERVE_SIZE =
        (256 < XDP_TX_RING_SIZE / 4) ? 256 : XDP_TX_RING_SIZE / 4;

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
              ConnStateShm* conn_state) {

        umem_area_ = umem_area;
        umem_size_ = umem_size;
        raw_inbox_prod_ = raw_inbox_prod;
        raw_outbox_cons_ = raw_outbox_cons;
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
        xsk_cfg.rx_size = XDP_RX_RING_SIZE;
        xsk_cfg.tx_size = XDP_TX_RING_SIZE;
        xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        xsk_cfg.xdp_flags = 0;
        xsk_cfg.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

        ret = xsk_socket__create(&xsk_, interface_, kQueueId,
                                 umem_, &rx_ring_, &tx_ring_, &xsk_cfg);
        if (ret) {
            if (-ret == EBUSY) {
                fprintf(stderr, "\n");
                fprintf(stderr, "╔══════════════════════════════════════════════════════════════════╗\n");
                fprintf(stderr, "║  FATAL: XDP interface %s is already in use!                 ║\n", interface_);
                fprintf(stderr, "╠══════════════════════════════════════════════════════════════════╣\n");
                fprintf(stderr, "║  Another process has an XSK socket bound to this interface.     ║\n");
                fprintf(stderr, "║                                                                  ║\n");
                fprintf(stderr, "║  To fix, run:                                                    ║\n");
                fprintf(stderr, "║    pkill -9 -f test_pipeline_websocket_binance                   ║\n");
                fprintf(stderr, "║    sudo ip link set %s xdp off                              ║\n", interface_);
                fprintf(stderr, "╚══════════════════════════════════════════════════════════════════╝\n");
                fprintf(stderr, "\n");
            } else {
                fprintf(stderr, "[XDP-POLL] Failed to create XSK socket: %s\n", strerror(-ret));
            }
            xsk_umem__delete(umem_);
            if (bpf_loader_) bpf_loader_->detach();
            return false;
        }

        xsk_fd_ = xsk_socket__fd(xsk_);

        // Initialize RX ring cached values (consumer ring)
        // xsk_socket__create may not initialize these
        rx_ring_.cached_cons = *rx_ring_.consumer;
        rx_ring_.cached_prod = *rx_ring_.producer;

        // Register XSK socket with BPF program
        if (bpf_loader_) {
            try {
                bpf_loader_->register_xsk_socket(xsk_);
            } catch (const std::exception& e) {
                fprintf(stderr, "[XDP-POLL] Failed to register XSK: %s\n", e.what());
                cleanup();
                return false;
            }
        }

        // Enable SO_BUSY_POLL
        int busy_poll = 1;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_PREFER_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        int budget = XDP_BUSY_POLL_BUDGET;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
        int usec = XDP_BUSY_POLL_USEC;
        setsockopt(xsk_fd_, SOL_SOCKET, SO_BUSY_POLL, &usec, sizeof(usec));

        // Populate fill ring with RX pool frames
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

        // Create trickle socket
        if constexpr (kTrickleEnabled) {
            create_trickle_socket();
        }

        // Configure BPF filter with exchange IPs from ConnStateShm
        if (bpf_loader_ && conn_state_ && conn_state_->exchange_ip_count > 0) {
            for (uint8_t i = 0; i < conn_state_->exchange_ip_count; i++) {
                char ip_str[INET_ADDRSTRLEN];
                struct in_addr addr;
                addr.s_addr = conn_state_->exchange_ips[i];
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                bpf_loader_->add_exchange_ip(ip_str);
            }
            bpf_loader_->add_exchange_port(conn_state_->target_port);

            // Set local IP for incoming packet filtering
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock >= 0) {
                struct ifreq ifr = {};
                strncpy(ifr.ifr_name, interface_, IFNAMSIZ - 1);
                if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
                    auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                    bpf_loader_->set_local_ip(ip_str);
                }
                ::close(sock);
            }
        }

        // Signal XDP ready for fork-first architecture
        if (conn_state_) {
            conn_state_->set_handshake_xdp_ready();
        }

        return true;
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        uint8_t trickle_counter = 0;
        uint64_t loop_id = 0;

        // Initial TX slot reservation before entering main loop
        release_and_reserve_tx();

        while (conn_state_->running[PROC_XDP_POLL].flag.load(std::memory_order_acquire)) {
            [[maybe_unused]] uint64_t loop_start = 0;
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                loop_start = rdtsc();
                first_rx_timestamp_ns_ = 0;  // Reset for this iteration
                first_rx_poll_cycle_ = 0;    // Reset for this iteration
                slot = profiling_data_->next_slot();
            }

            // 0. TX submit
            int32_t tx_count = profile_op<Profiling>([this]{ return submit_tx_batch(); }, slot, 0);

            // 1. RX process
            int32_t rx_count = profile_op<Profiling>([this, loop_id]{ return process_rx(loop_id); }, slot, 1);

            bool data_moved = (tx_count > 0) || (rx_count > 0);
            bool tx_starved = (tx_preserved_count_ == 0);

            // 2. Trickle (every 8th iteration)
            bool trickle_triggered = ((++trickle_counter & 0x07) == 0);
            profile_op<Profiling>([this]{ send_trickle(); return 1; }, slot, 2, trickle_triggered);

            // 3. Process completions (idle or TX-starved)
            bool maint_gate = !data_moved || tx_starved;
            [[maybe_unused]] int32_t comp_count = profile_op<Profiling>([this]{ return process_completions(); }, slot, 3, maint_gate);

            // 4. Release ACKed TX frames + Proactive TX reservation (idle or TX-starved)
            [[maybe_unused]] int32_t reserve_count = profile_op<Profiling>([this]{ return release_and_reserve_tx(); }, slot, 4, maint_gate);

            // 5. Reclaim RX frames (idle or TX-starved)
            [[maybe_unused]] int32_t reclaim_count = profile_op<Profiling>([this]{ return reclaim_rx_frames(); }, slot, 5, maint_gate);

            if (tx_starved) {
                tx_starved_count_++;
            } else {
                tx_starved_count_ = 0;
            }

            // Record sample
            if constexpr (Profiling) {
                slot->packet_nic_ns = first_rx_timestamp_ns_;
                slot->nic_poll_cycle = first_rx_poll_cycle_;
                slot->transport_poll_cycle = 0;  // Not used by XDP Poll
                profiling_data_->commit();
            }

            loop_id++;
        }
    }

    // ========================================================================
    // TX Path
    // ========================================================================

    int32_t submit_tx_batch() {
        uint32_t tx_count = 0;

        // Pre-check: any data to send?
        if (!raw_outbox_cons_ || !raw_outbox_cons_->has_data()) {
            return 0;  // Nothing to send
        }

        // Use pre-reserved slots (no reservation here - done in release_and_reserve_tx)
        uint32_t available = tx_preserved_count_;
        uint32_t tx_idx = tx_preserved_idx_;

        if (available == 0) {
            return 0;  // No slots available
        }

        // Collect from RAW_OUTBOX unconditionally
        raw_outbox_cons_->process_manually([&](auto& desc, [[maybe_unused]] int64_t seq) -> bool {
            if (tx_count >= available) {
                return false;  // TX batch full
            }

            struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, tx_idx++);
            tx_desc->addr = desc.frame_ptr;
            tx_desc->len = desc.frame_len;
            tx_desc->options = 0;

            tx_count++;

            return true;
        });

        // Update preserved tracking BEFORE submit
        tx_preserved_idx_ += tx_count;
        tx_preserved_count_ -= tx_count;

        // Submit whatever we collected
        xsk_ring_prod__submit(&tx_ring_, tx_count);

        if (tx_count > 0) {
            // Always kick kernel when we have frames to send
            if (xsk_ring_prod__needs_wakeup(&tx_ring_)) {
                sendto(xsk_fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
            }

            tx_total_submitted_ += tx_count;

            // Commit consumer after successful TX submission
            raw_outbox_cons_->commit_manually();

            return static_cast<int32_t>(tx_count);
        }

        return 0;
    }

    // ========================================================================
    // RX Path
    // ========================================================================

    int32_t process_rx(uint64_t loop_id) {
        uint32_t rx_idx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &rx_idx);

        if (nb_pkts == 0) return 0;

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
            desc.frame_ptr = rx_desc->addr;
            desc.frame_len = rx_desc->len;
            desc.nic_frame_poll_cycle = poll_cycle;
            desc.frame_type = FRAME_TYPE_RX;
            desc.consumed = 0;
            desc.acked = 0;

            // Read XDP metadata from headroom (16 bytes before packet data)
            // BPF program uses bpf_xdp_adjust_meta() to store timestamps
            // Layout: [xdp_user_metadata (16 bytes)][packet data]
            //         ^                              ^
            //         data_meta                      data (rx_desc->addr)
            struct xdp_user_metadata {
                uint64_t rx_timestamp_ns;  // NIC hardware timestamp
                uint64_t bpf_entry_ns;     // BPF entry bpf_ktime_get_ns()
            };
            auto* meta = reinterpret_cast<xdp_user_metadata*>(
                static_cast<uint8_t*>(umem_area_) + rx_desc->addr - sizeof(xdp_user_metadata));
            desc.nic_timestamp_ns = meta->rx_timestamp_ns;
            desc.bpf_entry_ns = meta->bpf_entry_ns;
            last_rx_timestamp_ns_ = desc.nic_timestamp_ns;  // Track for testing
            if (i == 0) {
                first_rx_timestamp_ns_ = desc.nic_timestamp_ns;  // First packet's timestamp for profiling
                first_rx_poll_cycle_ = poll_cycle;               // First packet's poll cycle for profiling
            }

            // Record NIC latency sample (when profiling enabled)
            if constexpr (Profiling) {
                if (nic_latency_data_) {
                    // Get poll timestamps in both clock domains
                    struct timespec ts_mono, ts_real;
                    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
                    clock_gettime(CLOCK_REALTIME, &ts_real);
                    uint64_t poll_timestamp_ns = static_cast<uint64_t>(ts_mono.tv_sec) * 1'000'000'000ULL +
                                                 static_cast<uint64_t>(ts_mono.tv_nsec);
                    uint64_t poll_realtime_ns = static_cast<uint64_t>(ts_real.tv_sec) * 1'000'000'000ULL +
                                                static_cast<uint64_t>(ts_real.tv_nsec);
                    nic_latency_data_->record(desc.nic_timestamp_ns, desc.bpf_entry_ns,
                                              poll_cycle, poll_timestamp_ns, poll_realtime_ns);
                }
            }

#if DEBUG
            fprintf(stderr, "[XDP-RX] Frame addr=%lu meta=%p nic_ts=%lu bpf_ts=%lu slot=%ld\n",
                    rx_desc->addr, (void*)meta, desc.nic_timestamp_ns, desc.bpf_entry_ns, slot);
            fflush(stderr);
#endif

            // Publish the claimed slot
            raw_inbox_prod_->publish(slot);

            // RX frames reclaimed via consumer sequence tracking in reclaim_rx_frames()
        }

        xsk_ring_cons__release(&rx_ring_, nb_pkts);
        rx_packets_ += nb_pkts;
        return static_cast<int32_t>(nb_pkts);  // Return RX frame count
    }

    // ========================================================================
    // Completion Processing
    // ========================================================================

    int32_t process_completions() {
        uint32_t comp_idx;
        uint32_t nb_completed = xsk_ring_cons__peek(&comp_ring_, COMP_BATCH, &comp_idx);

        if (nb_completed == 0) return 0;

        // Just peek and release - Transport handles frame lifecycle via mark_frame_acked()
        xsk_ring_cons__release(&comp_ring_, nb_completed);
        tx_completions_ += nb_completed;
        return static_cast<int32_t>(nb_completed);
    }

    // ========================================================================
    // Release ACKed TX Frames + Proactive TX Reservation (idle loop only)
    // 1. Advances release_pos for PONG/MSG frames when Transport has ACKed them
    // 2. Reserves TX ring slots to maintain TX_PRESERVE_SIZE
    // Returns number of TX slots reserved (for profiling)
    // ========================================================================

    uint32_t release_and_reserve_tx() {
        // Proactive TX slot reservation
        if (tx_preserved_count_ >= TX_PRESERVE_SIZE) return 0;  // Already have enough

        uint32_t needed = TX_PRESERVE_SIZE - tx_preserved_count_;
        uint32_t idx = 0;
        uint32_t got = xsk_ring_prod__reserve(&tx_ring_, needed, &idx);

        if (got == 0) return 0;

        if (tx_preserved_count_ == 0) {
            tx_preserved_idx_ = idx;  // First reservation, save start index
        }
        tx_preserved_count_ += got;
        return got;
    }

    // ========================================================================
    // RX Frame Reclaim
    // ========================================================================

    int32_t reclaim_rx_frames() {
        // Read Transport's consumer sequence to know which frames are safe to reclaim
        // Transport advances consumer sequence after processing each frame
        int64_t consumer_pos = raw_inbox_prod_->consumer_sequence();

        // Nothing to reclaim if consumer hasn't advanced past our last release
        if (consumer_pos <= last_released_seq_) return 0;

        // Calculate how many frames to reclaim
        int64_t to_reclaim = consumer_pos - last_released_seq_;
        if (to_reclaim <= 0) return 0;

        // Reserve fill ring slots
        uint32_t fill_idx;
        uint32_t available = xsk_ring_prod__reserve(&fill_ring_, static_cast<uint32_t>(to_reclaim), &fill_idx);
        if (available == 0) return 0;

        // Reclaim frames from RAW_INBOX ring buffer
        // Read descriptor addresses from the ring at positions [last_released_seq_+1, consumer_pos]
        uint32_t reclaimed = 0;
        for (int64_t pos = last_released_seq_ + 1; pos <= consumer_pos && reclaimed < available; pos++) {
            // Get descriptor from ring buffer at this position
            const auto& desc = (*raw_inbox_prod_)[pos];
            uint64_t addr = desc.frame_ptr;

            // Return frame to fill ring (mask to frame boundary)
            *xsk_ring_prod__fill_addr(&fill_ring_, fill_idx++) = addr & ~(static_cast<uint64_t>(kFrameSize) - 1);
            reclaimed++;
        }

        if (reclaimed > 0) {
            xsk_ring_prod__submit(&fill_ring_, reclaimed);
            last_released_seq_ += reclaimed;
        }
        return static_cast<int32_t>(reclaimed);
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

    // Profiling
    void set_profiling_data(CycleSampleBuffer* data) { profiling_data_ = data; }
    void set_nic_latency_data(NicLatencyBuffer* data) { nic_latency_data_ = data; }

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
    uint64_t tx_total_submitted_ = 0;

    // For testing/debugging
    int64_t last_released_seq_ = -1;
    uint64_t last_rx_timestamp_ns_ = 0;
    uint64_t first_rx_timestamp_ns_ = 0;  // First RX timestamp in current loop iteration (for profiling)
    uint64_t first_rx_poll_cycle_ = 0;    // First RX poll cycle in current loop iteration (for profiling)

    // Profiling data (optional, set via set_profiling_data())
    CycleSampleBuffer* profiling_data_ = nullptr;
    NicLatencyBuffer* nic_latency_data_ = nullptr;

    // Pre-reserved TX slots (proactive reservation in idle loop)
    uint32_t tx_preserved_count_ = 0;   // Current number of preserved slots
    uint32_t tx_preserved_idx_ = 0;     // Starting index of preserved slots

    // TX stall tracking
    uint64_t tx_starved_count_ = 0;     // Consecutive loops with tx_preserved_count_==0

#if DEBUG
    // For FIFO ordering verification (design doc: abort on out-of-order)
    uint64_t last_comp_addr_ = 0;
#endif
};

}  // namespace websocket::pipeline
