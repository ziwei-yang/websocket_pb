// pipeline/dpdk_packet_io.hpp
// DPDKPacketIO - Single-process DPDK PMD PacketIO Policy for PacketTransport
//
// Implements the PacketIO concept (transport.hpp:532-551) using DPDK PMD
// directly in the same process. No fork, no IPC rings.
//
// Architecture:
//   PacketTransport<DPDKPacketIO>
//       │
//       └── DPDKPacketIO (this file)
//               │
//               └── DPDK PMD → NIC
//
// Replaces the 2-process path:
//   Fork → DPDKPollProcess → IPC rings → PacketTransport<DisruptorPacketIO>
//
// Frame Pool Usage (from pipeline_config.hpp):
//   - RX: Frames [0, RX_FRAMES) — NIC DMA writes directly into UMEM
//   - TX: Frames [RX_FRAMES, TOTAL_UMEM_FRAMES) — unified pool for data + ACKs + retransmits
//
// C++20, policy-based design, single-thread HFT focus
#pragma once

#ifdef USE_DPDK

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_dev.h>
#include <rte_bus.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "../xdp/packet_frame_descriptor.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// DPDK VA constants (also defined in 01_dpdk_poll_process.hpp — guard against double-def)
#ifndef DPDK_PACKET_IO_VA_CONSTANTS
#define DPDK_PACKET_IO_VA_CONSTANTS
inline constexpr uintptr_t DPDK_UMEM_BASE_VA  = 0x200000000ULL;  // 8 GB
inline constexpr uintptr_t DPDK_BASE_VIRTADDR = 0x400000000ULL;  // 16 GB
#endif

// ============================================================================
// DPDKPacketIO Configuration
// ============================================================================

struct DPDKPacketIOConfig {
    const char* interface = nullptr;
    uint32_t queue_id = 0;
    void* umem_area = nullptr;          // Pre-allocated at DPDK_UMEM_BASE_VA (8GB)
    size_t umem_size = 0;
    // For init_packet_io_config() compatibility (transport.hpp:1843)
    const char* bpf_path = nullptr;     // Unused — DPDK uses userspace filter
    bool zero_copy = true;              // Always true
    // For init_with_pio_config() — holds cached IP/MAC when NIC is DPDK-bound
    ConnStateShm* conn_state = nullptr;
};

// ============================================================================
// DPDKPacketIO - Single-process DPDK PMD PacketIO Policy
// ============================================================================

struct DPDKPacketIO {
    using config_type = DPDKPacketIOConfig;

    static constexpr uint32_t kFrameSize = calculate_frame_size(NIC_MTU);
    static constexpr uint16_t kRxBatch = RX_BATCH;
    static constexpr uint16_t kTxBatch = 64;
    static constexpr uint32_t kRxPoolSize = PIPELINE_MAX_CONN * 4096;
    static constexpr uint32_t TX_POOL_START = kRxPoolSize;
    static constexpr uint32_t kTxPoolSize = static_cast<uint32_t>(TX_POOL_SIZE);

    DPDKPacketIO() = default;
    ~DPDKPacketIO() = default;

    // Prevent copying
    DPDKPacketIO(const DPDKPacketIO&) = delete;
    DPDKPacketIO& operator=(const DPDKPacketIO&) = delete;

    // ========================================================================
    // Initialization
    // ========================================================================

    void init(const DPDKPacketIOConfig& config) {
        interface_ = config.interface;
        frame_size_ = kFrameSize;

        // UMEM: use provided area or self-allocate at DPDK_UMEM_BASE_VA
        if (config.umem_area) {
            umem_area_ = static_cast<uint8_t*>(config.umem_area);
            umem_size_ = config.umem_size;
            owns_umem_ = false;
        } else {
            umem_size_ = static_cast<size_t>(kRxPoolSize + kTxPoolSize) * kFrameSize;
            umem_area_ = static_cast<uint8_t*>(
                mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), umem_size_,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_FIXED_NOREPLACE,
                     -1, 0));
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "[DPDK-PIO] Hugepages not available at low VA, trying regular pages\n");
                umem_area_ = static_cast<uint8_t*>(
                    mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), umem_size_,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         -1, 0));
                if (umem_area_ == MAP_FAILED) {
                    throw std::runtime_error("[DPDK-PIO] Cannot allocate UMEM at low VA");
                }
            }
            owns_umem_ = true;
            fprintf(stderr, "[DPDK-PIO] Self-allocated UMEM: %zu bytes at %p\n",
                    umem_size_, static_cast<void*>(umem_area_));
        }

        // Step 1: Resolve PCI address
        if (!resolve_pci_addr(interface_, pci_addr_str_, sizeof(pci_addr_str_))) {
            throw std::runtime_error("[DPDK-PIO] Failed to resolve PCI address");
        }
        fprintf(stderr, "[DPDK-PIO] Interface %s -> PCI %s\n", interface_, pci_addr_str_);

        // Step 2: Initialize EAL
        if (!init_eal()) {
            throw std::runtime_error("[DPDK-PIO] EAL initialization failed");
        }

        // Step 3: Find and configure port
        if (!init_port()) {
            throw std::runtime_error("[DPDK-PIO] Port initialization failed");
        }

        // Step 4: Register UMEM as external memory
        if (!register_external_memory()) {
            throw std::runtime_error("[DPDK-PIO] External memory registration failed");
        }

        // Step 5: Create memory pools
        if (!create_mempools()) {
            throw std::runtime_error("[DPDK-PIO] Mempool creation failed");
        }

        // Step 6: Setup queues and start port
        if (!setup_queues_and_start()) {
            throw std::runtime_error("[DPDK-PIO] Queue setup or port start failed");
        }

        // Step 7: Initialize TX shinfo and heap-allocate RX tracking arrays
        // (kRxPoolSize can be 65536+; PacketTransportMulti embeds MaxConn
        // copies of this struct on the stack — arrays must be on the heap)
        init_tx_shinfo();
        rx_mbuf_ring_ = new struct rte_mbuf*[kRxPoolSize]();
        rx_frame_idx_ring_ = new uint32_t[kRxPoolSize]();
        rx_consumed_ = new bool[kRxPoolSize]();

        // Step 8: Get MAC address and export to ConnStateShm if provided
        rte_eth_macaddr_get(port_id_, &local_mac_);
        if (config.conn_state) {
            memcpy(config.conn_state->local_mac, local_mac_.addr_bytes, 6);
            // Import local IP for ARP replies (is_bpf_enabled() is false so
            // transport won't call set_local_ip())
            if (config.conn_state->local_ip != 0) {
                local_ip_ = config.conn_state->local_ip;
            }
            // Import exchange IPs for userspace filter
            if (config.conn_state->exchange_ip_count > 0) {
                exchange_ip_count_ = config.conn_state->exchange_ip_count;
                for (uint8_t i = 0; i < exchange_ip_count_; i++) {
                    exchange_ips_[i] = config.conn_state->exchange_ips[i];
                }
                exchange_port_ = config.conn_state->target_port;
            }
        }

        // Step 9: Initialize TX pool state
        tx_alloc_pos_ = 0;
        tx_free_pos_ = 0;
        tx_pending_count_ = 0;
        rx_process_pos_ = 0;
        rx_consume_pos_ = 0;
        rx_buffered_count_ = 0;
        rx_buffered_pos_ = 0;
        for (uint32_t i = 0; i < kTxPoolSize; ++i) {
            frame_acked_[i] = false;
            frame_sent_[i] = false;
        }
        // Reset NIC stats to avoid residual counters from previous run
        rte_eth_stats_reset(port_id_);

        fprintf(stderr, "[DPDK-PIO] Initialized: port=%u, frame_size=%u, UMEM=%p, "
                "rx_pool=%u mbufs\n",
                port_id_, frame_size_, static_cast<void*>(umem_area_),
                rte_mempool_avail_count(rx_pool_) + rte_mempool_in_use_count(rx_pool_));
    }

    void close() {
        if (port_started_) {
            struct rte_eth_stats stats;
            if (rte_eth_stats_get(port_id_, &stats) == 0) {
                fprintf(stderr, "[DPDK-PIO] Port stats: RX=%lu TX=%lu RX_err=%lu TX_err=%lu RX_nombuf=%lu ARP_replied=%lu\n",
                        stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors, stats.rx_nombuf,
                        arp_replies_sent_);
            }
            rte_eth_dev_stop(port_id_);
            rte_eth_dev_close(port_id_);
            port_started_ = false;
        }
        if (rx_pool_) {
            rte_mempool_free(rx_pool_);
            rx_pool_ = nullptr;
        }
        if (tx_hdr_pool_) {
            rte_mempool_free(tx_hdr_pool_);
            tx_hdr_pool_ = nullptr;
        }
        if (eal_initialized_) {
            rte_eal_cleanup();
            eal_initialized_ = false;
        }
        delete[] rx_mbuf_ring_;  rx_mbuf_ring_ = nullptr;
        delete[] rx_frame_idx_ring_;  rx_frame_idx_ring_ = nullptr;
        delete[] rx_consumed_;  rx_consumed_ = nullptr;
        if (owns_umem_ && umem_area_) {
            munmap(umem_area_, umem_size_);
            umem_area_ = nullptr;
        }
    }

    // ========================================================================
    // Polling — rte_eth_rx_burst + ARP + filter → buffer descriptors
    // ========================================================================

    int poll_wait() {
        struct rte_mbuf* rx_mbufs[kRxBatch];
        uint16_t nb_rx = rte_eth_rx_burst(port_id_, 0, rx_mbufs, kRxBatch);
        if (nb_rx == 0) {
            rx_buffered_count_ = 0;
            rx_buffered_pos_ = 0;
            return 0;
        }

        uint64_t poll_cycle = rdtscp();

        struct timespec ts_mono;
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        uint64_t mono_ns = static_cast<uint64_t>(ts_mono.tv_sec) * 1'000'000'000ULL +
                           static_cast<uint64_t>(ts_mono.tv_nsec);

        uint16_t buffered = 0;
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf* m = rx_mbufs[i];

            // Handle ARP before filtering
            if (handle_arp(m)) {
                continue;
            }

            // Userspace filter (replaces BPF)
            if (!match_exchange_packet(m)) {
                rte_pktmbuf_free(m);
                continue;
            }

            // Compute UMEM frame index from mbuf
            uint8_t* pkt_data = rte_pktmbuf_mtod(m, uint8_t*);
            uint32_t frame_idx = static_cast<uint32_t>(
                (reinterpret_cast<uint8_t*>(m->buf_addr) - umem_area_) / frame_size_);

            // Build descriptor
            auto& desc = rx_buffered_[buffered];
            desc.clear();
            desc.frame_ptr = reinterpret_cast<uint64_t>(pkt_data);
            desc.frame_len = m->data_len;
            desc.nic_frame_poll_cycle = poll_cycle;
            desc.frame_type = websocket::xdp::FRAME_TYPE_RX;
            desc.nic_timestamp_ns = mono_ns;
            desc.bpf_entry_ns = mono_ns;

            rx_buffered_frame_idx_[buffered] = frame_idx;

            // Hold mbuf until mark_frame_consumed
            rx_mbuf_ring_[frame_idx] = m;

            buffered++;
        }

        rx_buffered_count_ = buffered;
        rx_buffered_pos_ = 0;

        return (buffered > 0) ? 1 : 0;
    }

    // ========================================================================
    // RX Path — iterate buffered descriptors from last poll_wait()
    // ========================================================================

    template<typename Func>
    size_t process_rx_frames(size_t max_frames, Func&& callback) {
        size_t processed = 0;

        while (rx_buffered_pos_ < rx_buffered_count_ && processed < max_frames) {
            uint16_t pos = rx_buffered_pos_;
            auto& desc = rx_buffered_[pos];
            uint32_t frame_idx = rx_buffered_frame_idx_[pos];

            // Track for FIFO release
            uint32_t rel_idx = rx_process_pos_ % kRxPoolSize;
            rx_frame_idx_ring_[rel_idx] = frame_idx;
            rx_process_pos_++;

            callback(static_cast<uint32_t>(processed), desc);
            processed++;
            rx_buffered_pos_++;
        }

        return processed;
    }

    void mark_frame_consumed(uint32_t frame_idx) {
        if (frame_idx >= kRxPoolSize) return;
        rx_consumed_[frame_idx] = true;
        // FIFO release: free mbufs while contiguous consumed
        while (rx_consume_pos_ < rx_process_pos_) {
            uint32_t consume_rel = rx_consume_pos_ % kRxPoolSize;
            uint32_t idx = rx_frame_idx_ring_[consume_rel];
            if (!rx_consumed_[idx]) break;
            if (rx_mbuf_ring_[idx]) {
                rte_pktmbuf_free(rx_mbuf_ring_[idx]);
                rx_mbuf_ring_[idx] = nullptr;
            }
            rx_consumed_[idx] = false;
            rx_consume_pos_++;
        }
    }

    uint32_t get_rx_process_pos() const {
        return rx_process_pos_;
    }

    // ========================================================================
    // TX Path — claim / commit / ack
    // ========================================================================

    template<typename Func>
    uint32_t claim_tx_frames(uint32_t count, Func&& callback) {
        uint32_t claimed = 0;

        for (uint32_t i = 0; i < count; i++) {
            // Check TX pool capacity
            uint32_t in_use = tx_alloc_pos_ - tx_free_pos_;
            if (in_use >= kTxPoolSize) {
                break;
            }

            uint32_t relative_idx = tx_alloc_pos_ % kTxPoolSize;
            uint32_t frame_idx = TX_POOL_START + relative_idx;
            frame_sent_[relative_idx] = false;

            // Setup descriptor with actual pointer
            uint64_t umem_offset = static_cast<uint64_t>(frame_idx) * frame_size_;
            websocket::xdp::PacketFrameDescriptor desc;
            desc.clear();
            desc.frame_ptr = reinterpret_cast<uint64_t>(umem_area_ + umem_offset);
            desc.nic_frame_poll_cycle = rdtsc();
            desc.frame_type = websocket::xdp::FRAME_TYPE_TX_DATA;

            callback(i, desc);

            // Store for commit
            tx_pending_descs_[claimed] = desc;
            tx_pending_frame_idx_[claimed] = frame_idx;

            tx_alloc_pos_++;
            claimed++;
        }

        tx_pending_count_ = claimed;
        return claimed;
    }

    void commit_tx_frames([[maybe_unused]] uint32_t lowest_idx, [[maybe_unused]] uint32_t highest_idx) {
        if (tx_pending_count_ == 0) return;

        struct rte_mbuf* tx_mbufs[kTxBatch];
        uint16_t tx_count = 0;

        for (uint32_t i = 0; i < tx_pending_count_ && tx_count < kTxBatch; i++) {
            auto& desc = tx_pending_descs_[i];
            uint32_t frame_idx = tx_pending_frame_idx_[i];
            uint32_t relative_idx = (frame_idx - TX_POOL_START) % kTxPoolSize;

            struct rte_mbuf* m = rte_pktmbuf_alloc(tx_hdr_pool_);
            if (!m) {
                fprintf(stderr, "[DPDK-PIO] TX header alloc failed\n");
                break;
            }

            // Attach UMEM frame as external buffer — zero-copy
            uint8_t* frame_data = reinterpret_cast<uint8_t*>(desc.frame_ptr);
            rte_mbuf_ext_refcnt_set(&tx_shinfo_[relative_idx], 1);
            rte_pktmbuf_attach_extbuf(m, frame_data,
                rte_mem_virt2iova(frame_data),
                frame_size_, &tx_shinfo_[relative_idx]);

            m->data_off = 0;
            m->data_len = desc.frame_len;
            m->pkt_len = desc.frame_len;

            frame_sent_[relative_idx] = true;
            tx_mbufs[tx_count++] = m;
        }

        if (tx_count > 0) {
            uint16_t sent = rte_eth_tx_burst(port_id_, 0, tx_mbufs, tx_count);
            for (uint16_t i = sent; i < tx_count; i++) {
                rte_pktmbuf_free(tx_mbufs[i]);
            }
        }

        tx_pending_count_ = 0;
    }

    template<typename Func>
    uint32_t commit_ack_frame(Func&& callback) {
        uint32_t frame_idx = 0;
        uint32_t claimed = claim_tx_frames(1, [&](uint32_t, websocket::xdp::PacketFrameDescriptor& desc) {
            frame_idx = frame_ptr_to_idx(desc.frame_ptr);
            desc.frame_type = websocket::xdp::FRAME_TYPE_TX_ACK;
            callback(desc);
        });
        if (claimed > 0) {
            commit_tx_frames(frame_idx, frame_idx);
            mark_frame_acked(frame_idx);
            return frame_idx;
        }
        return 0;
    }

    void mark_frame_acked(uint32_t frame_idx) {
        if (frame_idx < TX_POOL_START || frame_idx >= TX_POOL_START + kTxPoolSize) return;

        uint32_t relative_idx = (frame_idx - TX_POOL_START) % kTxPoolSize;
        frame_acked_[relative_idx] = true;

        // FIFO release: advance tx_free_pos_ while contiguous frames are acked
        while (tx_free_pos_ < tx_alloc_pos_) {
            uint32_t free_rel = tx_free_pos_ % kTxPoolSize;
            if (!frame_acked_[free_rel]) break;
            frame_acked_[free_rel] = false;
            frame_sent_[free_rel] = false;
            tx_free_pos_++;
        }
    }

    ssize_t retransmit_frame(uint32_t idx, uint16_t len) {
        // Guard: skip if frame not yet committed
        if (idx >= TX_POOL_START && idx < TX_POOL_START + kTxPoolSize) {
            uint32_t relative_idx = (idx - TX_POOL_START) % kTxPoolSize;
            if (!frame_sent_[relative_idx]) {
                return len;  // Not an error, just not ready
            }
        }

        // Alloc header mbuf, attach existing UMEM frame, tx_burst
        struct rte_mbuf* m = rte_pktmbuf_alloc(tx_hdr_pool_);
        if (!m) return -1;

        uint64_t umem_offset = static_cast<uint64_t>(idx) * frame_size_;
        uint8_t* frame_data = umem_area_ + umem_offset;
        uint32_t relative_idx = (idx - TX_POOL_START) % kTxPoolSize;

        rte_mbuf_ext_refcnt_set(&tx_shinfo_[relative_idx], 1);
        rte_pktmbuf_attach_extbuf(m, frame_data,
            rte_mem_virt2iova(frame_data),
            frame_size_, &tx_shinfo_[relative_idx]);

        m->data_off = 0;
        m->data_len = len;
        m->pkt_len = len;

        uint16_t sent = rte_eth_tx_burst(port_id_, 0, &m, 1);
        if (sent == 0) {
            rte_pktmbuf_free(m);
            return -1;
        }
        return len;
    }

    // ========================================================================
    // Frame Utilities
    // ========================================================================

    uint32_t frame_ptr_to_idx(uint64_t frame_ptr) const {
        return static_cast<uint32_t>((frame_ptr - reinterpret_cast<uint64_t>(umem_area_)) / frame_size_);
    }

    uint64_t frame_idx_to_addr(uint32_t idx) const {
        return static_cast<uint64_t>(idx) * frame_size_;
    }

    uint8_t* get_frame_ptr(uint64_t addr) {
        return umem_area_ + addr;
    }

    uint32_t frame_capacity() const {
        return frame_size_;
    }

    // ========================================================================
    // BPF Filter / Exchange IP Configuration
    // ========================================================================

    void add_remote_ip(const char* ip) {
        if (exchange_ip_count_ >= 8) return;
        struct in_addr addr;
        if (inet_pton(AF_INET, ip, &addr) == 1) {
            exchange_ips_[exchange_ip_count_++] = addr.s_addr;
        }
    }

    void add_remote_port(uint16_t port) {
        exchange_port_ = port;
    }

    void set_local_ip(const char* ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip, &addr) == 1) {
            local_ip_ = addr.s_addr;
        }
    }

    bool is_bpf_enabled() const { return false; }
    void print_stats() const {}
    void stop_rx_trickle_thread() {}

    // ========================================================================
    // Accessors
    // ========================================================================

    const char* get_mode() const { return "DPDK-PMD"; }
    const char* get_interface() const { return interface_; }
    uint32_t get_queue_id() const { return 0; }
    uint32_t get_frame_size() const { return frame_size_; }
    void* get_umem_area() { return umem_area_; }
    size_t get_umem_size() const { return umem_size_; }

private:
    // ========================================================================
    // DPDK Initialization Helpers
    // ========================================================================

    static size_t detect_page_size(const void* addr) {
        FILE* f = fopen("/proc/self/smaps", "r");
        if (!f) return sysconf(_SC_PAGESIZE);

        uintptr_t target = reinterpret_cast<uintptr_t>(addr);
        char line[256];
        bool in_region = false;
        size_t result = sysconf(_SC_PAGESIZE);

        while (fgets(line, sizeof(line), f)) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                in_region = (target >= start && target < end);
            }
            if (in_region && strncmp(line, "KernelPageSize:", 15) == 0) {
                unsigned long kps = 0;
                if (sscanf(line + 15, "%lu", &kps) == 1 && kps > 0) {
                    result = kps * 1024;
                }
                break;
            }
        }
        fclose(f);
        fprintf(stderr, "[DPDK-PIO] UMEM page size: %zu bytes\n", result);
        return result;
    }

    static bool resolve_pci_addr(const char* interface, char* buf, size_t buf_size) {
        // Case 1: Already a PCI address
        if (strlen(interface) >= 10 && interface[4] == ':' && interface[7] == ':' && interface[10] == '.') {
            snprintf(buf, buf_size, "%s", interface);
            return true;
        }

        // Case 2: Interface name — resolve via sysfs
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/net/%s/device", interface);

        char link_target[256];
        ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
        if (len >= 0) {
            link_target[len] = '\0';
            const char* pci = strrchr(link_target, '/');
            if (pci) {
                pci++;
                snprintf(buf, buf_size, "%s", pci);
                return true;
            }
        }

        // Case 3: NIC already bound to DPDK — try cached PCI address
        char cache_path[256];
        snprintf(cache_path, sizeof(cache_path), "/tmp/dpdk_pci_%s", interface);
        FILE* f = fopen(cache_path, "r");
        if (f) {
            if (fgets(buf, buf_size, f)) {
                size_t slen = strlen(buf);
                if (slen > 0 && buf[slen-1] == '\n') buf[slen-1] = '\0';
                fclose(f);
                return strlen(buf) > 0;
            }
            fclose(f);
        }

        return false;
    }

    bool init_eal() {
        char core_arg[16];
        snprintf(core_arg, sizeof(core_arg), "%d", sched_getcpu());

        char allow_arg[64];
        snprintf(allow_arg, sizeof(allow_arg), "%s", pci_addr_str_);

        char base_va_arg[32];
        snprintf(base_va_arg, sizeof(base_va_arg), "0x%lx", DPDK_BASE_VIRTADDR);

        const char* argv[] = {
            "dpdk-pio",
            "-l", core_arg,
            "-a", allow_arg,
            "--iova-mode", "va",
            "--base-virtaddr", base_va_arg,
            "--file-prefix", "hft",
            "--socket-mem", "64",
            "--log-level", "lib.eal:error",
            "--log-level", "pmd:error",
            nullptr
        };
        int argc = 0;
        while (argv[argc]) argc++;

        char* mutable_argv[32];
        for (int i = 0; i < argc; i++) {
            mutable_argv[i] = const_cast<char*>(argv[i]);
        }

        int ret = rte_eal_init(argc, mutable_argv);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
            return false;
        }

        eal_initialized_ = true;
        fprintf(stderr, "[DPDK-PIO] EAL: iova-mode=va, base-virtaddr=%s, UMEM VA=%p\n",
                base_va_arg, static_cast<void*>(umem_area_));
        return true;
    }

    bool init_port() {
        uint16_t nb_ports = rte_eth_dev_count_avail();
        if (nb_ports == 0) {
            fprintf(stderr, "[DPDK-PIO] No DPDK ports available. Is NIC bound to vfio-pci?\n");
            return false;
        }

        port_id_ = rte_eth_find_next(0);
        if (port_id_ >= RTE_MAX_ETHPORTS) {
            fprintf(stderr, "[DPDK-PIO] No ports found (EAL allowed: %s)\n", pci_addr_str_);
            return false;
        }

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);
        fprintf(stderr, "[DPDK-PIO] Port %u: %s (driver: %s)\n",
                port_id_, rte_dev_name(dev_info.device), dev_info.driver_name);

        return true;
    }

    bool register_external_memory() {
        size_t page_size = detect_page_size(umem_area_);
        size_t reg_size = (umem_size_ + page_size - 1) & ~(page_size - 1);

        // Fault in all pages
        unsigned int n_pages = reg_size / page_size;
        for (unsigned int i = 0; i < n_pages; i++) {
            *reinterpret_cast<volatile uint8_t*>(umem_area_ + i * page_size) = 0;
        }

        int ret = rte_extmem_register(umem_area_, reg_size, nullptr, 0, page_size);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] rte_extmem_register failed: %s\n",
                    rte_strerror(rte_errno));
            return false;
        }

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);

        rte_iova_t iova = reinterpret_cast<rte_iova_t>(umem_area_);
        ret = rte_dev_dma_map(dev_info.device, umem_area_, iova, reg_size);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] rte_dev_dma_map failed (va=%p, size=%zu): %s\n",
                    static_cast<void*>(umem_area_), reg_size, rte_strerror(rte_errno));
            return false;
        }

        fprintf(stderr, "[DPDK-PIO] Registered+DMA mapped %zu bytes (%u pages) at VA %p\n",
                reg_size, n_pages, static_cast<void*>(umem_area_));
        return true;
    }

    struct RxPoolInitCtx {
        uint8_t* umem_area;
        uint32_t frame_size;
    };

    static void rx_mbuf_umem_init(struct rte_mempool* /*mp*/, void* opaque,
                                   void* obj, unsigned obj_idx) {
        auto* ctx = static_cast<RxPoolInitCtx*>(opaque);
        auto* m = static_cast<struct rte_mbuf*>(obj);

        m->buf_addr = ctx->umem_area + obj_idx * ctx->frame_size;
        m->buf_iova = reinterpret_cast<rte_iova_t>(m->buf_addr);
        m->buf_len = ctx->frame_size;
        m->data_off = RTE_PKTMBUF_HEADROOM;
    }

    bool create_mempools() {
        int socket_id = rte_eth_dev_socket_id(port_id_);
        if (socket_id < 0) socket_id = 0;

        // data_room_size=0: buf_addr is overridden by rx_mbuf_umem_init to point
        // into external UMEM, so DPDK-allocated data room is unused. This keeps
        // pool allocation small (~8MB for 65536 mbufs) instead of 264MB.
        rx_pool_ = rte_pktmbuf_pool_create("RX_POOL",
            kRxPoolSize,
            0, 0, 0, socket_id);

        if (!rx_pool_) {
            fprintf(stderr, "[DPDK-PIO] RX pool creation failed (n=%u): %s\n",
                    kRxPoolSize, rte_strerror(rte_errno));
            return false;
        }

        RxPoolInitCtx ctx{umem_area_, frame_size_};
        rte_mempool_obj_iter(rx_pool_, rx_mbuf_umem_init, &ctx);

        // Override pool-private mbuf_data_room_size so rte_eth_rx_queue_setup
        // sees our actual UMEM frame size (not the 0 from pool creation).
        auto* mbp_priv = rte_mempool_get_priv(rx_pool_);
        static_cast<struct rte_pktmbuf_pool_private*>(mbp_priv)->mbuf_data_room_size =
            static_cast<uint16_t>(frame_size_);

        fprintf(stderr, "[DPDK-PIO] RX pool: %u mbufs, frame_size=%u, buf_addr -> UMEM VA %p\n",
                kRxPoolSize, frame_size_, static_cast<void*>(umem_area_));

        tx_hdr_pool_ = rte_pktmbuf_pool_create("TX_HDR_POOL",
            static_cast<uint32_t>(TX_POOL_SIZE),
            0, 0, 0, socket_id);

        if (!tx_hdr_pool_) {
            fprintf(stderr, "[DPDK-PIO] TX header pool creation failed: %s\n",
                    rte_strerror(rte_errno));
            return false;
        }

        return true;
    }

    bool setup_queues_and_start() {
        int socket_id = rte_eth_dev_socket_id(port_id_);
        if (socket_id < 0) socket_id = 0;

        struct rte_eth_conf port_conf = {};
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);

        int ret = rte_eth_dev_configure(port_id_, 1, 1, &port_conf);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] rte_eth_dev_configure failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        // RX queue
        struct rte_eth_rxconf rx_conf = dev_info.default_rxconf;
        ret = rte_eth_rx_queue_setup(port_id_, 0, 1024, socket_id, &rx_conf, rx_pool_);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] RX queue setup failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        // TX queue
        struct rte_eth_txconf tx_conf = dev_info.default_txconf;
        static constexpr uint16_t kTxRingSize = 256;
        ret = rte_eth_tx_queue_setup(port_id_, 0, kTxRingSize, socket_id, &tx_conf);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] TX queue setup failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        ret = rte_eth_dev_start(port_id_);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-PIO] rte_eth_dev_start failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }
        port_started_ = true;

        rte_eth_promiscuous_enable(port_id_);

        // Wait for link up
        struct rte_eth_link link;
        for (int i = 0; i < 100; i++) {
            rte_eth_link_get_nowait(port_id_, &link);
            if (link.link_status) break;
            usleep(100'000);
        }
        fprintf(stderr, "[DPDK-PIO] Link: %s, speed %u Mbps, %s\n",
                link.link_status ? "UP" : "DOWN",
                link.link_speed,
                link.link_duplex ? "full-duplex" : "half-duplex");
        if (!link.link_status) {
            fprintf(stderr, "[DPDK-PIO] WARNING: Link is still down after 10s\n");
        }

        return true;
    }

    void init_tx_shinfo() {
        for (size_t i = 0; i < TX_POOL_SIZE; i++) {
            tx_shinfo_[i].free_cb = noop_free_cb;
            tx_shinfo_[i].fcb_opaque = nullptr;
            rte_mbuf_ext_refcnt_set(&tx_shinfo_[i], 1);
        }
    }

    static void noop_free_cb(void* /*addr*/, void* /*opaque*/) {}

    // ========================================================================
    // ARP Responder
    // ========================================================================

    bool handle_arp(struct rte_mbuf* m) {
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))
            return false;

        auto* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
        if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
            return false;

        auto* arp = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr*,
                                              sizeof(struct rte_ether_hdr));

        if (arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            rte_pktmbuf_free(m);
            return true;
        }

        if (arp->arp_data.arp_tip != local_ip_) {
            rte_pktmbuf_free(m);
            return true;
        }

        // Build ARP reply in place
        rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
        rte_ether_addr_copy(&local_mac_, &eth->src_addr);

        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
        uint32_t sender_ip = arp->arp_data.arp_sip;
        arp->arp_data.arp_tip = sender_ip;

        rte_ether_addr_copy(&local_mac_, &arp->arp_data.arp_sha);
        arp->arp_data.arp_sip = local_ip_;

        uint16_t sent = rte_eth_tx_burst(port_id_, 0, &m, 1);
        if (sent == 0) {
            rte_pktmbuf_free(m);
        } else {
            arp_replies_sent_++;
        }

        return true;
    }

    // ========================================================================
    // Userspace Packet Filter
    // ========================================================================

    bool match_exchange_packet(struct rte_mbuf* m) const {
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
            return false;

        const auto* eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr*);
        if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            return false;

        const auto* ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr*,
                                                   sizeof(struct rte_ether_hdr));
        if (ip->next_proto_id != IPPROTO_TCP)
            return false;

        return is_exchange_ip(ip->src_addr) || is_exchange_ip(ip->dst_addr);
    }

    bool is_exchange_ip(uint32_t ip_addr) const {
        for (uint8_t i = 0; i < exchange_ip_count_; i++) {
            if (exchange_ips_[i] == ip_addr) return true;
        }
        return false;
    }

    // ========================================================================
    // Member Variables
    // ========================================================================

    // DPDK
    uint16_t port_id_ = 0;
    struct rte_mempool* rx_pool_ = nullptr;
    struct rte_mempool* tx_hdr_pool_ = nullptr;
    bool port_started_ = false;
    bool eal_initialized_ = false;

    // UMEM
    uint8_t* umem_area_ = nullptr;
    size_t umem_size_ = 0;
    uint32_t frame_size_ = kFrameSize;
    bool owns_umem_ = false;

    // Configuration
    const char* interface_ = nullptr;
    char pci_addr_str_[32] = {};

    // RX: buffered from last poll_wait()
    websocket::xdp::PacketFrameDescriptor rx_buffered_[RX_BATCH];
    uint32_t rx_buffered_frame_idx_[RX_BATCH];
    uint16_t rx_buffered_count_ = 0;
    uint16_t rx_buffered_pos_ = 0;

    // RX: held mbufs and FIFO release tracking (heap-allocated — kRxPoolSize
    // can be 65536+, and PacketTransportMulti embeds MaxConn copies of this struct)
    struct rte_mbuf** rx_mbuf_ring_ = nullptr;      // [kRxPoolSize]
    uint32_t* rx_frame_idx_ring_ = nullptr;          // [kRxPoolSize]
    uint32_t rx_process_pos_ = 0;
    uint32_t rx_consume_pos_ = 0;
    bool* rx_consumed_ = nullptr;                    // [kRxPoolSize]

    // TX pool [RX_FRAMES, TOTAL_UMEM_FRAMES)
    uint32_t tx_alloc_pos_ = 0;
    uint32_t tx_free_pos_ = 0;
    bool frame_acked_[TX_POOL_SIZE] = {};
    bool frame_sent_[TX_POOL_SIZE] = {};
    struct rte_mbuf_ext_shared_info tx_shinfo_[TX_POOL_SIZE] = {};

    // TX pending (claim -> commit two-phase)
    websocket::xdp::PacketFrameDescriptor tx_pending_descs_[64];
    uint32_t tx_pending_frame_idx_[64];
    uint32_t tx_pending_count_ = 0;

    // ARP / filter
    struct rte_ether_addr local_mac_ = {};
    uint32_t local_ip_ = 0;
    uint32_t exchange_ips_[8] = {};
    uint8_t exchange_ip_count_ = 0;
    uint16_t exchange_port_ = 0;

    // Stats
    uint64_t arp_replies_sent_ = 0;
};

}  // namespace websocket::pipeline

#else  // !USE_DPDK

#include <stdexcept>

namespace websocket::pipeline {

// Stub when DPDK is not enabled
struct DPDKPacketIOConfig {
    const char* interface = nullptr;
    const char* bpf_path = nullptr;
    bool zero_copy = true;
};

struct DPDKPacketIO {
    using config_type = DPDKPacketIOConfig;

    void init(const DPDKPacketIOConfig&) {
        throw std::runtime_error("DPDK support not compiled. Build with USE_DPDK=1");
    }
    void close() {}
};

}  // namespace websocket::pipeline

#endif  // USE_DPDK
