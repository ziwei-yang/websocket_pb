// pipeline/01_dpdk_poll_process.hpp
// DPDK Poll Process - PMD-based NIC I/O for zero-copy packet handling
// Drop-in replacement for XDPPollProcess, selectable via USE_DPDK=1
//
// Differences from XDP:
// - No BPF program (userspace packet filter replaces eBPF)
// - No trickle (DPDK PMD drives NIC directly, no NAPI coalescing bug)
// - No fill/completion ring overhead (DPDK manages mbuf pools internally)
// - No sendto() kick on TX (rte_eth_tx_burst directly submits)
// - Shared UMEM registered as DPDK external memory via rte_extmem_register
//
// C++20, policy-based design, single-thread HFT focus
#pragma once

#ifdef USE_DPDK

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>

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
#include "../core/timing.hpp"
#include "../xdp/packet_frame_descriptor.hpp"

namespace websocket::pipeline {

// ============================================================================
// DPDK Low-VA allocation
//
// The Intel IOMMU on this system has SAGAW=39 (bits [12:8] of cap register),
// meaning DMA addresses are limited to 2^39 = 512 GB. Linux mmap places
// hugepages at VAs in the TB range by default, causing "Access beyond MGAW"
// DMA faults.
//
// Fix: allocate shared UMEM at a fixed low VA, and use --iova-mode=va so
// IOVA == VA. All addresses stay below 512 GB.
// ============================================================================

// UMEM at 8 GB, DPDK internals at 16 GB via --base-virtaddr.
// DPDK reserves 4 × 16 GB VA blocks for memseg lists, so it needs
// 16 GB + 64 GB = 80 GB range — all below the 512 GB IOMMU limit.
// UMEM at 8 GB is safely before DPDK's 16 GB start.
inline constexpr uintptr_t DPDK_UMEM_BASE_VA  = 0x200000000ULL;  // 8 GB
inline constexpr uintptr_t DPDK_BASE_VIRTADDR = 0x400000000ULL;  // 16 GB

// ============================================================================
// DPDKPollProcess - DPDK PMD packet I/O handler
//
// Template Parameters:
//   RingProducer   - Producer type for RAW_INBOX (PacketFrameDescriptor)
//   OutboxConsumer - Consumer type for RAW_OUTBOX (PacketFrameDescriptor)
//   Profiling      - Enable profiling/timing collection
//   MTU            - NIC MTU, frame size computed via calculate_frame_size()
//
// Responsibilities:
// 1. Collect TX packets from RAW_OUTBOX, wrap in extbuf mbufs, rte_eth_tx_burst()
// 2. Receive RX packets via rte_eth_rx_burst(), publish to RAW_INBOX with timestamps
// 3. Reclaim consumed RX mbufs when Transport advances consumer_sequence
// ============================================================================

template<typename RingProducer,
         typename OutboxConsumer,
         bool Profiling = false,
         uint32_t MTU = NIC_MTU>
struct DPDKPollProcess {
    // Compile-time constants
    static constexpr bool kProfiling = Profiling;
    static constexpr uint32_t kFrameSize = calculate_frame_size(MTU);
    static constexpr uint16_t kRxBatch = RX_BATCH;
    static constexpr uint16_t kTxBatch = 64;

    // ========================================================================
    // Constructor
    // ========================================================================

    explicit DPDKPollProcess(const char* interface) : interface_(interface) {}

    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(void* umem_area, size_t umem_size,
              const char* /*bpf_path — ignored for DPDK*/,
              RingProducer* raw_inbox_prod,
              OutboxConsumer* raw_outbox_cons,
              ConnStateShm* conn_state) {

        umem_area_ = static_cast<uint8_t*>(umem_area);
        umem_size_ = umem_size;
        raw_inbox_prod_ = raw_inbox_prod;
        raw_outbox_cons_ = raw_outbox_cons;
        conn_state_ = conn_state;

        // Step 1: Resolve PCI address from interface name
        if (!resolve_pci_addr(interface_, pci_addr_str_, sizeof(pci_addr_str_))) {
            fprintf(stderr, "[DPDK-POLL] Failed to resolve PCI address for %s\n", interface_);
            return false;
        }
        fprintf(stderr, "[DPDK-POLL] Interface %s -> PCI %s\n", interface_, pci_addr_str_);

        // Step 2: Initialize DPDK EAL
        if (!init_eal()) {
            fprintf(stderr, "[DPDK-POLL] EAL initialization failed\n");
            return false;
        }

        // Step 3: Find and configure the Ethernet device
        if (!init_port()) {
            fprintf(stderr, "[DPDK-POLL] Port initialization failed\n");
            return false;
        }

        // Step 4: Register shared UMEM as external memory
        if (!register_external_memory()) {
            fprintf(stderr, "[DPDK-POLL] External memory registration failed\n");
            return false;
        }

        // Step 5: Create memory pools
        if (!create_mempools()) {
            fprintf(stderr, "[DPDK-POLL] Mempool creation failed\n");
            return false;
        }

        // Step 6: Setup RX/TX queues and start port
        if (!setup_queues_and_start()) {
            fprintf(stderr, "[DPDK-POLL] Queue setup or port start failed\n");
            return false;
        }

        // Step 7: Initialize TX extbuf shared info (free_cb = noop) and clear RX mbuf ring
        init_tx_shinfo();
        memset(rx_mbuf_ring_, 0, sizeof(rx_mbuf_ring_));

        // Step 8: Export MAC address to ConnStateShm and store locally for ARP
        {
            rte_eth_macaddr_get(port_id_, &local_mac_);
            if (conn_state_) {
                memcpy(conn_state_->local_mac, local_mac_.addr_bytes, 6);
            }
        }

        // Step 9: Store local IP for ARP replies (from ConnStateShm)
        if (conn_state_) {
            local_ip_ = conn_state_->local_ip;
        }

        // Step 10: Populate exchange IP filter table from ConnStateShm
        if (conn_state_ && conn_state_->exchange_ip_count > 0) {
            exchange_ip_count_ = conn_state_->exchange_ip_count;
            for (uint8_t i = 0; i < exchange_ip_count_; i++) {
                exchange_ips_[i] = conn_state_->exchange_ips[i];
            }
            exchange_port_ = conn_state_->target_port;
        }

        // Step 11: Signal ready
        if (conn_state_) {
            conn_state_->set_handshake_xdp_ready();  // Reuses same handshake flag
        }

        fprintf(stderr, "[DPDK-POLL] Initialized: port=%u, RX pool=%u mbufs, TX hdr pool=%u mbufs, local_ip=%u.%u.%u.%u\n",
                port_id_, static_cast<uint32_t>(RX_FRAMES), static_cast<uint32_t>(TX_POOL_SIZE),
                local_ip_ & 0xFF, (local_ip_ >> 8) & 0xFF,
                (local_ip_ >> 16) & 0xFF, (local_ip_ >> 24) & 0xFF);
        return true;
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        uint64_t loop_id = 0;

        while (conn_state_->running[PROC_XDP_POLL].flag.load(std::memory_order_acquire)) {
            [[maybe_unused]] uint64_t loop_start = 0;
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                loop_start = rdtsc();
                first_rx_timestamp_ns_ = 0;
                first_rx_poll_cycle_ = 0;
                slot = profiling_data_->next_slot();
            }

            // 0. TX submit
            int32_t tx_count = profile_op<Profiling>(
                [this]{ return submit_tx_batch(); }, slot, 0);

            // 1. RX process
            int32_t rx_count = profile_op<Profiling>(
                [this, loop_id]{ return process_rx(loop_id); }, slot, 1);

            bool data_moved = (tx_count > 0) || (rx_count > 0);

            // 2. Reclaim RX frames (idle only — no trickle, no completion ring)
            bool maint_gate = !data_moved;
            profile_op<Profiling>(
                [this]{ return reclaim_rx_frames(); }, slot, 5, maint_gate);

            // Record sample
            if constexpr (Profiling) {
                slot->packet_nic_ns = first_rx_timestamp_ns_;
                slot->nic_poll_cycle = first_rx_poll_cycle_;
                slot->transport_poll_cycle = 0;
                profiling_data_->commit();
            }

            loop_id++;
        }
    }

    // ========================================================================
    // TX Path — zero-copy via attach_extbuf
    // ========================================================================

    int32_t submit_tx_batch() {
        if (!raw_outbox_cons_ || !raw_outbox_cons_->has_data()) {
            return 0;
        }

        uint16_t tx_count = 0;
        struct rte_mbuf* tx_mbufs[kTxBatch];

        raw_outbox_cons_->process_manually([&](auto& desc, [[maybe_unused]] int64_t seq) -> bool {
            if (tx_count >= kTxBatch) return false;

            struct rte_mbuf* m = rte_pktmbuf_alloc(tx_hdr_pool_);
            if (!m) {
                return false;
            }

            // Attach shared UMEM frame as external buffer — zero-copy
            uint8_t* frame_data = umem_area_ + desc.frame_ptr;
            uint32_t frame_idx = static_cast<uint32_t>(desc.frame_ptr / kFrameSize);
            // TX shinfo index: frame_idx is absolute UMEM index (starts at RX_FRAMES),
            // but tx_shinfo_ is sized TX_POOL_SIZE and indexed from 0.
            uint32_t tx_si = frame_idx - static_cast<uint32_t>(RX_FRAMES);

            // Reset refcnt before each attach — after DPDK frees the mbuf,
            // shinfo refcnt is decremented to 0.  attach_extbuf does NOT reset it.
            rte_mbuf_ext_refcnt_set(&tx_shinfo_[tx_si], 1);
            rte_pktmbuf_attach_extbuf(m, frame_data,
                rte_mem_virt2iova(frame_data),
                kFrameSize, &tx_shinfo_[tx_si]);

            m->data_off = 0;
            m->data_len = desc.frame_len;
            m->pkt_len = desc.frame_len;

            tx_mbufs[tx_count++] = m;
            return true;
        });

        if (tx_count > 0) {
            uint16_t sent = rte_eth_tx_burst(port_id_, 0, tx_mbufs, tx_count);

            // Free unsent mbufs (header only — extbuf shinfo.free_cb is noop)
            for (uint16_t i = sent; i < tx_count; i++) {
                rte_pktmbuf_free(tx_mbufs[i]);
            }

            raw_outbox_cons_->commit_manually();
            tx_total_submitted_ += sent;
            return static_cast<int32_t>(sent);
        }

        return 0;
    }

    // ========================================================================
    // RX Path — TRUE ZERO-COPY
    // NIC DMA writes directly into shared UMEM via extbuf pool.
    // mbuf is HELD (not freed) until Transport advances consumer_sequence.
    // No memcpy anywhere in the RX path.
    // ========================================================================

    int32_t process_rx([[maybe_unused]] uint64_t loop_id) {
        struct rte_mbuf* rx_mbufs[kRxBatch];
        uint16_t nb_rx = rte_eth_rx_burst(port_id_, 0, rx_mbufs, kRxBatch);

        if (nb_rx == 0) return 0;

        uint64_t poll_cycle = rdtscp();

        struct timespec ts_mono;
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        uint64_t mono_ns = static_cast<uint64_t>(ts_mono.tv_sec) * 1'000'000'000ULL +
                           static_cast<uint64_t>(ts_mono.tv_nsec);

        uint16_t published = 0;
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf* m = rx_mbufs[i];

            // Handle ARP before filtering — DPDK owns the NIC, kernel can't respond
            if (handle_arp(m)) {
                continue;  // ARP consumed (replied or dropped)
            }

            // Userspace filter (replaces BPF)
            if (!match_exchange_packet(m)) {
                rte_pktmbuf_free(m);
                continue;
            }

            // Compute UMEM offset from mbuf data pointer
            // mbuf->buf_addr points into shared UMEM (extbuf pool)
            uint8_t* pkt_data = rte_pktmbuf_mtod(m, uint8_t*);
            uint64_t umem_offset = static_cast<uint64_t>(pkt_data - umem_area_);
            uint32_t frame_idx = static_cast<uint32_t>(
                (reinterpret_cast<uint8_t*>(m->buf_addr) - umem_area_) / kFrameSize);

            // Claim slot in RAW_INBOX
            int64_t slot = raw_inbox_prod_->try_claim();
            if (slot < 0) {
                rte_pktmbuf_free(m);
                fprintf(stderr, "[DPDK-POLL] FATAL: RAW_INBOX full\n");
                abort();
            }

            auto& desc = (*raw_inbox_prod_)[slot];
            desc.frame_ptr = umem_offset;
            desc.frame_len = m->data_len;
            desc.nic_frame_poll_cycle = poll_cycle;
            desc.frame_type = FRAME_TYPE_RX;
            desc.consumed = 0;
            desc.acked = 0;

            desc.nic_timestamp_ns = 0;
            desc.bpf_entry_ns = mono_ns;

            if (i == 0) {
                first_rx_timestamp_ns_ = desc.nic_timestamp_ns;
                first_rx_poll_cycle_ = poll_cycle;
            }

            if constexpr (Profiling) {
                if (nic_latency_data_) {
                    struct timespec ts_real;
                    clock_gettime(CLOCK_REALTIME, &ts_real);
                    uint64_t poll_realtime_ns = static_cast<uint64_t>(ts_real.tv_sec) * 1'000'000'000ULL +
                                                static_cast<uint64_t>(ts_real.tv_nsec);
                    nic_latency_data_->record(desc.nic_timestamp_ns, desc.bpf_entry_ns,
                                              poll_cycle, mono_ns, poll_realtime_ns);
                }
            }

            raw_inbox_prod_->publish(slot);

            // HOLD mbuf — do NOT free. Transport reads directly from shared UMEM.
            // Released in reclaim_rx_frames() when consumer advances.
            rx_mbuf_ring_[frame_idx] = m;
            published++;
        }

        rx_packets_ += published;
        return static_cast<int32_t>(published);
    }

    // ========================================================================
    // RX Frame Reclaim — free held mbufs when Transport advances consumer_sequence
    // Returns mbufs to DPDK pool, making their UMEM frames available for next rx_burst.
    // ========================================================================

    int32_t reclaim_rx_frames() {
        int64_t consumer_pos = raw_inbox_prod_->consumer_sequence();
        if (consumer_pos <= last_released_seq_) return 0;

        int32_t reclaimed = 0;
        for (int64_t pos = last_released_seq_ + 1; pos <= consumer_pos; pos++) {
            const auto& desc = (*raw_inbox_prod_)[pos];
            uint32_t frame_idx = static_cast<uint32_t>(desc.frame_ptr / kFrameSize);

            if (frame_idx < RX_FRAMES && rx_mbuf_ring_[frame_idx]) {
                rte_pktmbuf_free(rx_mbuf_ring_[frame_idx]);
                rx_mbuf_ring_[frame_idx] = nullptr;
                reclaimed++;
            }
        }
        last_released_seq_ = consumer_pos;
        return reclaimed;
    }

    // ========================================================================
    // Accessors — match XDPPollProcess interface
    // ========================================================================

    // No BPF for DPDK
    void* get_bpf_loader() { return nullptr; }
    const void* get_bpf_loader() const { return nullptr; }

    // Stats
    uint64_t rx_packets() const { return rx_packets_; }
    uint64_t tx_completions() const { return tx_total_submitted_; }

    int64_t last_released_seq() const { return last_released_seq_; }
    uint64_t last_rx_timestamp() const { return last_rx_timestamp_ns_; }

    // Profiling
    void set_profiling_data(CycleSampleBuffer* data) { profiling_data_ = data; }
    void set_nic_latency_data(NicLatencyBuffer* data) { nic_latency_data_ = data; }

    // ========================================================================
    // Cleanup
    // ========================================================================

    void cleanup() {
        if (port_started_) {
            struct rte_eth_stats stats;
            if (rte_eth_stats_get(port_id_, &stats) == 0) {
                fprintf(stderr, "[DPDK-POLL] Port stats: RX=%lu TX=%lu RX_err=%lu TX_err=%lu RX_nombuf=%lu ARP_replied=%lu\n",
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
    }

private:
    // ========================================================================
    // Initialization Helpers
    // ========================================================================

    static size_t detect_page_size(const void* addr) {
        // Read /proc/self/smaps to detect hugepage backing
        FILE* f = fopen("/proc/self/smaps", "r");
        if (!f) return sysconf(_SC_PAGESIZE);

        uintptr_t target = reinterpret_cast<uintptr_t>(addr);
        char line[256];
        bool in_region = false;
        size_t result = sysconf(_SC_PAGESIZE);

        while (fgets(line, sizeof(line), f)) {
            // Match region header: "7f1234000000-7f1234800000 rw-p ..."
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                in_region = (target >= start && target < end);
            }
            if (in_region && strncmp(line, "KernelPageSize:", 15) == 0) {
                unsigned long kps = 0;
                if (sscanf(line + 15, "%lu", &kps) == 1 && kps > 0) {
                    result = kps * 1024;  // smaps reports in kB
                }
                break;
            }
        }
        fclose(f);
        fprintf(stderr, "[DPDK-POLL] UMEM page size: %zu bytes\n", result);
        return result;
    }

    static bool resolve_pci_addr(const char* interface, char* buf, size_t buf_size) {
        // Case 1: Already a PCI address (e.g., "0000:6c:00.0")
        //         Pattern: DDDD:DD:DD.D where D is hex digit
        if (strlen(interface) >= 10 && interface[4] == ':' && interface[7] == ':' && interface[10] == '.') {
            snprintf(buf, buf_size, "%s", interface);
            return true;
        }

        // Case 2: Interface name — resolve via sysfs (only works before vfio-pci bind)
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/net/%s/device", interface);

        char link_target[256];
        ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
        if (len >= 0) {
            link_target[len] = '\0';
            const char* pci = strrchr(link_target, '/');
            if (pci) {
                pci++;  // Skip '/'
                snprintf(buf, buf_size, "%s", pci);
                return true;
            }
        }

        // Case 3: Interface name but NIC already bound to DPDK —
        //         try cached PCI address from bind script
        char cache_path[256];
        snprintf(cache_path, sizeof(cache_path), "/tmp/dpdk_pci_%s", interface);
        FILE* f = fopen(cache_path, "r");
        if (f) {
            if (fgets(buf, buf_size, f)) {
                // Strip trailing newline
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
        // Build EAL arguments
        // VA mode: IOVA == VA. With UMEM at low VA (< 512 GB) and --base-virtaddr
        // keeping DPDK internals low, all DMA addresses fit within the 39-bit IOMMU SAGAW.
        char core_arg[16];
        snprintf(core_arg, sizeof(core_arg), "%d", sched_getcpu());

        char allow_arg[64];
        snprintf(allow_arg, sizeof(allow_arg), "%s", pci_addr_str_);

        char base_va_arg[32];
        snprintf(base_va_arg, sizeof(base_va_arg), "0x%lx", DPDK_BASE_VIRTADDR);

        const char* argv[] = {
            "dpdk-poll",
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
            fprintf(stderr, "[DPDK-POLL] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
            return false;
        }

        eal_initialized_ = true;
        fprintf(stderr, "[DPDK-POLL] EAL: iova-mode=va, base-virtaddr=%s, UMEM VA=%p\n",
                base_va_arg, (void*)umem_area_);
        return true;
    }

    bool init_port() {
        uint16_t nb_ports = rte_eth_dev_count_avail();
        if (nb_ports == 0) {
            fprintf(stderr, "[DPDK-POLL] No DPDK ports available. Is NIC bound to vfio-pci?\n");
            return false;
        }

        // EAL -a flag already restricts to our PCI device, so use first available port
        port_id_ = rte_eth_find_next(0);
        if (port_id_ >= RTE_MAX_ETHPORTS) {
            fprintf(stderr, "[DPDK-POLL] No ports found (EAL allowed: %s)\n", pci_addr_str_);
            return false;
        }

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);
        fprintf(stderr, "[DPDK-POLL] Port %u: %s (driver: %s)\n",
                port_id_, rte_dev_name(dev_info.device), dev_info.driver_name);

        return true;
    }

    bool register_external_memory() {
        // In VA mode (IOVA == VA), register shared UMEM with DPDK and set up
        // VFIO IOMMU DMA mapping. The kernel VFIO driver walks the user page table
        // to map each page's VA→PA in the IOMMU, so non-contiguous hugepages work
        // transparently with a single contiguous VA range.
        //
        // The UMEM is at a low VA (< 512 GB) so all IOVAs fit within the 39-bit SAGAW.

        size_t page_size = detect_page_size(umem_area_);
        size_t reg_size = (umem_size_ + page_size - 1) & ~(page_size - 1);

        // Fault in all pages (hugepages may be lazily allocated)
        unsigned int n_pages = reg_size / page_size;
        for (unsigned int i = 0; i < n_pages; i++) {
            *reinterpret_cast<volatile uint8_t*>(umem_area_ + i * page_size) = 0;
        }

        // Register with DPDK — nullptr IOVA table means DPDK uses rte_mem_virt2iova()
        // which in VA mode returns the VA itself as the IOVA
        int ret = rte_extmem_register(umem_area_, reg_size, nullptr, 0, page_size);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] rte_extmem_register failed: %s\n",
                    rte_strerror(rte_errno));
            return false;
        }

        // DMA map the entire region — VFIO kernel driver handles per-page PA translation
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);

        rte_iova_t iova = reinterpret_cast<rte_iova_t>(umem_area_);  // VA == IOVA in VA mode
        ret = rte_dev_dma_map(dev_info.device, umem_area_, iova, reg_size);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] rte_dev_dma_map failed (va=%p, size=%zu): %s\n",
                    (void*)umem_area_, reg_size, rte_strerror(rte_errno));
            return false;
        }

        fprintf(stderr, "[DPDK-POLL] Registered+DMA mapped %zu bytes (%u pages) at VA %p (IOVA=VA)\n",
                reg_size, n_pages, (void*)umem_area_);
        extmem_registered_ = true;
        return true;
    }

    // Callback to redirect each RX mbuf's buf_addr/buf_iova to a UMEM frame.
    // Called via rte_mempool_obj_iter after pool creation.
    struct RxPoolInitCtx {
        uint8_t* umem_area;
        uint32_t frame_size;
    };

    static void rx_mbuf_umem_init(struct rte_mempool* /*mp*/, void* opaque,
                                   void* obj, unsigned obj_idx) {
        auto* ctx = static_cast<RxPoolInitCtx*>(opaque);
        auto* m = static_cast<struct rte_mbuf*>(obj);

        // Redirect data area to shared UMEM frame
        m->buf_addr = ctx->umem_area + obj_idx * ctx->frame_size;
        m->buf_iova = reinterpret_cast<rte_iova_t>(m->buf_addr);  // VA == IOVA
        m->buf_len = ctx->frame_size;
        m->data_off = RTE_PKTMBUF_HEADROOM;
    }

    bool create_mempools() {
        int socket_id = rte_eth_dev_socket_id(port_id_);
        if (socket_id < 0) socket_id = 0;

        // RX pool: standard pool (headers + unused data in DPDK hugepages).
        // After creation, we override each mbuf's buf_addr/buf_iova to point
        // into shared UMEM frames. The NIC DMA writes directly into UMEM.
        //
        // Why not rte_pktmbuf_pool_create_extbuf? That function packs mbuf headers
        // INTO the external memory alongside data areas, corrupting the UMEM layout.
        // Our approach: mbuf headers in DPDK hugepages, data pointers into UMEM.
        // buf_addr/buf_iova persist across alloc/free (rte_pktmbuf_reset doesn't touch them).
        rx_pool_ = rte_pktmbuf_pool_create("RX_POOL",
            static_cast<uint32_t>(RX_FRAMES),
            0,              // cache_size (0 = no per-core cache, all mbufs in ring)
            0,              // priv_size
            kFrameSize,     // data_room_size (PMD checks this, actual data goes to UMEM)
            socket_id);

        if (!rx_pool_) {
            fprintf(stderr, "[DPDK-POLL] RX pool creation failed: %s\n",
                    rte_strerror(rte_errno));
            return false;
        }

        // Override buf_addr/buf_iova to point into shared UMEM RX region
        RxPoolInitCtx ctx{umem_area_, kFrameSize};
        rte_mempool_obj_iter(rx_pool_, rx_mbuf_umem_init, &ctx);

        fprintf(stderr, "[DPDK-POLL] RX pool: %u mbufs, frame_size=%u, buf_addr → UMEM VA %p\n",
                static_cast<uint32_t>(RX_FRAMES), kFrameSize, (void*)umem_area_);

        // TX header-only pool (no data buffer — data lives in shared UMEM TX region)
        tx_hdr_pool_ = rte_pktmbuf_pool_create("TX_HDR_POOL",
            static_cast<uint32_t>(TX_POOL_SIZE),
            0,      // cache size
            0,      // priv size
            0,      // data_room_size = 0 (header-only)
            socket_id);

        if (!tx_hdr_pool_) {
            fprintf(stderr, "[DPDK-POLL] TX header pool creation failed: %s\n",
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

        // NOTE: Do NOT enable RTE_ETH_RX_OFFLOAD_TIMESTAMP on igc.
        // When enabled, the I225 NIC prepends a 16-byte timestamp header to each
        // packet, but the igc PMD (DPDK 23.11) doesn't adjust data_off to skip it,
        // causing mtod to point at the TS header instead of the Ethernet frame.
        // We use clock_gettime(MONOTONIC) instead for software timestamps.
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id_, &dev_info);

        int ret = rte_eth_dev_configure(port_id_, 1, 1, &port_conf);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] rte_eth_dev_configure failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        // RX queue
        struct rte_eth_rxconf rx_conf = dev_info.default_rxconf;
        ret = rte_eth_rx_queue_setup(port_id_, 0,
            1024,  // descriptor ring size (pool has RX_FRAMES=2048 mbufs)
            socket_id, &rx_conf, rx_pool_);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] RX queue setup failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        // TX queue — ring must be smaller than pool to avoid pool exhaustion.
        // igc driver only scans for TX completions when used > (ring_size - tx_free_thresh).
        // With ring=pool, ALL mbufs can sit in the ring with none available for alloc.
        struct rte_eth_txconf tx_conf = dev_info.default_txconf;
        static constexpr uint16_t kTxRingSize = 256;  // 4x kTxBatch, << TX_POOL_SIZE
        ret = rte_eth_tx_queue_setup(port_id_, 0,
            kTxRingSize,
            socket_id, &tx_conf);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] TX queue setup failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }

        // Start port
        ret = rte_eth_dev_start(port_id_);
        if (ret < 0) {
            fprintf(stderr, "[DPDK-POLL] rte_eth_dev_start failed: %s\n",
                    rte_strerror(-ret));
            return false;
        }
        port_started_ = true;

        // Enable promiscuous mode (filter in userspace)
        rte_eth_promiscuous_enable(port_id_);

        // Wait for link up (I225 takes ~2-8s for auto-negotiation after port reconfig)
        struct rte_eth_link link;
        for (int i = 0; i < 100; i++) {  // 10s max
            rte_eth_link_get_nowait(port_id_, &link);
            if (link.link_status) break;
            usleep(100'000);
        }
        fprintf(stderr, "[DPDK-POLL] Link: %s, speed %u Mbps, %s\n",
                link.link_status ? "UP" : "DOWN",
                link.link_speed,
                link.link_duplex ? "full-duplex" : "half-duplex");
        if (!link.link_status) {
            fprintf(stderr, "[DPDK-POLL] WARNING: Link is still down after 5s\n");
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

    static void noop_free_cb(void* /*addr*/, void* /*opaque*/) {
        // No-op: UMEM TX frame lifetime managed by Transport's mark_frame_acked()
    }

    // ========================================================================
    // ARP Responder — required because DPDK takes the NIC from the kernel
    //
    // In XDP mode, the kernel handles ARP. In DPDK mode, we must respond
    // to ARP requests for our IP so the gateway can forward packets to us.
    // Modifies the RX mbuf in place and sends it directly via tx_burst.
    // ========================================================================

    bool handle_arp(struct rte_mbuf* m) {
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))
            return false;

        auto* eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
        if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
            return false;

        auto* arp = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr*,
                                              sizeof(struct rte_ether_hdr));

        // Only handle ARP requests
        if (arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))
            return true;  // ARP but not a request — consume silently

        // Only reply if it's for our IP
        if (arp->arp_data.arp_tip != local_ip_)
            return true;  // Not for us — consume

        // Build ARP reply in place
        // Ethernet: swap dst/src, set our MAC as source
        rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
        rte_ether_addr_copy(&local_mac_, &eth->src_addr);

        // ARP: set reply opcode, swap sender/target
        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        // Target = original sender
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
        uint32_t sender_ip = arp->arp_data.arp_sip;
        arp->arp_data.arp_tip = sender_ip;

        // Sender = us
        rte_ether_addr_copy(&local_mac_, &arp->arp_data.arp_sha);
        arp->arp_data.arp_sip = local_ip_;

        // Send reply directly using the modified RX mbuf
        uint16_t sent = rte_eth_tx_burst(port_id_, 0, &m, 1);
        if (sent == 0) {
            rte_pktmbuf_free(m);
        } else {
            arp_replies_sent_++;
        }

        return true;  // ARP handled, don't process further
    }

    // ========================================================================
    // Userspace Packet Filter (replaces BPF)
    // ========================================================================

    bool match_exchange_packet(struct rte_mbuf* m) const {
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
            return false;
        }

        const auto* eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr*);
        if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
            return false;
        }

        const auto* ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr*,
                                                   sizeof(struct rte_ether_hdr));
        if (ip->next_proto_id != IPPROTO_TCP) {
            return false;
        }

        // Check if source or destination IP matches any exchange IP
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

    // DPDK state
    uint16_t port_id_ = 0;
    struct rte_mempool* rx_pool_ = nullptr;
    struct rte_mempool* tx_hdr_pool_ = nullptr;
    bool port_started_ = false;
    bool eal_initialized_ = false;
    bool extmem_registered_ = false;

    // Shared UMEM (inherited from parent via fork, registered with DPDK)
    uint8_t* umem_area_ = nullptr;
    size_t umem_size_ = 0;

    // Configuration
    const char* interface_ = nullptr;
    char pci_addr_str_[32] = {};

    // Ring pointers
    RingProducer* raw_inbox_prod_ = nullptr;
    OutboxConsumer* raw_outbox_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // Held RX mbufs — freed when Transport advances consumer_sequence
    struct rte_mbuf* rx_mbuf_ring_[RX_FRAMES] = {};

    // TX external buffer shared info (one per TX frame, free_cb = noop)
    struct rte_mbuf_ext_shared_info tx_shinfo_[TX_POOL_SIZE] = {};

    // Exchange IP filter table
    uint32_t exchange_ips_[ConnStateShm::MAX_EXCHANGE_IPS] = {};
    uint8_t exchange_ip_count_ = 0;
    uint16_t exchange_port_ = 0;

    // Local identity (for ARP replies)
    struct rte_ether_addr local_mac_ = {};
    uint32_t local_ip_ = 0;  // Network byte order

    // Stats
    uint64_t rx_packets_ = 0;
    uint64_t tx_total_submitted_ = 0;
    uint64_t arp_replies_sent_ = 0;
    // Frame reclaim tracking
    int64_t last_released_seq_ = -1;
    uint64_t last_rx_timestamp_ns_ = 0;
    uint64_t first_rx_timestamp_ns_ = 0;
    uint64_t first_rx_poll_cycle_ = 0;

    // Profiling data (optional)
    CycleSampleBuffer* profiling_data_ = nullptr;
    NicLatencyBuffer* nic_latency_data_ = nullptr;
};

}  // namespace websocket::pipeline

#endif  // USE_DPDK
