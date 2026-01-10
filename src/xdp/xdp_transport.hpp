// xdp/xdp_transport.hpp
// AF_XDP (eXpress Data Path) Transport Layer
//
// This provides zero-copy packet I/O using AF_XDP sockets for HFT use cases:
//   - Zero-copy packet I/O via UMEM (User Memory) with XDP_ZEROCOPY flag
//   - Complete kernel bypass with userspace TCP/IP stack
//   - Sub-microsecond latency (~1-2 μs NIC to app)
//   - Native driver mode (XDP_FLAGS_DRV_MODE) for maximum performance
//   - NIC hardware timestamp support via bpf_xdp_metadata_rx_timestamp()
//
// Architecture:
//   Application → Userspace TCP/IP Stack → XDP Transport → AF_XDP Socket → NIC
//
// Primary API (Zero-Copy):
//   - peek_rx_frame() / release_rx_frame() - Zero-copy RX
//   - get_tx_frame() / send_frame() - Zero-copy TX
//   - poll_wait() - Userspace busy-polling with SO_BUSY_POLL
//
// igc Driver TX Completion Workaround:
//   The igc driver (Intel I225/I226 NICs) has a TX completion stall bug in
//   XDP zero-copy mode. TX completions only happen during NAPI poll which
//   requires RX traffic. This is worked around by an RX trickle thread that
//   sends self-addressed UDP packets at 500 Hz to keep NAPI polling active.
//   See start_rx_trickle() for implementation details.
//
// Requirements:
//   - Linux kernel 5.4+ (AF_XDP zero-copy support)
//   - libbpf, libxdp
//   - XDP-capable NIC with zero-copy support (e.g., Intel igc/i40e/ixgbe)
//   - CAP_NET_RAW + CAP_BPF or root privileges

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

// Forward declarations to avoid hard dependency on XDP headers
// (allows compilation without libbpf/libxdp installed)
#ifdef USE_XDP
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include <atomic>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include "xdp_frame.hpp"
#include "bpf_loader.hpp"
#endif

namespace websocket {
namespace xdp {

#ifdef USE_XDP

// ============================================================================
// Compile-time XDP Configuration
// ============================================================================
// Override these via Makefile: -DXDP_INTERFACE='"enp40s0"'
// MTU and HEADROOM are auto-detected from interface if not specified.
//
// XDP_INTERFACE: Network interface for XDP (REQUIRED)
// XDP_HEADROOM:  Bytes reserved before packet data in UMEM frame (auto: 0 for most drivers, 256 for mlx5)
// XDP_MTU:       Maximum transmission unit (auto-detected from interface)
// ============================================================================

#ifndef XDP_INTERFACE
#error "XDP_INTERFACE must be defined. Use: make USE_XDP=1 XDP_INTERFACE=<interface>"
#endif

#ifndef XDP_HEADROOM
#define XDP_HEADROOM 0
#endif

#ifndef XDP_MTU
#define XDP_MTU 3502
#endif

// Calculate frame size: MTU + Ethernet(14) + IP(20) + TCP(60 max) + margin, round up to power of 2
// For MTU=3502: 3502 + 14 + 20 + 60 + 500 = 4096
constexpr uint32_t xdp_calculate_frame_size(uint32_t mtu) {
    uint32_t min_size = mtu + 14 + 20 + 60 + 500;  // Headers + margin
    // Round up to next power of 2
    uint32_t v = min_size - 1;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    return v + 1;
}

constexpr uint32_t XDP_FRAME_SIZE = xdp_calculate_frame_size(XDP_MTU);

/**
 * XDP Transport Configuration
 */
struct XDPConfig {
    const char* interface;      // Network interface (e.g., "eth0")
    uint32_t queue_id;          // RX/TX queue ID (usually 0)
    uint32_t frame_size;        // UMEM frame size (default: calculated from XDP_MTU)
    uint32_t num_frames;        // Number of UMEM frames (default: 65536)
    bool zero_copy;             // Enable zero-copy mode (requires driver support)
    uint32_t batch_size;        // Batch size for TX/RX (default: 64)

    // SO_BUSY_POLL settings for userspace busy-polling
    uint32_t busy_poll_usec;          // SO_BUSY_POLL timeout in microseconds (default: 50)
    uint32_t busy_poll_budget;        // SO_BUSY_POLL_BUDGET packets per poll (default: 64)

    // RX Trickle settings for zero-copy mode TX completion workaround
    // See detailed comment in start_rx_trickle() for rationale
    bool rx_trickle_enabled;          // Enable RX trickle for zero-copy TX workaround (default: true when zero_copy)
    uint32_t rx_trickle_interval_us;  // Interval between trickle packets in microseconds (default: 2000 = 500 Hz)

    XDPConfig()
        : interface(XDP_INTERFACE)
        , queue_id(0)
        , frame_size(XDP_FRAME_SIZE)  // Calculated from XDP_MTU (4096 for MTU=3502)
        , num_frames(65536)           // 16x larger for high throughput
        , zero_copy(true)   // Enable zero-copy by default for HFT (igc driver supports it)
        , batch_size(64)
        , busy_poll_usec(1000)           // 1000us busy-poll duration (testing)
        , busy_poll_budget(64)           // 64 packets per poll
        , rx_trickle_enabled(true)       // Enable RX trickle by default for zero-copy mode
        , rx_trickle_interval_us(2000)   // 500 Hz (2ms interval) - optimal for igc driver
    {}
};

/**
 * XDP Transport - AF_XDP socket-based transport for zero-copy packet I/O
 *
 * Provides zero-copy frame access for HFT applications using userspace
 * TCP/IP stack. All packet processing bypasses the kernel completely.
 *
 * Usage with userspace stack:
 *   XDPTransport xdp;
 *   xdp.init(config, "path/to/bpf.o");  // With BPF filtering
 *   xdp.init(config);                    // Without BPF filtering
 *
 *   // TX (zero-copy):
 *   XDPFrame* tx = xdp.get_tx_frame();
 *   memcpy(tx->data, packet, len);
 *   xdp.send_frame(tx, len);
 *
 *   // RX (zero-copy):
 *   XDPFrame* rx = xdp.peek_rx_frame();
 *   process(rx->data, rx->len);
 *   xdp.release_rx_frame(rx);
 *
 * Frame Pool Architecture (Zero-Copy Retransmit):
 *   UMEM is split into dedicated RX and TX pools:
 *   - RX Pool (frames 0 - RX_POOL_SIZE-1): Used for FILL/RX rings
 *   - TX Pool (frames RX_POOL_SIZE - num_frames-1): Sequential allocation for TX
 *
 *   TX frames use sequential allocation with ACK-based release:
 *   - alloc_tx_frame_idx() allocates next TX frame
 *   - mark_frame_acked() flags frame as ACKed
 *   - try_release_tx_frames() releases contiguous ACKed frames
 *   - retransmit_frame() re-submits existing frame (no rebuild)
 */
struct XDPTransport {
    // Headroom: configurable via -DXDP_HEADROOM=N (0 for ENA driver)
    static constexpr uint32_t HEADROOM = XDP_HEADROOM;

    // Frame pool configuration (separate RX and TX pools)
    // Total frames split 50/50 between RX and TX (16x larger: 65536 total)
    static constexpr uint32_t RX_POOL_START = 0;
    static constexpr uint32_t DEFAULT_RX_POOL_SIZE = 32768;  // Frames 0-32767 for RX
    static constexpr uint32_t DEFAULT_TX_POOL_SIZE = 32768;  // Frames 32768-65535 for TX

    XDPTransport()
        : xsk_(nullptr)
        , umem_(nullptr)
        , umem_area_(nullptr)
        , umem_size_(0)
        , umem_fd_(-1)
        , connected_(false)
        , ifindex_(0)
        , next_free_frame_(0)
        , current_rx_frame_(nullptr)
        , current_rx_addr_(0)
        , bpf_loader_(nullptr)
        , bpf_enabled_(false)
        , rx_trickle_running_(false)
        , rx_trickle_fd_(-1)
        , poll_fd_{}
        , poll_wait_count_(0)
        , rx_pool_size_(DEFAULT_RX_POOL_SIZE)
        , tx_pool_start_(DEFAULT_RX_POOL_SIZE)
        , tx_pool_size_(DEFAULT_TX_POOL_SIZE)
        , tx_alloc_pos_(0)
        , tx_free_pos_(0)
    {
        free_frames_.reserve(4096);  // Pre-allocate for performance
        frame_acked_.fill(false);    // Initialize ACK bitmap
    }

    ~XDPTransport() {
        close();
    }

    // Prevent copying
    XDPTransport(const XDPTransport&) = delete;
    XDPTransport& operator=(const XDPTransport&) = delete;

    /**
     * Initialize XDP transport
     *
     * @param config XDP configuration
     * @param bpf_obj_path Path to BPF object file, or nullptr to disable BPF filtering
     * @throws std::runtime_error on failure
     */
    void init(const XDPConfig& config,
              const char* bpf_obj_path = nullptr) {
        config_ = config;

        // If BPF path provided, load AND ATTACH BPF program FIRST (before creating socket)
        // This is critical: the XDP program must be attached BEFORE creating the XSK socket
        // so the socket properly binds to receive redirects
        if (bpf_obj_path != nullptr) {
            printf("[XDP] Loading and attaching BPF program before socket creation...\n");
            bpf_loader_ = new BPFLoader();
            bpf_loader_->load(config_.interface, bpf_obj_path);

            // CRITICAL: Attach BPF program NOW, before creating socket
            // MUST use driver mode for AF_XDP redirect to work!
            // SKB/generic mode can execute BPF but cannot redirect to XSK sockets
            printf("[XDP] Attaching BPF in native driver mode (required for AF_XDP redirect)...\n");
            bpf_loader_->attach(XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
            printf("[XDP] ✅ Native driver mode attached\n");

            bpf_enabled_ = true;
        }

        // Get interface index
        ifindex_ = if_nametoindex(config_.interface);
        if (ifindex_ == 0) {
            throw std::runtime_error(std::string("Interface not found: ") + config_.interface);
        }

        // Allocate UMEM (User Memory for packet buffers)
        // CRITICAL: Use MAP_SHARED so child processes can see kernel writes after fork()
        // With MAP_PRIVATE, copy-on-write semantics prevent children from seeing XDP RX data
        umem_size_ = config_.num_frames * config_.frame_size;

        // Create shared memory file for UMEM
        char umem_path[256];
        snprintf(umem_path, sizeof(umem_path), "/dev/shm/xdp_umem_%d_%s",
                 getpid(), config_.interface);
        umem_fd_ = open(umem_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (umem_fd_ < 0) {
            throw std::runtime_error(std::string("Failed to create UMEM file: ") + strerror(errno));
        }
        // Mark for deletion on close (will be cleaned up when all processes exit)
        unlink(umem_path);

        // Resize the file
        if (ftruncate(umem_fd_, umem_size_) < 0) {
            ::close(umem_fd_);
            throw std::runtime_error(std::string("Failed to resize UMEM file: ") + strerror(errno));
        }

        // Try with huge pages first (MAP_SHARED + MAP_HUGETLB)
        umem_area_ = mmap(nullptr, umem_size_,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_HUGETLB,
                          umem_fd_, 0);

        if (umem_area_ == MAP_FAILED) {
            // Fallback to regular pages if huge pages fail
            umem_area_ = mmap(nullptr, umem_size_,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED,
                              umem_fd_, 0);
        }

        if (umem_area_ == MAP_FAILED) {
            ::close(umem_fd_);
            throw std::runtime_error(std::string("Failed to mmap UMEM: ") + strerror(errno));
        }

        printf("[XDP] UMEM allocated: %zu bytes (MAP_SHARED) at %p\n", umem_size_, umem_area_);

        // Configure UMEM
        struct xsk_umem_config umem_cfg;
        memset(&umem_cfg, 0, sizeof(umem_cfg));
        // Use larger ring sizes to match increased UMEM (32768 RX frames)
        umem_cfg.fill_size = rx_pool_size_;  // FILL ring holds all RX frames
        umem_cfg.comp_size = tx_pool_size_;  // COMP ring holds all TX frames
        umem_cfg.frame_size = config_.frame_size;
        umem_cfg.frame_headroom = HEADROOM;  // Configurable via -DXDP_HEADROOM=N
        umem_cfg.flags = 0;

        // Create UMEM
        int ret = xsk_umem__create(&umem_, umem_area_, umem_size_,
                                    &fill_ring_, &comp_ring_, &umem_cfg);
        if (ret) {
            munmap(umem_area_, umem_size_);
            throw std::runtime_error("Failed to create UMEM");
        }

        // Configure XDP socket
        struct xsk_socket_config xsk_cfg;
        memset(&xsk_cfg, 0, sizeof(xsk_cfg));
        // Use larger ring sizes to match increased UMEM
        xsk_cfg.rx_size = rx_pool_size_;  // RX ring size matches RX pool
        xsk_cfg.tx_size = tx_pool_size_;  // TX ring size matches TX pool

        // If BPF filtering enabled, bind to the existing XDP program
        // Otherwise, let libxsk attach its default XDP program
        if (bpf_enabled_) {
            // IMPORTANT: Use XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD to prevent libxsk from loading its own program
            // When INHIBIT_PROG_LOAD is set, xdp_flags should be 0 (we've already attached our program)
            xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
            xsk_cfg.xdp_flags = 0;  // Don't touch XDP program - we've already attached it
            // Use XDP_ZEROCOPY with XDP_USE_NEED_WAKEUP for zero-copy mode
            // NOTE: igc driver has a TX completion stall bug in zero-copy mode - TX completions
            // only happen during NAPI poll which requires RX traffic. We use an RX trickle
            // thread (see start_rx_trickle()) to work around this.
            xsk_cfg.bind_flags = config_.zero_copy
                ? (XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)
                : XDP_COPY;
        } else {
            xsk_cfg.libbpf_flags = 0;
            xsk_cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
            xsk_cfg.bind_flags = config_.zero_copy
                ? (XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)
                : XDP_COPY;
        }

        // Create AF_XDP socket
        ret = xsk_socket__create(&xsk_, config_.interface, config_.queue_id,
                                  umem_, &rx_ring_, &tx_ring_, &xsk_cfg);
        if (ret) {
            xsk_umem__delete(umem_);
            umem_ = nullptr;  // Prevent double-free in destructor
            munmap(umem_area_, umem_size_);
            umem_area_ = nullptr;  // Prevent double-free in destructor
            if (bpf_loader_) {
                delete bpf_loader_;
                bpf_loader_ = nullptr;
                bpf_enabled_ = false;
            }
            throw std::runtime_error(std::string("Failed to create XDP socket: ") + strerror(-ret));
        }

        int xdp_fd = xsk_socket__fd(xsk_);

        // Enable SO_BUSY_POLL for userspace busy-polling
        // poll() syscall will busy-poll in kernel for specified duration
        int busy_poll = 1;
        setsockopt(xdp_fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &busy_poll, sizeof(busy_poll));
        int budget = static_cast<int>(config_.busy_poll_budget);
        setsockopt(xdp_fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
        int usec = static_cast<int>(config_.busy_poll_usec);
        setsockopt(xdp_fd, SOL_SOCKET, SO_BUSY_POLL, &usec, sizeof(usec));
        printf("[XDP] SO_BUSY_POLL=%d us, budget=%d\n", usec, budget);

        // Cache pollfd for poll_wait() (avoid recreating on every call)
        poll_fd_.fd = xdp_fd;
        poll_fd_.events = POLLIN | POLLOUT;

        // If BPF enabled, register the socket in the BPF map
        // (BPF program was already attached before socket creation)
        if (bpf_enabled_) {
            // CRITICAL: Must use xsk_socket__update_xskmap() for XSKMAP type!
            // Manual bpf_map_update_elem() does NOT work for AF_XDP socket maps
            bpf_loader_->register_xsk_socket(xsk_);

            printf("[XDP] ✅ BPF filtering enabled\n");
        }

        // Initialize frame pools: split UMEM into RX and TX pools
        // RX pool: frames 0 to rx_pool_size_-1 (for FILL/RX rings)
        // TX pool: frames tx_pool_start_ to num_frames-1 (sequential allocation)
        rx_pool_size_ = config_.num_frames / 2;
        tx_pool_start_ = rx_pool_size_;
        tx_pool_size_ = config_.num_frames - rx_pool_size_;
        tx_alloc_pos_ = 0;
        tx_free_pos_ = 0;
        frame_acked_.fill(false);

        printf("[XDP] Frame pools: RX[0-%u] (%u frames), TX[%u-%u] (%u frames)\n",
               rx_pool_size_ - 1, rx_pool_size_,
               tx_pool_start_, config_.num_frames - 1, tx_pool_size_);

        // Populate fill ring with RX pool frames only
        // Note: Fill ring size might be smaller than RX pool size
        uint32_t idx = 0;
        uint32_t fill_ring_size = umem_cfg.fill_size;
        uint32_t frames_to_populate = (rx_pool_size_ < fill_ring_size) ? rx_pool_size_ : fill_ring_size;

        ret = xsk_ring_prod__reserve(&fill_ring_, frames_to_populate, &idx);
        if (ret != (int)frames_to_populate) {
            cleanup();
            throw std::runtime_error("Failed to populate fill ring");
        }

        for (uint32_t i = 0; i < frames_to_populate; i++) {
            // Use only RX pool frames (0 to rx_pool_size_-1)
            uint64_t addr = i * config_.frame_size;
            *xsk_ring_prod__fill_addr(&fill_ring_, idx++) = addr;
            // Debug: Print first few and last few frame addresses
            if (i < 3 || i >= frames_to_populate - 3) {
                printf("[FILL-INIT] Frame %u: addr=0x%lx\n", i, addr);
            } else if (i == 3) {
                printf("[FILL-INIT] ... (%u frames total) ...\n", frames_to_populate);
            }
        }

        xsk_ring_prod__submit(&fill_ring_, frames_to_populate);
        printf("[XDP] FILL ring populated with %u RX frames\n", frames_to_populate);

        // RX pool uses free_frames_ for recycling (populated as frames are released)
        // TX pool uses sequential allocation (tx_alloc_pos_/tx_free_pos_)
        next_free_frame_ = frames_to_populate;  // Legacy: not used for TX anymore

        // Initialize reusable frame structs (no FramePool needed)
        rx_frame_.clear();
        rx_frame_.capacity = config_.frame_size - HEADROOM;
        tx_frame_.clear();
        tx_frame_.capacity = config_.frame_size - HEADROOM;

        // Mark as "connected" for userspace stack usage (no TCP socket needed)
        connected_ = true;

        printf("[XDP] Initialized on %s (queue %u, %u frames)\n",
               config_.interface, config_.queue_id, config_.num_frames);

        // Start RX trickle for igc driver TX completion workaround
        if (config_.zero_copy && config_.rx_trickle_enabled) {
            start_rx_trickle();
        }
    }

    /**
     * Poll for RX/TX events with userspace busy-polling
     *
     * Uses poll() on the AF_XDP socket to trigger SO_BUSY_POLL behavior.
     * SO_BUSY_POLL causes the kernel to busy-poll during the poll() syscall,
     * which processes both RX and TX completions.
     *
     * Always uses timeout=0 (non-blocking) to avoid timer setup overhead.
     * SO_BUSY_POLL duration (set via setsockopt) controls the polling time.
     *
     * @return 1 if events ready, 0 on timeout, -1 on error
     */
    int poll_wait() {
        if (!xsk_) return -1;

        int ret = poll(&poll_fd_, 1, 0);  // Always non-blocking, SO_BUSY_POLL controls duration

        // Inline trickle every 8 poll_wait() calls (~400us at 50us/poll)
        // Triggers NAPI poll for TX completions (igc driver workaround)
        if (rx_trickle_fd_ >= 0 && (++poll_wait_count_ & 0x07) == 0) {
            ::send(rx_trickle_fd_, trickle_packet_, trickle_packet_len_, MSG_DONTWAIT);
        }

        // After poll(), reclaim any TX completions
        reclaim_completed_frames();

        return ret;
    }

    // ========================================================================
    // Zero-Copy API (Primary interface for HFT use case)
    // ========================================================================

    /**
     * Peek at received frame without copying data
     *
     * Returns a reference to the next RX frame in UMEM. The frame data
     * remains in UMEM (no memcpy). The caller can read directly from
     * frame->data pointer.
     *
     * IMPORTANT: Must call release_rx_frame() when done with the frame
     * to return it to the fill ring.
     *
     * @return Pointer to XDPFrame, or nullptr if no data available
     */
    XDPFrame* peek_rx_frame() {
        if (!connected_ || !xsk_) {
            errno = ENOTCONN;
            return nullptr;
        }

        // If we already have a frame held, return it
        if (current_rx_frame_ != nullptr) {
            return current_rx_frame_;
        }

        // Check RX ring for received packets
        uint32_t idx_rx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, 1, &idx_rx);

        if (nb_pkts == 0) {
            // No packets available
            errno = EAGAIN;
            return nullptr;
        }

        // Get first packet descriptor
        const struct xdp_desc* rx_desc = xsk_ring_cons__rx_desc(&rx_ring_, idx_rx);

        // Store RX descriptor address (includes headroom) for refill
        current_rx_addr_ = rx_desc->addr;

        // Setup rx_frame_ directly from descriptor (no FramePool lookup needed)
        uint64_t base_addr = rx_desc->addr & ~(config_.frame_size - 1);
        rx_frame_.addr = base_addr;

        // BPF program uses bpf_xdp_adjust_meta() to store timestamp before packet data
        // Layout: [xdp_user_metadata (8 bytes)][packet data]
        //         ^                            ^
        //         data_meta                    data (rx_desc->addr)
        // The timestamp is stored at rx_desc->addr - 8 (sizeof(__u64))
        rx_frame_.data = (uint8_t*)umem_area_ + rx_desc->addr;
        rx_frame_.len = rx_desc->len;

        // Read hardware timestamp from metadata area (8 bytes before packet data)
        // Only valid when HEADROOM >= 8 (space for bpf_xdp_adjust_meta to store timestamp)
        if constexpr (HEADROOM >= 8) {
            uint64_t* ts_ptr = (uint64_t*)((uint8_t*)umem_area_ + rx_desc->addr - 8);
            rx_frame_.hw_timestamp_ns = *ts_ptr;
        } else {
            rx_frame_.hw_timestamp_ns = 0;  // No metadata space available
        }
        rx_frame_.capacity = config_.frame_size - HEADROOM;
        rx_frame_.offset = 0;
        rx_frame_.owned = true;

        // Hold this frame until release_rx_frame() is called
        current_rx_frame_ = &rx_frame_;

        return &rx_frame_;
    }

    /**
     * Release RX frame back to fill ring
     *
     * Returns the frame to the kernel for reuse. Must be called after
     * peek_rx_frame() when done reading frame data.
     *
     * @param frame Frame to release (must be from peek_rx_frame())
     * @param deferred If true, defer FILL ring refill - returns UMEM address for later refill_frame() call.
     *                 If false (default), immediately refill FILL ring.
     * @return When deferred=true: UMEM address to pass to refill_frame() later, or 0 on error.
     *         When deferred=false: always returns 0.
     */
    uint64_t release_rx_frame(XDPFrame* frame, bool deferred = false) {
        if (frame == nullptr || frame != current_rx_frame_) {
            return 0;
        }

        // Save address before clearing (needed for both paths)
        uint64_t saved_addr = current_rx_addr_;

        // Release RX descriptor (this was peeked in peek_rx_frame)
        xsk_ring_cons__release(&rx_ring_, 1);

        if (!deferred) {
            // Immediate refill: return buffer to FILL ring now
            uint32_t idx_fq;
            if (xsk_ring_prod__reserve(&fill_ring_, 1, &idx_fq) == 1) {
                uint64_t base_addr = saved_addr & ~(config_.frame_size - 1);
                *xsk_ring_prod__fill_addr(&fill_ring_, idx_fq) = base_addr;
                xsk_ring_prod__submit(&fill_ring_, 1);
            }
        }

        // Clear frame state
        rx_frame_.clear();
        current_rx_frame_ = nullptr;
        current_rx_addr_ = 0;

        return deferred ? saved_addr : 0;
    }

    /**
     * Refill a frame to FILL ring (deferred zero-copy release)
     *
     * Called when SSL has finished consuming data from a frame that was
     * released with release_rx_frame(frame, true).
     *
     * @param umem_addr UMEM address returned from release_rx_frame(frame, true)
     */
    void refill_frame(uint64_t umem_addr) {
        if (umem_addr == 0) return;

        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&fill_ring_, 1, &idx_fq) == 1) {
            // Get base address by masking off headroom offset
            uint64_t base_addr = umem_addr & ~(config_.frame_size - 1);
            *xsk_ring_prod__fill_addr(&fill_ring_, idx_fq) = base_addr;
            xsk_ring_prod__submit(&fill_ring_, 1);
        }
    }

    /**
     * Get a free TX frame for writing
     *
     * Returns a frame reference that can be written to directly.
     * The caller should write data to frame->data and then call
     * send_frame() to submit for transmission.
     *
     * @return Pointer to XDPFrame, or nullptr if no frames available
     */
    XDPFrame* get_tx_frame() {
        if (!connected_ || !xsk_) {
            errno = ENOTCONN;
            return nullptr;
        }

        // Reclaim completed TX frames first
        reclaim_completed_frames();

        // Get a free UMEM frame address
        uint64_t frame_addr = get_free_frame();
        if (frame_addr == UINT64_MAX) {
            errno = ENOBUFS;
            return nullptr;
        }

        // Setup tx_frame_ directly (no FramePool lookup needed)
        tx_frame_.addr = frame_addr;
        tx_frame_.data = (uint8_t*)umem_area_ + frame_addr + HEADROOM;
        tx_frame_.len = 0;
        tx_frame_.capacity = config_.frame_size - HEADROOM;
        tx_frame_.offset = 0;
        tx_frame_.owned = true;

        return &tx_frame_;
    }

    /**
     * Submit TX frame for transmission
     *
     * Submits the frame to the TX ring for transmission. The frame
     * must have been obtained from get_tx_frame() and data must be
     * written to frame->data with length set via frame->set_length()
     * or frame->append().
     *
     * After this call, the frame is owned by the kernel until it
     * appears in the completion ring.
     *
     * @param frame Frame to send
     * @param len Data length (must be <= frame->capacity)
     * @return Number of bytes queued, or -1 on error
     */
    ssize_t send_frame(XDPFrame* frame, size_t len) {
        if (!connected_ || !xsk_) {
            errno = ENOTCONN;
            return -1;
        }

        if (frame == nullptr || !frame->owned) {
            errno = EINVAL;
            return -1;
        }

        if (len > frame->capacity) {
            errno = EMSGSIZE;
            return -1;
        }

        // Update frame length if not already set
        if (frame->len != len) {
            if (!frame->set_length(len)) {
                errno = EMSGSIZE;
                return -1;
            }
        }

        // Try to reserve a TX descriptor
        uint32_t idx;
        if (xsk_ring_prod__reserve(&tx_ring_, 1, &idx) != 1) {
            // TX ring is full - return frame to free pool
            printf("[TX-ERROR] TX ring FULL! Dropping frame (addr=%lx, len=%zu)\n",
                   (unsigned long)frame->addr, len);
            free_frames_.push_back(frame->addr);
            frame->clear();  // No FramePool, just clear the frame
            errno = EAGAIN;
            return -1;
        }

        // Set TX descriptor - use offset of frame->data from UMEM base (includes headroom)
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, idx);
        tx_desc->addr = frame->data - (uint8_t*)umem_area_;
        tx_desc->len = frame->len;
        tx_desc->options = 0;

        // Submit the TX descriptor
        xsk_ring_prod__submit(&tx_ring_, 1);

        // Kick TX if kernel needs wakeup (required with XDP_USE_NEED_WAKEUP)
        kick_tx();

        // Mark frame as no longer owned by application
        frame->owned = false;

        return len;
    }

    /**
     * Kick TX ring to notify kernel of pending transmissions
     *
     * With XDP_USE_NEED_WAKEUP, the kernel may be sleeping and needs
     * explicit notification via sendto() to process TX ring.
     */
    void kick_tx() {
        if (xsk_ring_prod__needs_wakeup(&tx_ring_)) {
            int xdp_fd = xsk_socket__fd(xsk_);
            ::sendto(xdp_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
    }

    // ========================================================================
    // End Zero-Copy API
    // ========================================================================

    // ========================================================================
    // Zero-Copy Retransmit API (TX frame management for userspace TCP)
    // ========================================================================

    /**
     * Allocate next TX frame index (for zero-copy retransmit)
     *
     * Returns absolute frame index from TX pool (tx_pool_start_ to num_frames-1).
     * Uses sequential allocation - frames are released via ACK, not completion.
     *
     * @return Frame index, or UINT32_MAX if TX pool exhausted
     */
    uint32_t alloc_tx_frame_idx() {
        // Check if TX pool has available frames
        if (tx_alloc_pos_ - tx_free_pos_ >= tx_pool_size_) {
            return UINT32_MAX;  // TX pool exhausted
        }

        uint32_t relative_idx = tx_alloc_pos_++ % tx_pool_size_;
        return tx_pool_start_ + relative_idx;  // Absolute frame index
    }

    /**
     * Convert frame index to UMEM address
     *
     * @param frame_idx Frame index (from alloc_tx_frame_idx())
     * @return UMEM base address for frame
     */
    uint64_t frame_idx_to_addr(uint32_t frame_idx) const {
        return static_cast<uint64_t>(frame_idx) * config_.frame_size;
    }

    /**
     * Get pointer to frame data area (after headroom)
     *
     * @param addr UMEM base address (from frame_idx_to_addr())
     * @return Pointer to frame data area
     */
    uint8_t* get_frame_ptr(uint64_t addr) {
        return static_cast<uint8_t*>(umem_area_) + addr + HEADROOM;
    }

    /**
     * Get frame data capacity (frame_size - headroom)
     */
    uint32_t frame_capacity() const {
        return config_.frame_size - HEADROOM;
    }

    /**
     * Mark TX frame as ACKed (ready for release)
     *
     * Called when TCP ACK is received for a segment. The frame will be
     * released when try_release_tx_frames() is called and all earlier
     * frames are also ACKed (maintains sequential release order).
     *
     * @param frame_idx Frame index (from alloc_tx_frame_idx())
     */
    void mark_frame_acked(uint32_t frame_idx) {
        if (frame_idx < tx_pool_start_ || frame_idx >= config_.num_frames) {
            return;  // Invalid frame index
        }
        uint32_t relative_idx = (frame_idx - tx_pool_start_) % tx_pool_size_;
        frame_acked_[relative_idx] = true;
    }

    /**
     * Release contiguous ACKed TX frames (call in idle loop)
     *
     * Advances tx_free_pos_ while frames are marked as ACKed.
     * This maintains sequential release order - a frame is only
     * released when all frames before it are also ACKed.
     */
    void try_release_tx_frames() {
        while (tx_free_pos_ < tx_alloc_pos_) {
            uint32_t relative_idx = tx_free_pos_ % tx_pool_size_;
            if (!frame_acked_[relative_idx]) {
                break;  // Can't release - earlier frame not yet ACKed
            }
            frame_acked_[relative_idx] = false;
            tx_free_pos_++;
        }
    }

    /**
     * Retransmit existing frame (no rebuild/re-encryption)
     *
     * Re-submits the same UMEM frame to TX ring. The frame data is
     * unchanged from original transmission.
     *
     * @param frame_idx Frame index
     * @param frame_len Total frame length (Ethernet + IP + TCP + payload)
     * @return frame_len on success, -1 on error (TX ring full)
     */
    ssize_t retransmit_frame(uint32_t frame_idx, uint16_t frame_len) {
        uint64_t addr = frame_idx_to_addr(frame_idx);

        uint32_t idx;
        if (xsk_ring_prod__reserve(&tx_ring_, 1, &idx) != 1) {
            return -1;  // TX ring full
        }

        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, idx);
        tx_desc->addr = addr + HEADROOM;
        tx_desc->len = frame_len;
        tx_desc->options = 0;

        xsk_ring_prod__submit(&tx_ring_, 1);
        return frame_len;
    }

    /**
     * Send raw frame at UMEM address (for zero-copy TX)
     *
     * Submits frame directly to TX ring. Used by userspace TCP stack
     * to send packets built in UMEM frames.
     *
     * @param addr UMEM address (from frame_idx_to_addr())
     * @param len Frame length
     * @return len on success, -1 on error (TX ring full)
     */
    ssize_t send_raw_frame(uint64_t addr, size_t len) {
        uint32_t idx;
        if (xsk_ring_prod__reserve(&tx_ring_, 1, &idx) != 1) {
            return -1;  // TX ring full
        }

        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&tx_ring_, idx);
        tx_desc->addr = addr + HEADROOM;
        tx_desc->len = len;
        tx_desc->options = 0;

        xsk_ring_prod__submit(&tx_ring_, 1);

        // Kick TX if kernel needs wakeup (required with XDP_USE_NEED_WAKEUP)
        kick_tx();

        return len;
    }

    /**
     * Get TX pool statistics (for debugging)
     */
    void get_tx_pool_stats(uint32_t& allocated, uint32_t& pending, uint32_t& available) const {
        allocated = tx_alloc_pos_;
        pending = tx_alloc_pos_ - tx_free_pos_;
        available = tx_pool_size_ - pending;
    }

    // ========================================================================
    // End Zero-Copy Retransmit API
    // ========================================================================

    /**
     * Get underlying AF_XDP socket file descriptor (for event polling)
     *
     * @return XDP socket FD, or -1 if not initialized
     */
    int get_fd() const {
        return xsk_ ? xsk_socket__fd(xsk_) : -1;
    }

    /**
     * Check if connected
     */
    bool is_connected() const {
        return connected_;
    }

    /**
     * Close XDP transport
     */
    void close() {
        // Stop RX trickle thread first (before closing sockets)
        stop_rx_trickle();

        // cleanup() handles xsk_socket__delete() which closes the AF_XDP socket
        cleanup();
        connected_ = false;
    }

    /**
     * Stop RX trickle thread (public API)
     *
     * Call this after SSL/WebSocket handshake completes to stop the background
     * trickle thread. After handshake, inline trickle in poll_wait() and
     * send_frame() provides NAPI triggers, so the thread is no longer needed.
     *
     * This reduces CPU overhead by eliminating the 500 Hz self-ping thread.
     * Inline trickle continues to trigger NAPI for both RX delivery and TX
     * completions in receive-only and send-heavy workloads.
     */
    void stop_rx_trickle_thread() {
        stop_rx_trickle();
    }

    static const char* name() {
        return "XDP (AF_XDP)";
    }

    // ========================================================================
    // XSK State Accessors (for pipeline process inheritance)
    // ========================================================================
    // These allow child processes to inherit the XSK socket/UMEM after fork

    struct xsk_socket* get_xsk() { return xsk_; }
    struct xsk_umem* get_umem() { return umem_; }
    void* get_umem_area() { return umem_area_; }
    size_t get_umem_size() const { return umem_size_; }
    struct xsk_ring_prod* get_fill_ring() { return &fill_ring_; }
    struct xsk_ring_cons* get_comp_ring() { return &comp_ring_; }
    struct xsk_ring_cons* get_rx_ring() { return &rx_ring_; }
    struct xsk_ring_prod* get_tx_ring() { return &tx_ring_; }
    uint32_t get_frame_size() const { return config_.frame_size; }
    BPFLoader* get_bpf_loader() { return bpf_loader_; }

    // ========================================================================

    /**
     * Enable BPF packet filtering
     *
     * Loads and attaches eBPF program to filter packets. Exchange traffic
     * is redirected to AF_XDP socket, other traffic goes to kernel.
     *
     * @param bpf_obj_path Path to compiled BPF object file (.bpf.o)
     * @throws std::runtime_error on failure
     */
    void enable_bpf_filter(const char* bpf_obj_path = "src/xdp/bpf/exchange_filter.bpf.o") {
        if (bpf_enabled_) {
            return;  // Already enabled
        }

        if (!xsk_) {
            throw std::runtime_error("XDPTransport: Must call init() before enable_bpf_filter()");
        }

        // Create BPF loader
        bpf_loader_ = new BPFLoader();

        // Load BPF program
        bpf_loader_->load(config_.interface, bpf_obj_path);

        // Attach to interface
        bpf_loader_->attach();

        // Register our AF_XDP socket in the xsks_map
        int xdp_fd = xsk_socket__fd(xsk_);
        bpf_loader_->register_xsk(config_.queue_id, xdp_fd);

        bpf_enabled_ = true;

        printf("[XDP] ✅ BPF packet filtering enabled\n");
    }

    /**
     * Disable BPF packet filtering
     */
    void disable_bpf_filter() {
        if (!bpf_enabled_ || !bpf_loader_) {
            return;
        }

        delete bpf_loader_;
        bpf_loader_ = nullptr;
        bpf_enabled_ = false;

        printf("[XDP] BPF packet filtering disabled\n");
    }

    /**
     * Add exchange IP address to BPF filter
     *
     * @param ip_str IP address string (e.g., "52.192.2.5")
     */
    void add_exchange_ip(const char* ip_str) {
        if (!bpf_enabled_ || !bpf_loader_) {
            throw std::runtime_error("XDPTransport: BPF filtering not enabled");
        }

        bpf_loader_->add_exchange_ip(ip_str);
    }

    /**
     * Add exchange port to BPF filter
     *
     * @param port Port number (host byte order)
     */
    void add_exchange_port(uint16_t port) {
        if (!bpf_enabled_ || !bpf_loader_) {
            throw std::runtime_error("XDPTransport: BPF filtering not enabled");
        }

        bpf_loader_->add_exchange_port(port);
    }

    /**
     * Set local IP address (Phase 1: destination-based filtering)
     */
    void set_local_ip(const char* ip_str) {
        if (!bpf_enabled_ || !bpf_loader_) {
            throw std::runtime_error("XDPTransport: BPF filtering not enabled");
        }

        bpf_loader_->set_local_ip(ip_str);
    }

    /**
     * Get BPF statistics
     */
    BPFStats get_bpf_stats() const {
        if (!bpf_enabled_ || !bpf_loader_) {
            return BPFStats{};
        }

        return bpf_loader_->get_stats();
    }

    /**
     * Print BPF statistics
     */
    void print_bpf_stats() const {
        if (!bpf_enabled_ || !bpf_loader_) {
            printf("[XDP] BPF filtering not enabled\n");
            return;
        }

        bpf_loader_->print_stats();
    }

    /**
     * Check if BPF filtering is enabled
     */
    bool is_bpf_enabled() const {
        return bpf_enabled_;
    }

    /**
     * Get XDP mode name (for diagnostics)
     */
    const char* get_xdp_mode() const {
        if (bpf_enabled_) {
            return "Native Driver Mode + Zero-Copy (XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY)";
        } else if (config_.zero_copy) {
            return "Zero-Copy Mode (XDP_ZEROCOPY)";
        } else {
            return "Copy Mode (XDP_COPY)";
        }
    }

    /**
     * Get interface name
     */
    const char* get_interface() const {
        return config_.interface;
    }

    /**
     * Get queue ID
     */
    uint32_t get_queue_id() const {
        return config_.queue_id;
    }

private:
    void cleanup() {
        // Close RX trickle socket (used by both background thread and inline trickle)
        if (rx_trickle_fd_ >= 0) {
            ::close(rx_trickle_fd_);
            rx_trickle_fd_ = -1;
        }

        // Clean up BPF first (detach before deleting socket)
        if (bpf_loader_) {
            delete bpf_loader_;
            bpf_loader_ = nullptr;
        }
        bpf_enabled_ = false;

        if (xsk_) {
            xsk_socket__delete(xsk_);
            xsk_ = nullptr;
        }

        if (umem_) {
            xsk_umem__delete(umem_);
            umem_ = nullptr;
        }

        if (umem_area_) {
            munmap(umem_area_, umem_size_);
            umem_area_ = nullptr;
        }

        if (umem_fd_ >= 0) {
            ::close(umem_fd_);
            umem_fd_ = -1;
        }

        if (!free_frames_.empty()) {
            free_frames_.clear();
        }
    }

    // ========================================================================
    // RX Trickle Implementation
    // ========================================================================
    //
    // RATIONALE: igc driver (Intel I225/I226 NICs) zero-copy TX completion bug
    // -------------------------------------------------------------------------
    // In XDP zero-copy mode (XDP_ZEROCOPY), the igc driver processes TX
    // completions during NAPI polling. However, NAPI only runs when:
    //   1. Hardware interrupt triggers (RX packet arrives)
    //   2. Busy-poll is active (requires RX traffic to have work)
    //
    // Without RX traffic, TX completions never happen, causing:
    //   - Packets stuck in TX ring (pending > 0)
    //   - SSL handshake timeout (server ACKs never processed)
    //   - Connection stall
    //
    // The TX completion path in igc driver:
    //   igc_poll() -> igc_clean_tx_ring() -> xsk_tx_completed()
    //
    // This only runs during NAPI poll, which requires:
    //   1. igc_xsk_wakeup() to schedule NAPI (via sendto())
    //   2. NAPI to actually run (triggered by IRQ or busy-poll)
    //   3. napi_busy_loop() to process both RX and TX
    //
    // WORKAROUND: RX Trickle
    // ----------------------
    // We inject minimal RX traffic using raw socket self-ping to the
    // interface's own MAC address. This triggers NAPI polls which
    // process both RX and TX completions.
    //
    // The trickle packet is a minimal UDP packet:
    //   - Ethernet: self MAC -> self MAC
    //   - IP: 127.0.0.1 -> 127.0.0.1 (loopback, won't be routed)
    //   - UDP: port 65534 -> 65534 (unused high port)
    //   - Payload: 1 byte
    //
    // At 500 Hz (2ms interval), this generates ~50KB/s of traffic,
    // which is negligible compared to HFT workloads.
    //
    // ALTERNATIVE SOLUTIONS:
    // 1. Use XDP_COPY mode (adds ~1-2µs latency per packet)
    // 2. Wait for Intel to fix igc driver (unknown timeline)
    // 3. Use different NIC with better XDP support (e.g., Mellanox)
    // ========================================================================

    /**
     * Start RX trickle thread for zero-copy TX completion workaround
     */
    void start_rx_trickle() {
        if (rx_trickle_running_.load()) {
            return;  // Already running
        }

        // Get interface MAC address
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, config_.interface, IFNAMSIZ - 1);

        int tmp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_fd < 0) {
            printf("[RX-TRICKLE] Warning: Cannot create socket for MAC lookup: %s\n", strerror(errno));
            return;
        }

        if (ioctl(tmp_fd, SIOCGIFHWADDR, &ifr) < 0) {
            printf("[RX-TRICKLE] Warning: Cannot get MAC address for %s: %s\n",
                   config_.interface, strerror(errno));
            ::close(tmp_fd);
            return;
        }
        ::close(tmp_fd);

        // Store MAC address for packet construction
        memcpy(local_mac_, ifr.ifr_hwaddr.sa_data, 6);

        // Create raw socket for sending trickle packets
        rx_trickle_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rx_trickle_fd_ < 0) {
            printf("[RX-TRICKLE] Warning: Cannot create raw socket: %s\n", strerror(errno));
            return;
        }

        // Bind to interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex_;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(rx_trickle_fd_, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            printf("[RX-TRICKLE] Warning: Cannot bind raw socket to %s: %s\n",
                   config_.interface, strerror(errno));
            ::close(rx_trickle_fd_);
            rx_trickle_fd_ = -1;
            return;
        }

        // Build trickle packet (minimal UDP to self)
        build_trickle_packet();

        // Start trickle thread
        rx_trickle_running_.store(true);
        rx_trickle_thread_ = std::thread([this]() {
            printf("[RX-TRICKLE] Thread started (interval=%u us, ~%u Hz)\n",
                   config_.rx_trickle_interval_us, 1000000 / config_.rx_trickle_interval_us);

            uint64_t packets_sent = 0;
            while (rx_trickle_running_.load()) {
                // Send trickle packet
                ssize_t sent = send(rx_trickle_fd_, trickle_packet_, trickle_packet_len_, 0);
                if (sent > 0) {
                    packets_sent++;
                }

                // Sleep for configured interval
                usleep(config_.rx_trickle_interval_us);
            }

            printf("[RX-TRICKLE] Thread stopped (sent %lu packets)\n", packets_sent);
        });

        printf("[RX-TRICKLE] Started on %s (MAC=%02x:%02x:%02x:%02x:%02x:%02x)\n",
               config_.interface,
               local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);

        // Wait for trickle thread to send at least one packet before returning.
        // This ensures NAPI poll is triggered before any TX operations (e.g., SYN packet),
        // which is critical for TX completion processing on igc driver in zero-copy mode.
        usleep(config_.rx_trickle_interval_us * 2);  // Wait ~2 intervals to ensure packet sent
    }

    /**
     * Stop RX trickle thread
     *
     * NOTE: This only stops the background thread. The rx_trickle_fd_ socket is
     * intentionally kept open for inline trickle use in poll_wait(). The socket
     * is closed in cleanup() when the XDP transport is fully destroyed.
     */
    void stop_rx_trickle() {
        if (!rx_trickle_running_.load()) {
            return;  // Not running
        }

        rx_trickle_running_.store(false);

        if (rx_trickle_thread_.joinable()) {
            rx_trickle_thread_.join();
        }

        // NOTE: Do NOT close rx_trickle_fd_ here - it's still needed for
        // inline trickle in poll_wait() to trigger NAPI during receive-only
        // workloads. The socket is closed in cleanup().

        printf("[RX-TRICKLE] Stopped (socket kept open for inline trickle)\n");
    }

    /**
     * Build minimal trickle packet (Ethernet + IP + UDP + 1 byte payload)
     *
     * Layout:
     *   [Ethernet Header (14 bytes)]
     *     - dst MAC: local MAC (self-addressed)
     *     - src MAC: local MAC
     *     - EtherType: 0x0800 (IPv4)
     *   [IP Header (20 bytes)]
     *     - version: 4, IHL: 5
     *     - total length: 29 (20 IP + 8 UDP + 1 payload)
     *     - TTL: 1 (won't be routed)
     *     - protocol: UDP (17)
     *     - src/dst: 127.0.0.1 (loopback)
     *   [UDP Header (8 bytes)]
     *     - src/dst port: 65534
     *     - length: 9 (8 header + 1 payload)
     *   [Payload (1 byte)]
     *     - 0x00
     */
    void build_trickle_packet() {
        memset(trickle_packet_, 0, sizeof(trickle_packet_));

        // Ethernet header (14 bytes)
        uint8_t* eth = trickle_packet_;
        memcpy(eth, local_mac_, 6);        // dst MAC = self
        memcpy(eth + 6, local_mac_, 6);    // src MAC = self
        eth[12] = 0x08;                    // EtherType = IPv4
        eth[13] = 0x00;

        // IP header (20 bytes)
        uint8_t* ip = eth + 14;
        ip[0] = 0x45;              // version=4, IHL=5
        ip[1] = 0x00;              // DSCP/ECN
        ip[2] = 0x00;              // total length (high byte)
        ip[3] = 0x1D;              // total length = 29 (20+8+1)
        ip[4] = 0x00;              // identification
        ip[5] = 0x00;
        ip[6] = 0x40;              // flags (Don't Fragment)
        ip[7] = 0x00;              // fragment offset
        ip[8] = 0x01;              // TTL = 1 (won't be routed)
        ip[9] = 0x11;              // protocol = UDP (17)
        ip[10] = 0x00;             // header checksum (will calculate)
        ip[11] = 0x00;
        // src IP = 127.0.0.1
        ip[12] = 127; ip[13] = 0; ip[14] = 0; ip[15] = 1;
        // dst IP = 127.0.0.1
        ip[16] = 127; ip[17] = 0; ip[18] = 0; ip[19] = 1;

        // Calculate IP header checksum
        uint32_t sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += (ip[i] << 8) | ip[i + 1];
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        uint16_t checksum = ~sum;
        ip[10] = checksum >> 8;
        ip[11] = checksum & 0xFF;

        // UDP header (8 bytes)
        uint8_t* udp = ip + 20;
        udp[0] = 0xFF;             // src port = 65534 (high byte)
        udp[1] = 0xFE;             // src port = 65534 (low byte)
        udp[2] = 0xFF;             // dst port = 65534 (high byte)
        udp[3] = 0xFE;             // dst port = 65534 (low byte)
        udp[4] = 0x00;             // length = 9 (8 + 1)
        udp[5] = 0x09;
        udp[6] = 0x00;             // checksum (0 = disabled)
        udp[7] = 0x00;

        // Payload (1 byte)
        udp[8] = 0x00;

        // Total packet length: 14 (eth) + 20 (ip) + 8 (udp) + 1 (payload) = 43 bytes
        trickle_packet_len_ = 43;
    }

    // ========================================================================
    // End RX Trickle Implementation
    // ========================================================================

    /**
     * Reclaim completed TX frames from completion ring
     */
    void reclaim_completed_frames() {
        uint32_t idx_cq;
        uint32_t nb_completed = xsk_ring_cons__peek(&comp_ring_, config_.batch_size, &idx_cq);

        if (nb_completed == 0) {
            return;
        }

        // Add completed frames back to free list
        // NOTE: The completion addr includes HEADROOM offset,
        // so we need to subtract it to get the base frame address
        // IMPORTANT: Insert at the FRONT of the free list to avoid immediately
        // reusing just-completed frames (gives DMA time to fully release)
        for (uint32_t i = 0; i < nb_completed; i++) {
            uint64_t desc_addr = *xsk_ring_cons__comp_addr(&comp_ring_, idx_cq++);
            // Convert descriptor addr back to frame base address
            uint64_t frame_addr = desc_addr - HEADROOM;
            free_frames_.insert(free_frames_.begin(), frame_addr);
        }

        xsk_ring_cons__release(&comp_ring_, nb_completed);
    }

    /**
     * Get a free UMEM frame address
     *
     * @return Frame address, or UINT64_MAX if no frames available
     */
    uint64_t get_free_frame() {
        // IMPORTANT: Prefer sequential allocation to avoid reusing just-completed
        // frames. The igc driver in zero-copy mode may still be accessing completed
        // frames briefly after CQ reports completion. Using fresh frames avoids
        // DMA race conditions.
        if (next_free_frame_ < config_.num_frames) {
            uint64_t addr = next_free_frame_ * config_.frame_size;
            next_free_frame_++;
            return addr;
        }

        // Fall back to reclaimed frames only when sequential allocation exhausted
        if (free_frames_.empty()) {
            return UINT64_MAX;  // No frames available
        }
        uint64_t addr = free_frames_.back();
        free_frames_.pop_back();
        return addr;
    }

    // Configuration (private)
    XDPConfig config_;                      // XDP configuration (interface, queue, frame size, etc.)

    // AF_XDP Socket
    struct xsk_socket* xsk_;                // AF_XDP socket handle for fast-path packet I/O

    // UMEM (User Memory for zero-copy packet buffers)
    struct xsk_umem* umem_;                 // UMEM handle for shared packet buffer memory
    void* umem_area_;                       // Pointer to mmap'd UMEM memory region
    size_t umem_size_;                      // Total UMEM size (num_frames × frame_size)
    int umem_fd_;                           // File descriptor for UMEM shared memory

    // Ring Buffers (zero-copy I/O between userspace and kernel)
    struct xsk_ring_prod fill_ring_;       // Producer: UMEM frames available for RX (app → kernel)
    struct xsk_ring_cons comp_ring_;       // Consumer: Completed TX frames (kernel → app)
    struct xsk_ring_cons rx_ring_;         // Consumer: Received packets (kernel → app)
    struct xsk_ring_prod tx_ring_;         // Producer: Packets to transmit (app → kernel)

    // Connection State
    bool connected_;                        // Connection state flag
    unsigned int ifindex_;                  // Network interface index

    // Frame Management
    std::vector<uint64_t> free_frames_;     // Pool of free UMEM frame addresses
    uint32_t next_free_frame_;              // Next unused frame index for initial allocation

    // Zero-copy frame management (no FramePool - just reusable frame structs)
    XDPFrame rx_frame_;                     // Reusable RX frame (only one held at a time)
    XDPFrame tx_frame_;                     // Reusable TX frame (only one built at a time)
    XDPFrame* current_rx_frame_;            // Points to rx_frame_ when holding, nullptr otherwise
    uint64_t current_rx_addr_;              // RX descriptor address (with headroom)

    // BPF packet filtering (optional)
    BPFLoader* bpf_loader_;                 // BPF loader for packet filtering (nullptr if disabled)
    bool bpf_enabled_;                      // Whether BPF filtering is enabled

    // RX Trickle thread (for zero-copy TX completion workaround)
    std::atomic<bool> rx_trickle_running_;  // Trickle thread running flag
    std::thread rx_trickle_thread_;         // Trickle thread handle
    int rx_trickle_fd_;                     // Raw socket FD for trickle packets
    uint8_t local_mac_[6];                  // Local MAC address for self-ping
    uint8_t trickle_packet_[64];            // Pre-built trickle packet
    size_t trickle_packet_len_;             // Trickle packet length

    // Cached poll state (avoid recreating struct on every poll_wait call)
    struct pollfd poll_fd_;                 // Cached pollfd for poll_wait()
    uint8_t poll_wait_count_;               // Counter for inline trickle throttling

    // TX Pool Management (for zero-copy retransmit)
    // TX frames are released based on TCP ACK, not TX completion
    uint32_t rx_pool_size_;                 // Number of frames in RX pool
    uint32_t tx_pool_start_;                // First frame index in TX pool
    uint32_t tx_pool_size_;                 // Number of frames in TX pool
    uint32_t tx_alloc_pos_;                 // Next frame to allocate (monotonic counter)
    uint32_t tx_free_pos_;                  // Next frame available for reuse (monotonic counter)
    std::array<bool, DEFAULT_TX_POOL_SIZE> frame_acked_;  // Per-TX-frame ACK status
};

#else  // !USE_XDP

// Stub when XDP is not enabled
struct XDPTransport {
    void init(const void*) {
        throw std::runtime_error("XDP support not compiled. Build with USE_XDP=1");
    }
    bool is_connected() const { return false; }
    void close() {}
    static const char* name() { return "XDP (disabled)"; }
};

#endif  // USE_XDP

}  // namespace xdp
}  // namespace websocket
