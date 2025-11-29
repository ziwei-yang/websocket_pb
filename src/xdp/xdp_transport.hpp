// xdp/xdp_transport.hpp
// AF_XDP (eXpress Data Path) Transport Layer
//
// This provides zero-copy packet I/O using AF_XDP sockets for HFT use cases:
//   - Zero-copy packet I/O via UMEM (User Memory)
//   - Complete kernel bypass with userspace TCP/IP stack
//   - Sub-microsecond latency (~1-2 μs NIC to app)
//
// Architecture:
//   Application → Userspace TCP/IP Stack → XDP Transport → AF_XDP Socket → NIC
//
// Primary API (Zero-Copy):
//   - peek_rx_frame() / release_rx_frame() - Zero-copy RX
//   - get_tx_frame() / send_frame() - Zero-copy TX
//
// Requirements:
//   - Linux kernel 5.4+ (AF_XDP zero-copy support)
//   - libbpf, libxdp
//   - XDP-capable NIC (e.g., Intel igc/i40e/ixgbe)
//   - CAP_NET_RAW + CAP_BPF or root privileges

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

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
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "xdp_frame.hpp"
#include "bpf_loader.hpp"
#endif

namespace websocket {
namespace xdp {

#ifdef USE_XDP

/**
 * XDP Transport Configuration
 */
struct XDPConfig {
    const char* interface;      // Network interface (e.g., "eth0")
    uint32_t queue_id;          // RX/TX queue ID (usually 0)
    uint32_t frame_size;        // UMEM frame size (default: 2048)
    uint32_t num_frames;        // Number of UMEM frames (default: 4096)
    bool zero_copy;             // Enable zero-copy mode (requires driver support)
    uint32_t batch_size;        // Batch size for TX/RX (default: 64)

    XDPConfig()
        : interface("eth0")
        , queue_id(0)
        , frame_size(XSK_UMEM__DEFAULT_FRAME_SIZE)  // 2048
        , num_frames(4096)
        , zero_copy(true)   // Enable zero-copy by default for HFT (igc driver supports it)
        , batch_size(64)
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
 */
class XDPTransport {
public:
    // Use 256 bytes headroom - maximum supported by igc driver for XDP_ZEROCOPY mode
    // Note: Higher values (e.g., 512) cause EOPNOTSUPP when using zero-copy
    static constexpr uint32_t XDP_HEADROOM = 256;

    XDPTransport()
        : xsk_(nullptr)
        , umem_(nullptr)
        , umem_area_(nullptr)
        , umem_size_(0)
        , socket_fd_(-1)
        , connected_(false)
        , ifindex_(0)
        , next_free_frame_(0)
        , current_rx_frame_(nullptr)
        , current_rx_addr_(0)
        , bpf_loader_(nullptr)
        , bpf_enabled_(false)
    {
        free_frames_.reserve(4096);  // Pre-allocate for performance
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
        umem_size_ = config_.num_frames * config_.frame_size;
        umem_area_ = mmap(nullptr, umem_size_,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);

        if (umem_area_ == MAP_FAILED) {
            // Fallback to regular pages if huge pages fail
            umem_area_ = mmap(nullptr, umem_size_,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1, 0);
        }

        if (umem_area_ == MAP_FAILED) {
            throw std::runtime_error("Failed to allocate UMEM");
        }

        // Configure UMEM
        struct xsk_umem_config umem_cfg;
        memset(&umem_cfg, 0, sizeof(umem_cfg));
        umem_cfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        umem_cfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        umem_cfg.frame_size = config_.frame_size;
        umem_cfg.frame_headroom = XDP_HEADROOM;  // Use 256 bytes, not 0
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
        xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;

        // If BPF filtering enabled, bind to the existing XDP program
        // Otherwise, let libxsk attach its default XDP program
        if (bpf_enabled_) {
            // IMPORTANT: Use XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD to prevent libxsk from loading its own program
            // When INHIBIT_PROG_LOAD is set, xdp_flags should be 0 (we've already attached our program)
            xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
            xsk_cfg.xdp_flags = 0;  // Don't touch XDP program - we've already attached it
            xsk_cfg.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;  // Zero-copy mode with wakeup
        } else {
            xsk_cfg.libbpf_flags = 0;
            xsk_cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
            xsk_cfg.bind_flags = config_.zero_copy ? XDP_ZEROCOPY : XDP_COPY;
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

        // If BPF enabled, register the socket in the BPF map
        // (BPF program was already attached before socket creation)
        if (bpf_enabled_) {
            // CRITICAL: Must use xsk_socket__update_xskmap() for XSKMAP type!
            // Manual bpf_map_update_elem() does NOT work for AF_XDP socket maps
            bpf_loader_->register_xsk_socket(xsk_);

            printf("[XDP] ✅ BPF filtering enabled\n");
        }

        // Populate fill ring with UMEM frames
        // Note: Fill ring size might be smaller than total UMEM frames
        uint32_t idx = 0;
        uint32_t fill_ring_size = umem_cfg.fill_size;
        uint32_t frames_to_populate = (config_.num_frames < fill_ring_size) ? config_.num_frames : fill_ring_size;

        ret = xsk_ring_prod__reserve(&fill_ring_, frames_to_populate, &idx);
        if (ret != (int)frames_to_populate) {
            cleanup();
            throw std::runtime_error("Failed to populate fill ring");
        }

        for (uint32_t i = 0; i < frames_to_populate; i++) {
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

        // CRITICAL FIX: Wake up kernel after initial FILL ring population!
        // Without this, kernel doesn't know frames are available for RX
        kick_rx();
        printf("[XDP] ✅ Kicked RX after initial FILL ring population\n");

        // CRITICAL FIX: Mark frames in fill ring as "used" by advancing the allocator
        // Otherwise TX will reuse the same frames that RX owns, causing corruption
        next_free_frame_ = frames_to_populate;
        printf("[XDP] Reserved first %u frames for RX fill ring (TX starts at frame %u)\n",
               frames_to_populate, next_free_frame_);

        // Initialize reusable frame structs (no FramePool needed)
        rx_frame_.clear();
        rx_frame_.capacity = config_.frame_size - XDP_HEADROOM;
        tx_frame_.clear();
        tx_frame_.capacity = config_.frame_size - XDP_HEADROOM;

        // Mark as "connected" for userspace stack usage (no TCP socket needed)
        connected_ = true;
        socket_fd_ = 1;  // Dummy value (not used for TX/RX frames)

        printf("[XDP] Initialized on %s (queue %u, %u frames)\n",
               config_.interface, config_.queue_id, config_.num_frames);
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
        if (!connected_ || socket_fd_ < 0) {
            errno = ENOTCONN;
            return nullptr;
        }

        // If we already have a frame held, return it
        if (current_rx_frame_ != nullptr) {
            return current_rx_frame_;
        }

        // Debug: Check fill ring status before trying to receive
        static int debug_call_count = 0;
        debug_call_count++;
        bool print_debug = (debug_call_count <= 100 || debug_call_count % 1000 == 0);
        if (print_debug) {
            uint32_t fill_avail = xsk_prod_nb_free(&fill_ring_, config_.num_frames);
            uint32_t rx_avail = xsk_cons_nb_avail(&rx_ring_, config_.num_frames);
            printf("[XDP-DEBUG] peek_rx_frame call #%d: fill_ring_free=%u, rx_ring_avail=%u\n",
                   debug_call_count, fill_avail, rx_avail);
            fflush(stdout);
        }

        // NOTE: No kick_rx() here - kernel is kicked only when:
        //   1. After init (FILL ring initially populated)
        //   2. After release_rx_frame() (FILL ring refilled)
        // This avoids unnecessary syscalls on every peek attempt.

        // Check RX ring for received packets
        uint32_t idx_rx;
        uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, 1, &idx_rx);

        if (print_debug) {
            printf("[PEEK-DEBUG] Peeked RX ring: nb_pkts=%u\n", nb_pkts);
        }

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
        rx_frame_.data = (uint8_t*)umem_area_ + rx_desc->addr;
        rx_frame_.len = rx_desc->len;
        rx_frame_.capacity = config_.frame_size - XDP_HEADROOM;
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
     */
    void release_rx_frame(XDPFrame* frame) {
        if (frame == nullptr || frame != current_rx_frame_) {
            return;
        }

        // Debug: Track refill operations
        static int refill_count = 0;
        refill_count++;
        bool print_debug = (refill_count <= 5 || refill_count % 10 == 0);

        // Release RX descriptor (this was peeked in peek_rx_frame)
        xsk_ring_cons__release(&rx_ring_, 1);

        // Refill fill ring with the SAME address the kernel gave us (includes headroom)
        // CRITICAL: Must use current_rx_addr_ (from RX descriptor) not frame->addr (base address)
        // The kernel adds headroom (0x100) when writing packets, so we must refill with that address
        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&fill_ring_, 1, &idx_fq) == 1) {
            // Get base address by subtracting headroom
            uint64_t base_addr = current_rx_addr_ & ~(config_.frame_size - 1);
            *xsk_ring_prod__fill_addr(&fill_ring_, idx_fq) = base_addr;
            xsk_ring_prod__submit(&fill_ring_, 1);

            // CRITICAL FIX: Wake up kernel after refilling!
            // Without this, kernel doesn't know fill ring has new frames -> ENOSPC errors
            kick_rx();

            if (print_debug) {
                printf("[REFILL-DEBUG] Refill #%d: RX addr=0x%lx, refilling base=0x%lx (+ kick)\n",
                       refill_count, current_rx_addr_, base_addr);
            }
        } else {
            printf("[REFILL-ERROR] Refill #%d: Failed to reserve fill ring space! RX addr=0x%lx lost!\n",
                   refill_count, current_rx_addr_);
        }

        // Clear frame state (no FramePool to release, just clear pointer)
        rx_frame_.clear();
        current_rx_frame_ = nullptr;
        current_rx_addr_ = 0;
    }

    /**
     * Release RX frame from ring but defer FILL ring refill (zero-copy mode)
     *
     * This releases the RX ring consumer so more frames can be peeked,
     * but does NOT refill the FILL ring. Caller must call refill_frame()
     * later when done with the frame data.
     *
     * @param frame Frame to release (must be from peek_rx_frame())
     * @return UMEM address to pass to refill_frame() later, or 0 on error
     */
    uint64_t release_rx_frame_deferred(XDPFrame* frame) {
        if (frame == nullptr || frame != current_rx_frame_) {
            return 0;
        }

        // Save the address for later refill
        uint64_t saved_addr = current_rx_addr_;

        // Release RX descriptor (so we can peek next frame)
        xsk_ring_cons__release(&rx_ring_, 1);

        // Clear frame state but DON'T refill FILL ring yet
        rx_frame_.clear();
        current_rx_frame_ = nullptr;
        current_rx_addr_ = 0;

        return saved_addr;
    }

    /**
     * Refill a frame to FILL ring (deferred zero-copy release)
     *
     * Called when SSL has finished consuming data from a frame that was
     * released with release_rx_frame_deferred().
     *
     * @param umem_addr UMEM address returned from release_rx_frame_deferred()
     */
    void refill_frame(uint64_t umem_addr) {
        if (umem_addr == 0) return;

        // Debug: Track refill operations
        static int deferred_refill_count = 0;
        deferred_refill_count++;
        bool print_debug = (deferred_refill_count <= 5 || deferred_refill_count % 10 == 0);

        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&fill_ring_, 1, &idx_fq) == 1) {
            // Get base address by masking off headroom offset
            uint64_t base_addr = umem_addr & ~(config_.frame_size - 1);
            *xsk_ring_prod__fill_addr(&fill_ring_, idx_fq) = base_addr;
            xsk_ring_prod__submit(&fill_ring_, 1);

            // Wake up kernel
            kick_rx();

            if (print_debug) {
                printf("[DEFERRED-REFILL] #%d: addr=0x%lx, base=0x%lx\n",
                       deferred_refill_count, umem_addr, base_addr);
            }
        } else {
            printf("[DEFERRED-REFILL-ERROR] #%d: Failed to reserve FILL ring! addr=0x%lx lost!\n",
                   deferred_refill_count, umem_addr);
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
        if (!connected_ || socket_fd_ < 0) {
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
        tx_frame_.data = (uint8_t*)umem_area_ + frame_addr + XDP_HEADROOM;
        tx_frame_.len = 0;
        tx_frame_.capacity = config_.frame_size - XDP_HEADROOM;
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
        if (!connected_ || socket_fd_ < 0) {
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

        // Debug: Log TX submission and packet contents
        static int tx_count = 0;
        if (++tx_count <= 3) {
            printf("[TX-DEBUG] Submitted TX descriptor #%d: addr=0x%llx, len=%u, idx=%u\n",
                   tx_count, (unsigned long long)tx_desc->addr, tx_desc->len, idx);

            // Dump first 64 bytes of packet (data is at frame->data, already includes headroom)
            uint8_t* pkt = frame->data;
            printf("[TX-DEBUG] Packet dump (first 64 bytes):\n");
            for (uint32_t i = 0; i < std::min(64u, tx_desc->len); i += 16) {
                printf("  %04x: ", i);
                for (uint32_t j = i; j < std::min(i + 16, tx_desc->len); j++) {
                    printf("%02x ", pkt[j]);
                }
                printf("\n");
            }
        }

        // Kick the kernel to process TX ring
        kick_tx();

        // Mark frame as no longer owned by application
        frame->owned = false;

        return len;
    }

    // ========================================================================
    // End Zero-Copy API
    // ========================================================================

    /**
     * Get underlying socket file descriptor (for event polling)
     *
     * @return Socket FD
     */
    int get_fd() const {
        return socket_fd_;
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
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }

        cleanup();
        connected_ = false;
    }

    static const char* name() {
        return "XDP (AF_XDP)";
    }

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

        if (!free_frames_.empty()) {
            free_frames_.clear();
        }
    }

    /**
     * Reclaim completed TX frames from completion ring
     */
    void reclaim_completed_frames() {
        uint32_t idx_cq;
        uint32_t nb_completed = xsk_ring_cons__peek(&comp_ring_, config_.batch_size, &idx_cq);

        if (nb_completed == 0) {
            return;
        }

        // Debug: Log completion
        static int reclaim_count = 0;
        if (++reclaim_count <= 3) {
            printf("[TX-DEBUG] Reclaimed %u completed frames from CQ (call #%d)\n",
                   nb_completed, reclaim_count);
        }

        // Add completed frames back to free list
        for (uint32_t i = 0; i < nb_completed; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring_, idx_cq++);
            free_frames_.push_back(addr);
        }

        xsk_ring_cons__release(&comp_ring_, nb_completed);
    }

    /**
     * Get a free UMEM frame address
     *
     * @return Frame address, or UINT64_MAX if no frames available
     */
    uint64_t get_free_frame() {
        if (free_frames_.empty()) {
            // Try to allocate from free pool
            if (next_free_frame_ >= config_.num_frames) {
                return UINT64_MAX;  // No frames available
            }
            uint64_t addr = next_free_frame_ * config_.frame_size;
            next_free_frame_++;
            return addr;
        }

        // Reuse a previously freed frame
        uint64_t addr = free_frames_.back();
        free_frames_.pop_back();
        return addr;
    }

    /**
     * Kick the kernel to process TX ring
     *
     * Uses sendto() on AF_XDP socket to trigger transmission
     */
    void kick_tx() {
        int xdp_fd = xsk_socket__fd(xsk_);

        // Send dummy packet to kick kernel
        // This triggers the kernel to process the TX ring
        // Note: Always call sendto() - the kernel will ignore if not needed
        static int kick_count = 0;
        int ret = sendto(xdp_fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        if (++kick_count <= 3) {
            printf("[TX-DEBUG] kick_tx() call #%d: fd=%d, ret=%d, errno=%d\n",
                   kick_count, xdp_fd, ret, (ret < 0) ? errno : 0);
        }
    }

    /**
     * Wake up kernel to process RX packets
     *
     * When XDP_USE_NEED_WAKEUP is set, we need to check the wakeup flag
     * and call recvfrom() when the kernel needs a kick.
     */
    void kick_rx() {
        // Check if kernel needs wakeup (when XDP_USE_NEED_WAKEUP is set)
        if (xsk_ring_prod__needs_wakeup(&fill_ring_)) {
            int xdp_fd = xsk_socket__fd(xsk_);

            // Wake up kernel to process RX
            // Using recvfrom() with MSG_DONTWAIT to avoid blocking
            recvfrom(xdp_fd, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
        }
    }

    // Configuration
    XDPConfig config_;                      // XDP configuration (interface, queue, frame size, etc.)

    // AF_XDP Socket
    struct xsk_socket* xsk_;                // AF_XDP socket handle for fast-path packet I/O

    // UMEM (User Memory for zero-copy packet buffers)
    struct xsk_umem* umem_;                 // UMEM handle for shared packet buffer memory
    void* umem_area_;                       // Pointer to mmap'd UMEM memory region
    size_t umem_size_;                      // Total UMEM size (num_frames × frame_size)

    // Ring Buffers (zero-copy I/O between userspace and kernel)
    struct xsk_ring_prod fill_ring_;       // Producer: UMEM frames available for RX (app → kernel)
    struct xsk_ring_cons comp_ring_;       // Consumer: Completed TX frames (kernel → app)
    struct xsk_ring_cons rx_ring_;         // Consumer: Received packets (kernel → app)
    struct xsk_ring_prod tx_ring_;         // Producer: Packets to transmit (app → kernel)

    // TCP Connection State
    int socket_fd_;                         // TCP socket file descriptor for connection
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
};

#else  // !USE_XDP

// Stub when XDP is not enabled
class XDPTransport {
public:
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
