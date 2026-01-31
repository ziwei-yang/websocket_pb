// xdp/xdp_packet_io.hpp
// XDP Packet I/O Policy - Primary AF_XDP interface for PacketTransport
//
// This provides a policy-based interface for packet I/O operations,
// enabling PacketTransport<PacketIO> to work with XDP, DPDK, or other
// packet I/O backends using the same transport logic.
//
// Architecture:
//   PacketTransport<XDPPacketIO>
//       │
//       └── XDPPacketIO (this file, public API)
//               │
//               └── XDPTransport (xdp_transport.hpp, internal implementation)
//
// XDPPacketIO is the public interface used by PacketTransport.
// XDPTransport is an internal implementation detail that handles
// the low-level AF_XDP socket management, UMEM, and BPF integration.

#pragma once

#ifdef USE_XDP

#include "xdp_transport.hpp"
#include "xdp_frame.hpp"
#include "packet_frame_descriptor.hpp"
#include "../pipeline/pipeline_config.hpp"

namespace websocket {
namespace xdp {

/**
 * XDP Packet I/O Configuration
 *
 * Wraps XDPConfig with a cleaner interface for PacketTransport use.
 */
struct XDPPacketIOConfig {
    const char* interface;          // Network interface (e.g., "enp108s0")
    const char* bpf_path;           // Path to BPF object file
    bool zero_copy = true;          // Enable zero-copy mode (default: true for HFT)
    uint32_t queue_id = 0;          // RX/TX queue ID (usually 0)
    uint32_t num_frames = websocket::pipeline::TOTAL_UMEM_FRAMES;
    uint32_t batch_size = websocket::pipeline::XDP_BATCH_SIZE;

    // SO_BUSY_POLL settings
    uint32_t busy_poll_usec = websocket::pipeline::XDP_BUSY_POLL_USEC;
    uint32_t busy_poll_budget = websocket::pipeline::XDP_BUSY_POLL_BUDGET;

    // RX Trickle settings (igc driver workaround)
    bool rx_trickle_enabled = true;
    uint32_t rx_trickle_interval_us = websocket::pipeline::XDP_TRICKLE_INTERVAL_US;

    XDPPacketIOConfig()
        : interface(XDP_INTERFACE)
        , bpf_path(nullptr)
    {}
};

/**
 * XDP Packet I/O Policy
 *
 * Thin wrapper over XDPTransport providing a cleaner interface
 * for use with PacketTransport<PacketIO> template.
 *
 * Primary API:
 *   RX Path (Batch):
 *   - process_rx_frames() - Process available RX frames with callback
 *   - mark_frame_consumed() - Mark frame as consumed (FIFO auto-refill)
 *
 *   TX Path (Batch):
 *   - claim_tx_frames() - Claim frames for transmission with callback
 *   - commit_tx_frames() - Submit claimed frames to TX ring
 *   - mark_frame_acked() - Mark frame as ACKed (FIFO auto-release)
 *   - retransmit_frame() - Re-transmit existing frame (TCP retransmit)
 */
struct XDPPacketIO {
    // Type alias for PacketTransport to use
    using config_type = XDPPacketIOConfig;

    XDPPacketIO() : xdp_() {}
    ~XDPPacketIO() = default;

    // Prevent copying
    XDPPacketIO(const XDPPacketIO&) = delete;
    XDPPacketIO& operator=(const XDPPacketIO&) = delete;

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize XDP packet I/O
     *
     * @param config XDP configuration (interface, BPF path, etc.)
     * @throws std::runtime_error on failure
     */
    void init(const XDPPacketIOConfig& config) {
        // Convert to XDPConfig
        XDPConfig xdp_config;
        xdp_config.interface = config.interface;
        xdp_config.queue_id = config.queue_id;
        xdp_config.num_frames = config.num_frames;
        xdp_config.zero_copy = config.zero_copy;
        xdp_config.batch_size = config.batch_size;
        xdp_config.busy_poll_usec = config.busy_poll_usec;
        xdp_config.busy_poll_budget = config.busy_poll_budget;
        xdp_config.rx_trickle_enabled = config.rx_trickle_enabled;
        xdp_config.rx_trickle_interval_us = config.rx_trickle_interval_us;

        xdp_.init(xdp_config, config.bpf_path);
    }

    /**
     * Close packet I/O
     */
    void close() {
        xdp_.close();
    }

    // ========================================================================
    // TX Path - Retransmit (used by TCP retransmit, not legacy)
    // ========================================================================

    /**
     * Retransmit existing frame (no rebuild/re-encryption)
     *
     * @param idx Frame index
     * @param len Frame length
     * @return len on success, -1 on error
     */
    ssize_t retransmit_frame(uint32_t idx, uint16_t len) {
        return xdp_.retransmit_frame(idx, len);
    }

    // ========================================================================
    // TX Path - ACK-based Release
    // ========================================================================

    /**
     * Mark TX frame as ACKed
     *
     * Internally performs FIFO release: advances tx_free_pos_ while
     * contiguous frames are ACKed.
     *
     * @param frame_idx Frame index that was ACKed
     */
    void mark_frame_acked(uint32_t frame_idx) {
        xdp_.mark_frame_acked(frame_idx);
    }

    // ========================================================================
    // New Batch TX API (symmetric with RX)
    // ========================================================================

    /**
     * Batch claim TX frames with lambda callback
     *
     * @param count Number of frames to claim
     * @param callback Lambda(uint32_t idx, PacketFrameDescriptor& desc)
     * @return Number of frames actually claimed
     */
    template<typename Func>
    uint32_t claim_tx_frames(uint32_t count, Func&& callback) {
        return xdp_.claim_tx_frames(count, std::forward<Func>(callback));
    }

    /**
     * Commit claimed TX frames to TX ring
     *
     * @param lowest_idx  First frame index to commit
     * @param highest_idx Last frame index to commit (inclusive)
     */
    void commit_tx_frames(uint32_t lowest_idx, uint32_t highest_idx) {
        xdp_.commit_tx_frames(lowest_idx, highest_idx);
    }

    /**
     * Commit a single ACK frame
     *
     * In single-process XDP mode, ACKs use the same TX path as data.
     * This method exists for API compatibility with DisruptorPacketIO.
     *
     * @param callback Lambda(PacketFrameDescriptor& desc) to fill the ACK frame
     * @return Frame index on success, 0 on failure
     */
    template<typename Func>
    uint32_t commit_ack_frame(Func&& callback) {
        uint32_t frame_idx = 0;
        uint32_t claimed = claim_tx_frames(1, [&](uint32_t, PacketFrameDescriptor& desc) {
            frame_idx = frame_ptr_to_idx(desc.frame_ptr);
            desc.frame_type = FRAME_TYPE_TX_ACK;
            callback(desc);
        });
        if (claimed > 0) {
            commit_tx_frames(frame_idx, frame_idx);
            // In single-process mode, mark ACK as acked immediately
            // (no separate congestion control tracking needed)
            mark_frame_acked(frame_idx);
            return frame_idx;
        }
        return 0;
    }

    /**
     * Get frame index from a descriptor's frame_ptr
     */
    uint32_t frame_ptr_to_idx(uint64_t frame_ptr) const {
        return xdp_.frame_ptr_to_idx(frame_ptr);
    }

    // ========================================================================
    // New Batch RX API (symmetric with TX)
    // ========================================================================

    /**
     * Process RX frames with lambda callback
     *
     * @param max_frames Maximum frames to process (SIZE_MAX for all)
     * @param callback Lambda(uint32_t idx, PacketFrameDescriptor& desc)
     * @return Number of frames processed
     */
    template<typename Func>
    size_t process_rx_frames(size_t max_frames, Func&& callback) {
        return xdp_.process_rx_frames(max_frames, std::forward<Func>(callback));
    }

    /**
     * Mark RX frame as consumed (data no longer needed)
     *
     * Internally performs FIFO refill: adds frame back to FILL ring only when
     * all earlier frames are also consumed.
     *
     * @param frame_idx Frame index that was consumed
     */
    void mark_frame_consumed(uint32_t frame_idx) {
        xdp_.mark_frame_consumed(frame_idx);
    }

    /**
     * Get current RX frame processing position
     */
    uint32_t get_rx_process_pos() const {
        return xdp_.get_rx_process_pos();
    }

    // ========================================================================
    // Polling
    // ========================================================================

    /**
     * Poll for RX/TX events with userspace busy-polling
     *
     * @return 1 if events ready, 0 on timeout, -1 on error
     */
    int poll_wait() {
        return xdp_.poll_wait();
    }

    // ========================================================================
    // Frame Utilities
    // ========================================================================

    /**
     * Convert frame index to UMEM address
     */
    uint64_t frame_idx_to_addr(uint32_t idx) const {
        return xdp_.frame_idx_to_addr(idx);
    }

    /**
     * Get pointer to frame data area
     */
    uint8_t* get_frame_ptr(uint64_t addr) {
        return xdp_.get_frame_ptr(addr);
    }

    /**
     * Get frame data capacity
     */
    uint32_t frame_capacity() const {
        return xdp_.frame_capacity();
    }

    // ========================================================================
    // Configuration Access
    // ========================================================================

    /**
     * Get XDP mode name (for diagnostics)
     */
    const char* get_mode() const {
        return xdp_.get_xdp_mode();
    }

    /**
     * Get interface name
     */
    const char* get_interface() const {
        return xdp_.get_interface();
    }

    /**
     * Get queue ID
     */
    uint32_t get_queue_id() const {
        return xdp_.get_queue_id();
    }

    // ========================================================================
    // BPF Filter Configuration
    // ========================================================================

    /**
     * Add remote IP to BPF filter
     */
    void add_remote_ip(const char* ip) {
        xdp_.add_exchange_ip(ip);
    }

    /**
     * Add remote port to BPF filter
     */
    void add_remote_port(uint16_t port) {
        xdp_.add_exchange_port(port);
    }

    /**
     * Set local IP in BPF filter
     */
    void set_local_ip(const char* ip) {
        xdp_.set_local_ip(ip);
    }

    /**
     * Check if BPF filtering is enabled
     */
    bool is_bpf_enabled() const {
        return xdp_.is_bpf_enabled();
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * Print BPF statistics
     */
    void print_stats() const {
        xdp_.print_bpf_stats();
    }

    /**
     * Get BPF statistics
     */
    BPFStats get_bpf_stats() const {
        return xdp_.get_bpf_stats();
    }

    // ========================================================================
    // Thread Control
    // ========================================================================

    /**
     * Stop RX trickle thread (call after handshake)
     */
    void stop_rx_trickle_thread() {
        xdp_.stop_rx_trickle_thread();
    }

    // ========================================================================
    // XSK State Accessors (for fork/inheritance)
    // ========================================================================

    struct xsk_socket* get_xsk() { return xdp_.get_xsk(); }
    struct xsk_umem* get_umem() { return xdp_.get_umem(); }
    void* get_umem_area() { return xdp_.get_umem_area(); }
    size_t get_umem_size() const { return xdp_.get_umem_size(); }
    struct xsk_ring_prod* get_fill_ring() { return xdp_.get_fill_ring(); }
    struct xsk_ring_cons* get_comp_ring() { return xdp_.get_comp_ring(); }
    struct xsk_ring_cons* get_rx_ring() { return xdp_.get_rx_ring(); }
    struct xsk_ring_prod* get_tx_ring() { return xdp_.get_tx_ring(); }
    uint32_t get_frame_size() const { return xdp_.get_frame_size(); }
    BPFLoader* get_bpf_loader() { return xdp_.get_bpf_loader(); }
    int get_fd() const { return xdp_.get_fd(); }

private:
    XDPTransport xdp_;
};

}  // namespace xdp
}  // namespace websocket

#else  // !USE_XDP

#include <stdexcept>

namespace websocket {
namespace xdp {

// Stub when XDP is not enabled
struct XDPPacketIOConfig {
    const char* interface = nullptr;
    const char* bpf_path = nullptr;
    bool zero_copy = true;
};

struct XDPPacketIO {
    using config_type = XDPPacketIOConfig;

    void init(const XDPPacketIOConfig&) {
        throw std::runtime_error("XDP support not compiled. Build with USE_XDP=1");
    }
    void close() {}
};

}  // namespace xdp
}  // namespace websocket

#endif  // USE_XDP
