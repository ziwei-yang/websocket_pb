// policy/transport_ab.hpp
// Dual A/B Connection Wrapper for PacketTransport
//
// PacketTransportAB wraps two PacketTransport instances (A and B) that share
// a single PacketIO (one NIC RX queue, one XDP socket, one thread).
// The poll loop demuxes incoming packets by TCP destination port.
//
// Usage:
//   PacketTransportAB<DisruptorPacketIO> transport;
//   transport.init_with_pio_config(config);
//   transport.connect(0, host, port);  // Connect A
//   transport.connect(1, host, port);  // Connect B (demuxed poll keeps A alive)
//
// Both connections share one PIO: A owns it, B shares via pointer.

#pragma once

#include "transport.hpp"
#include <chrono>
#include <thread>
#include <stdexcept>
#include <cstdio>
#include <arpa/inet.h>

namespace websocket {
namespace transport {

template<typename PacketIO>
struct PacketTransportAB {
    PacketTransport<PacketIO> a;    // Connection A (owns real PIO)
    PacketTransport<PacketIO> b;    // Connection B (shares A's PIO)
    uint8_t active_conn_id = 0;    // 0=A, 1=B

    // ========================================================================
    // Initialization
    // ========================================================================

    template<typename ConfigT>
    void init_with_pio_config(const ConfigT& config) {
        a.init_with_pio_config(config);       // A: full init (PIO + stack)
        b.set_shared_pio(a.get_packet_io());  // B: share A's PIO
        b.init_stack_only(config);            // B: stack only (no PIO init)

        // Override poll() on both A and B so that any code calling
        // transport->poll() (e.g., SSL handshake) uses the demuxed poll
        // instead of the per-connection poll_rx_and_process() which would
        // drop the other connection's packets.
        auto demux_poll = [](void* ctx) -> size_t {
            return static_cast<PacketTransportAB*>(ctx)->poll();
        };
        a.set_poll_override(demux_poll, this);
        b.set_poll_override(demux_poll, this);
    }

    // ========================================================================
    // Demuxed Poll Loop
    // ========================================================================

    /**
     * Poll RX frames and demux to A or B by TCP destination port.
     * Packet layout: ETH(14) + IP(20, IHL=5 enforced) + TCP(src:2, dst:2)
     * TCP dest port is at byte offset 36 (network byte order).
     */
    size_t poll() {
        a.get_packet_io()->poll_wait();
        size_t n = a.get_packet_io()->process_rx_frames(SIZE_MAX,
            [this](uint32_t idx, websocket::xdp::PacketFrameDescriptor& desc) {
                uint8_t* pkt = reinterpret_cast<uint8_t*>(desc.frame_ptr);
                uint16_t frame_len = desc.frame_len;

                // Need at least ETH(14) + IP(20) + TCP dest port(4) = 38 bytes
                if (frame_len < 38) {
                    // Too short — drop
                    uint32_t fi = a.get_packet_io()->frame_ptr_to_idx(desc.frame_ptr);
                    a.get_packet_io()->mark_frame_consumed(fi);
                    return;
                }

                // TCP dest port at offset 36 (ETH 14 + IP 20 + TCP src 2 = 36)
                uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(pkt + 36));

                if (dst_port == a.tcp_params().local_port) {
                    a.process_rx_frame(idx, desc);
                } else if (dst_port == b.tcp_params().local_port) {
                    b.process_rx_frame(idx, desc);
                } else {
                    // Neither connection — drop
                    uint32_t fi = a.get_packet_io()->frame_ptr_to_idx(desc.frame_ptr);
                    a.get_packet_io()->mark_frame_consumed(fi);
                }
            });
        // Service retransmit queues for both connections
        a.check_retransmit();
        if (b.is_connected()) {
            b.check_retransmit();
        }
        return n;
    }

    // ========================================================================
    // Non-blocking Connect / Reconnect (for state-machine-based init)
    // ========================================================================

    /**
     * Non-blocking: initiate TCP connect for connection ci.
     * Sends SYN and returns immediately. Use handshake_complete(ci) to check.
     */
    void start_connect(uint8_t ci, const char* host, uint16_t port) {
        auto& c = (ci == 0) ? a : b;
        c.initiate_connect(host, port);
        fprintf(stderr, "[PacketTransportAB] SYN sent for conn %u (local_port=%u)\n",
                ci, c.tcp_params().local_port);
    }

    /**
     * Non-blocking: initiate TCP reconnect for connection ci.
     * Resets state, sends SYN using cached IP. Returns immediately.
     *
     * @return 0 on success, -1 on failure
     */
    int start_reconnect(uint8_t ci) {
        auto& c = (ci == 0) ? a : b;
        c.reset_for_reconnect();
        int rc = c.initiate_reconnect();
        if (rc != 0) {
            fprintf(stderr, "[PacketTransportAB] Reconnect SYN failed for conn %u\n", ci);
            return rc;
        }
        fprintf(stderr, "[PacketTransportAB] Reconnect SYN sent for conn %u (local_port=%u)\n",
                ci, c.tcp_params().local_port);
        return 0;
    }

    /**
     * Check if TCP handshake completed for connection ci.
     */
    bool handshake_complete(uint8_t ci) const {
        return transport(ci).handshake_complete();
    }

    /**
     * Mark connection ci as connected after TCP handshake.
     */
    void set_connected(uint8_t ci) {
        transport(ci).set_connected();
    }

    // ========================================================================
    // Active Connection Routing
    // ========================================================================

    PacketTransport<PacketIO>& active_transport() {
        return active_conn_id == 0 ? a : b;
    }

    const PacketTransport<PacketIO>& active_transport() const {
        return active_conn_id == 0 ? a : b;
    }

    PacketTransport<PacketIO>& transport(uint8_t ci) {
        return ci == 0 ? a : b;
    }

    const PacketTransport<PacketIO>& transport(uint8_t ci) const {
        return ci == 0 ? a : b;
    }

    void set_active(uint8_t ci) { active_conn_id = ci; }

    // ========================================================================
    // Delegated Methods (operate on active connection)
    // ========================================================================

    bool is_connected() const {
        return active_transport().is_connected();
    }

    ssize_t recv(void* buf, size_t len) {
        return active_transport().recv(buf, len);
    }

    ssize_t send(const void* buf, size_t len) {
        return active_transport().send(buf, len);
    }

    // ========================================================================
    // TLS accessors (delegate to active)
    // ========================================================================

    bool has_tls_record_keys() const {
        return active_transport().has_tls_record_keys();
    }

    bool tls_record_boundary() const {
        return active_transport().tls_record_boundary();
    }

    template<typename CB>
    int ssl_read_by_chunk(uint8_t* d, size_t sz, CB&& cb) {
        return active_transport().ssl_read_by_chunk(d, sz, std::forward<CB>(cb));
    }

    void set_tls_record_keys(const crypto::TLSRecordKeys& keys) {
        active_transport().set_tls_record_keys(keys);
    }

    // ========================================================================
    // Transport accessors
    // ========================================================================

    void* get_transport_ptr() { return active_transport().get_transport_ptr(); }
    bool supports_ktls() const { return false; }
    PacketIO* get_packet_io() { return a.get_packet_io(); }

    void set_conn_state(void* cs) {
        a.set_conn_state(cs);
        b.set_conn_state(cs);
    }

    // ========================================================================
    // Close
    // ========================================================================

    void close(uint8_t ci) {
        transport(ci).close();
    }

    void close() {
        b.close();  // B first (doesn't own PIO, skips pio().close())
        a.close();  // A last (owns PIO, calls pio().close())
    }
};

}  // namespace transport
}  // namespace websocket
