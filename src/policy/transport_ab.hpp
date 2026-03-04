// policy/transport_ab.hpp
// Multi-Connection Wrapper for PacketTransport
//
// PacketTransportMulti wraps N PacketTransport instances that share
// a single PacketIO (one NIC RX queue, one XDP socket, one thread).
// The poll loop demuxes incoming packets by TCP destination port.
//
// Usage:
//   PacketTransportMulti<DisruptorPacketIO, 3> transport;
//   transport.init_with_pio_config(config);
//   transport.connect(0, host, port);  // Connect 0 (owns PIO)
//   transport.connect(1, host, port);  // Connect 1 (demuxed poll keeps 0 alive)
//   transport.connect(2, host, port);  // Connect 2
//
// conn[0] owns PIO, conn[1..N-1] share via pointer.

#pragma once

#include "transport.hpp"
#include <array>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <cstdio>
#include <arpa/inet.h>

namespace websocket {
namespace transport {

template<typename PacketIO, size_t MaxConn = 2>
struct PacketTransportMulti {
    static constexpr size_t NUM_CONN = MaxConn;
    std::array<PacketTransport<PacketIO>, MaxConn> conn;  // conn[0] owns PIO
    uint8_t active_conn_id = 0;

    // ========================================================================
    // Initialization
    // ========================================================================

    template<typename ConfigT>
    void init_with_pio_config(const ConfigT& config) {
        conn[0].init_with_pio_config(config);       // conn[0]: full init (PIO + stack)
        for (size_t i = 1; i < MaxConn; ++i) {
            conn[i].set_shared_pio(conn[0].get_packet_io());  // share conn[0]'s PIO
            conn[i].init_stack_only(config);                  // stack only (no PIO init)
        }

        // Override poll() on all connections so that any code calling
        // transport->poll() (e.g., SSL handshake) uses the demuxed poll
        // instead of the per-connection poll_rx_and_process() which would
        // drop other connections' packets.
        auto demux_poll = [](void* ctx) -> size_t {
            return static_cast<PacketTransportMulti*>(ctx)->poll();
        };
        for (size_t i = 0; i < MaxConn; ++i) {
            conn[i].set_poll_override(demux_poll, this);
        }
    }

    // ========================================================================
    // Demuxed Poll Loop
    // ========================================================================

    /**
     * Poll RX frames and demux to connections by TCP destination port.
     * Packet layout: ETH(14) + IP(20, IHL=5 enforced) + TCP(src:2, dst:2)
     * TCP dest port is at byte offset 36 (network byte order).
     */
    // Demux counters for diagnostics
    uint64_t demux_count_[MaxConn]{};
    uint64_t demux_dropped_ = 0;
    uint64_t demux_short_ = 0;
    uint64_t demux_log_cycle_ = 0;

    size_t poll() {
        conn[0].get_packet_io()->poll_wait();
        size_t n = conn[0].get_packet_io()->process_rx_frames(SIZE_MAX,
            [this](uint32_t idx, websocket::xdp::PacketFrameDescriptor& desc) {
                uint8_t* pkt = reinterpret_cast<uint8_t*>(desc.frame_ptr);
                uint16_t frame_len = desc.frame_len;

                // Need at least ETH(14) + IP(20) + TCP dest port(4) = 38 bytes
                if (frame_len < 38) {
                    uint32_t fi = conn[0].get_packet_io()->frame_ptr_to_idx(desc.frame_ptr);
                    conn[0].get_packet_io()->mark_frame_consumed(fi);
                    demux_short_++;
                    return;
                }

                // TCP dest port at offset 36 (ETH 14 + IP 20 + TCP src 2 = 36)
                uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(pkt + 36));

                // Demux to matching connection
                for (size_t i = 0; i < MaxConn; ++i) {
                    if (dst_port == conn[i].tcp_params().local_port) {
                        conn[i].process_rx_frame(idx, desc);
                        demux_count_[i]++;
                        return;
                    }
                }

                // No matching connection — drop
                uint32_t fi = conn[0].get_packet_io()->frame_ptr_to_idx(desc.frame_ptr);
                conn[0].get_packet_io()->mark_frame_consumed(fi);
                demux_dropped_++;
            });

        // Service retransmit queues for all connections
        for (size_t i = 0; i < MaxConn; ++i) {
            conn[i].check_retransmit();
        }

        // Periodic demux stats log (every ~10s)
        uint64_t now = rdtscp();
        if (demux_log_cycle_ == 0) demux_log_cycle_ = now;
        // Approximate 10s using ~3GHz TSC
        if (now - demux_log_cycle_ > 30000000000ULL) {
            fprintf(stderr, "[DEMUX-STATS]");
            for (size_t i = 0; i < MaxConn; ++i) {
                fprintf(stderr, " c%zu=%lu(port=%u)", i, demux_count_[i],
                        conn[i].tcp_params().local_port);
            }
            fprintf(stderr, " dropped=%lu short=%lu\n", demux_dropped_, demux_short_);
            demux_log_cycle_ = now;
        }

        return n;
    }

    // ========================================================================
    // Non-blocking Connect / Reconnect (for state-machine-based init)
    // ========================================================================

    void start_connect(uint8_t ci, const char* host, uint16_t port) {
        conn[ci].initiate_connect(host, port);
        fprintf(stderr, "[PacketTransportMulti] SYN sent for conn %u (local_port=%u)\n",
                ci, conn[ci].tcp_params().local_port);
    }

    void start_connect_ip(uint8_t ci, uint32_t ip_host_order, uint16_t port) {
        conn[ci].initiate_connect_ip(ip_host_order, port);
        fprintf(stderr, "[PacketTransportMulti] SYN sent for conn %u (local_port=%u, by IP)\n",
                ci, conn[ci].tcp_params().local_port);
    }

    void set_remote_ip(uint8_t ci, uint32_t ip_host_order) {
        conn[ci].set_remote_ip(ip_host_order);
    }

    int start_reconnect(uint8_t ci) {
        conn[ci].reset_for_reconnect();
        int rc = conn[ci].initiate_reconnect();
        if (rc != 0) {
            fprintf(stderr, "[PacketTransportMulti] Reconnect SYN failed for conn %u\n", ci);
            return rc;
        }
        fprintf(stderr, "[PacketTransportMulti] Reconnect SYN sent for conn %u (local_port=%u)\n",
                ci, conn[ci].tcp_params().local_port);
        return 0;
    }

    bool handshake_complete(uint8_t ci) const {
        return transport(ci).handshake_complete();
    }

    void set_connected(uint8_t ci) {
        transport(ci).set_connected();
    }

    // ========================================================================
    // Active Connection Routing
    // ========================================================================

    PacketTransport<PacketIO>& active_transport() {
        return conn[active_conn_id];
    }

    const PacketTransport<PacketIO>& active_transport() const {
        return conn[active_conn_id];
    }

    PacketTransport<PacketIO>& transport(uint8_t ci) {
        return conn[ci];
    }

    const PacketTransport<PacketIO>& transport(uint8_t ci) const {
        return conn[ci];
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
    PacketIO* get_packet_io() { return conn[0].get_packet_io(); }

    void set_conn_state(void* cs) {
        for (size_t i = 0; i < MaxConn; ++i) {
            conn[i].set_conn_state(cs);
        }
    }

    // ========================================================================
    // Close
    // ========================================================================

    void close(uint8_t ci) {
        conn[ci].close();
    }

    void close() {
        // Close in reverse order: conn[N-1] first (doesn't own PIO),
        // conn[0] last (owns PIO, calls pio().close())
        for (size_t i = MaxConn; i > 0; --i) {
            conn[i - 1].close();
        }
    }
};

// Backward compatibility alias
template<typename PIO>
using PacketTransportAB = PacketTransportMulti<PIO, 2>;

}  // namespace transport
}  // namespace websocket
