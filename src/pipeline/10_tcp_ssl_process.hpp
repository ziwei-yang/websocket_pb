// pipeline/10_tcp_ssl_process.hpp
// Transport Process - Protocol-agnostic TCP + SSL using DisruptorPacketIO
//
// Uses PacketTransport<DisruptorPacketIO> to delegate packet I/O to XDP Poll
// process via IPC Disruptor Rings. This decouples the TCP/SSL stack from
// the XDP kernel interface, allowing them to run on separate CPU cores.
//
// Transport is protocol-agnostic: it handles TCP + optional TLS only.
// SSL behavior is fully determined by the SSLPolicy template argument
// (OpenSSLPolicy, WolfSSLPolicy, NoSSLPolicy), not by the URL scheme.
// All application-layer protocols (HTTP, WebSocket) are handled by
// upstream callers or downstream processes.
//
// URL schemes (tcp://, http://, https://, ws://, wss://) are parsed
// for host/port/path extraction only.
//
// Architecture:
//   XDP Poll Process (Core 2)          Transport Process (Core 4)
//   +--------------------+             +-------------------------+
//   |  00_xdp_poll_*.hpp |             |  10_tcp_ssl_process.hpp |
//   |                    |             |                         |
//   |  XDP -> RAW_INBOX --+-------------+--> DisruptorPacketIO   |
//   |                    |             |       |                 |
//   |  XDP <- RAW_OUTBOX <+-------------+--- PacketTransport     |
//   |                    |             |       |                 |
//   +--------------------+             |     TCP + SSL           |
//           |                          |       |                 |
//           +--- Shared UMEM ----------+   MSG_INBOX + METADATA  |
//                                      +-------------------------+
//
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <vector>
#include <string>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <csignal>

// Pipeline data structures
#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"
#include "disruptor_packet_io.hpp"

#include "../policy/transport.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

using namespace websocket::transport;

// ============================================================================
// URL Parsing
// ============================================================================

struct ParsedURL {
    std::string host;           // e.g., "stream.binance.com"
    uint16_t port = 443;        // e.g., 443
    std::string path;           // e.g., "/ws"
    bool valid = false;
};

inline ParsedURL parse_url(const char* url) {
    ParsedURL result;
    std::string s(url);

    if (s.rfind("wss://", 0) == 0) {
        result.port = 443; s = s.substr(6);
    } else if (s.rfind("ws://", 0) == 0) {
        result.port = 80; s = s.substr(5);
    } else if (s.rfind("https://", 0) == 0) {
        result.port = 443; s = s.substr(8);
    } else if (s.rfind("http://", 0) == 0) {
        result.port = 80; s = s.substr(7);
    } else if (s.rfind("tcp://", 0) == 0) {
        result.port = 0; s = s.substr(6);
    } else {
        return result;  // Invalid scheme
    }

    // Find path start
    size_t path_pos = s.find('/');
    std::string host_port;
    if (path_pos != std::string::npos) {
        host_port = s.substr(0, path_pos);
        result.path = s.substr(path_pos);
    } else {
        host_port = s;
        result.path = "/";
    }

    // Parse host:port
    size_t colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
        result.host = host_port.substr(0, colon_pos);
        result.port = static_cast<uint16_t>(std::stoi(host_port.substr(colon_pos + 1)));
    } else {
        result.host = host_port;
    }

    result.valid = !result.host.empty();
    return result;
}

// ============================================================================
// TransportProcess - Protocol-agnostic TCP + SSL using DisruptorPacketIO
//
// Template Parameters:
//   - SSLPolicy: SSL/TLS implementation (OpenSSLPolicy, WolfSSLPolicy, NoSSLPolicy)
//                SSL behavior is fully determined by this template argument.
//                NoSSLPolicy methods are safe no-ops / pass-through delegates.
//   - MsgMetadataProd: IPCRingProducer<MsgMetadata> for publishing metadata
//   - PongsCons: IPCRingConsumer<PongFrameAligned> for PONG responses to send
//   - Profiling: Enable profiling counters
//
// This process runs on a single core and handles:
//   1. Consuming RX packets from RAW_INBOX (via DisruptorPacketIO)
//   2. Userspace TCP connection
//   3. SSL/TLS handshake (via SSLPolicy; no-op for NoSSLPolicy)
//   4. SSL/raw read -> MSG_INBOX
//   5. Publishing MsgMetadata to downstream process
//   6. Consuming PONGs from WS process and sending via SSL/raw
//   7. Consuming MSG_OUTBOX events and sending via SSL/raw (optional)
//   8. Producing TX packets to RAW_OUTBOX (via DisruptorPacketIO)
// ============================================================================

template<typename SSLPolicy,
         typename MsgMetadataProd,
         typename PongsCons,
         bool Profiling = false>
struct TransportProcess {
public:
    // Type aliases for IPC rings
    using RawInboxCons = IPCRingConsumer<websocket::xdp::PacketFrameDescriptor>;
    using RawOutboxProd = IPCRingProducer<websocket::xdp::PacketFrameDescriptor>;
    using MsgOutboxCons = IPCRingConsumer<MsgOutboxEvent>;

    // ========================================================================
    // Initialization
    // ========================================================================

    TransportProcess(const char* url,
                     void* umem_area,
                     uint32_t frame_size,
                     RawInboxCons* raw_inbox_cons,
                     RawOutboxProd* raw_outbox_prod,
                     MsgInbox* msg_inbox,
                     MsgMetadataProd* msg_metadata_prod,
                     PongsCons* pongs_cons,
                     ConnStateShm* conn_state,
                     MsgOutboxCons* msg_outbox_cons = nullptr)
        : url_(url)
        , umem_area_(umem_area)
        , frame_size_(frame_size)
        , raw_inbox_cons_(raw_inbox_cons)
        , raw_outbox_prod_(raw_outbox_prod)
        , msg_inbox_(msg_inbox)
        , msg_metadata_prod_(msg_metadata_prod)
        , pongs_cons_(pongs_cons)
        , conn_state_(conn_state)
        , msg_outbox_cons_(msg_outbox_cons) {

        parsed_url_ = parse_url(url);
    }

    void set_profiling_data(CycleSampleBuffer* data) {
        profiling_data_ = data;
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    bool init() {
        printf("[TRANSPORT] Initializing Transport Process\n");
        printf("[TRANSPORT] URL: %s\n", url_);

        if (!parsed_url_.valid) {
            fprintf(stderr, "[TRANSPORT] Invalid URL: %s\n", url_);
            return false;
        }

        printf("[TRANSPORT] Host: %s, Port: %u, Path: %s\n",
               parsed_url_.host.c_str(), parsed_url_.port, parsed_url_.path.c_str());

        // Calibrate TSC
        printf("[TRANSPORT] Calibrating TSC...\n");
        tsc_freq_hz_ = calibrate_tsc_freq();
        printf("[TRANSPORT] TSC frequency: %.2f GHz\n", tsc_freq_hz_ / 1e9);

        if (conn_state_) {
            conn_state_->tsc_freq_hz = tsc_freq_hz_;
        }

        // Wait for XDP Poll to be ready
        printf("[TRANSPORT] Waiting for XDP Poll to be ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {  // 10 second timeout
            fprintf(stderr, "[TRANSPORT] Timeout waiting for XDP Poll ready\n");
            return false;
        }
        printf("[TRANSPORT] XDP Poll ready\n");

        // Phase 1: Configure DisruptorPacketIO
        printf("[TRANSPORT] Phase 1: DisruptorPacketIO Init\n");
        DisruptorPacketIOConfig pio_config;
        pio_config.umem_area = umem_area_;
        pio_config.frame_size = frame_size_;
        pio_config.raw_inbox_cons = raw_inbox_cons_;
        pio_config.raw_outbox_prod = raw_outbox_prod_;
        pio_config.conn_state = conn_state_;

        transport_.init_with_pio_config(pio_config);

        // Resolve hostname
        auto ips = resolve_hostname(parsed_url_.host.c_str());
        if (ips.empty()) {
            fprintf(stderr, "[TRANSPORT] Failed to resolve %s\n", parsed_url_.host.c_str());
            return false;
        }

        printf("[TRANSPORT] Resolved %zu IP(s): ", ips.size());
        for (size_t i = 0; i < ips.size(); i++) {
            printf("%s%s", ips[i].c_str(), (i < ips.size() - 1) ? ", " : "\n");
        }

        // Phase 2: TCP Connection
        printf("[TRANSPORT] Phase 2: TCP Connect to %s:%u\n",
               parsed_url_.host.c_str(), parsed_url_.port);
        transport_.connect(parsed_url_.host.c_str(), parsed_url_.port);

        // Phase 3: SSL/TLS Handshake (via SSLPolicy; no-op for NoSSLPolicy)
        printf("[TRANSPORT] Phase 3: SSL/TLS Handshake\n");
        ssl_.init();
        ssl_.handshake_userspace_transport(&transport_, parsed_url_.host.c_str());
        printf("[TRANSPORT] SSL handshake complete\n");

        // Signal TLS ready for downstream process
        if (conn_state_) {
            conn_state_->set_handshake_tls_ready();
        }

        // Reset stats before message streaming
        transport_.reset_hw_timestamps();
        transport_.reset_recv_stats();

        return true;
    }

    void run() {
        printf("[TRANSPORT] Phase 4: Message Streaming\n");

        running_ = true;

        // Timing record for latency breakdown
        timing_record_t timing;
        memset(&timing, 0, sizeof(timing));

        while (running_ && check_running()) {
            // Stage 2: Event loop start
            timing.event_cycle = rdtsc();

            // 1. Poll transport (handles TX completions, etc.)
            transport_.poll();

            // 2. Process MSG_OUTBOX (optional outbound message processing)
            if (msg_outbox_cons_) process_msg_outbox();

            // 3. SSL/raw read -> MSG_INBOX
            // Calculate linear space available in circular buffer
            uint32_t write_pos = msg_inbox_->current_write_pos();
            uint32_t linear_space = MSG_INBOX_SIZE - write_pos;
            if (linear_space > 16384) linear_space = 16384;  // Limit read size

            timing.recv_start_cycle = rdtsc();
            ssize_t read_len = ssl_.read(msg_inbox_->write_ptr(), linear_space);
            timing.recv_end_cycle = rdtscp();

            if (read_len > 0) {
                // Capture HW timestamps before advancing write pointer
                timing.hw_timestamp_count = transport_.get_recv_packet_count();
                if (timing.hw_timestamp_count > 0) {
                    timing.hw_timestamp_oldest_ns = transport_.get_recv_oldest_timestamp();
                    timing.hw_timestamp_latest_ns = transport_.get_recv_latest_timestamp();
                } else {
                    timing.hw_timestamp_oldest_ns = 0;
                    timing.hw_timestamp_latest_ns = 0;
                }

                uint32_t write_offset = msg_inbox_->current_write_pos();
                msg_inbox_->advance_write(static_cast<uint32_t>(read_len));

                // 5. Publish MsgMetadata
                publish_metadata(write_offset, static_cast<uint32_t>(read_len), timing);

                // 6. Print timing breakdown (if Profiling)
                if constexpr (Profiling) {
                    print_timing_breakdown(static_cast<uint32_t>(read_len), timing);
                }

                // Reset timestamps for next batch
                transport_.reset_recv_stats();

                ssl_read_count_++;

            } else if (read_len < 0 && errno != EAGAIN) {
                fprintf(stderr, "[TRANSPORT] Read error: %s\n", strerror(errno));
                break;
            }

            // 4. Process PONGs (consume from PONGS ring, encrypt, send)
            process_pongs();
            // Pure busy-poll for lowest latency
        }

        printf("[TRANSPORT] Streaming ended. Reads: %lu, PONGs sent: %lu\n",
               ssl_read_count_, pong_count_);
    }

    void cleanup() {
        printf("[TRANSPORT] Cleanup\n");
        ssl_.shutdown();
        transport_.close();
    }

    void stop() {
        running_ = false;
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    uint64_t ssl_read_count() const { return ssl_read_count_; }
    uint64_t pong_count() const { return pong_count_; }

private:
    // ========================================================================
    // Hostname Resolution
    // ========================================================================

    std::vector<std::string> resolve_hostname(const char* hostname) {
        std::vector<std::string> ips;

        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(hostname, nullptr, &hints, &result);
        if (ret != 0 || !result) {
            if (result) freeaddrinfo(result);
            return ips;
        }

        for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                auto* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                ips.push_back(ip_str);
            }
        }

        freeaddrinfo(result);
        return ips;
    }

    // ========================================================================
    // MsgMetadata Publishing
    // ========================================================================

    void publish_metadata(uint32_t write_offset, uint32_t len, timing_record_t& timing) {
        int64_t seq = msg_metadata_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: MSG_METADATA full\n");
            abort();
        }

        auto& meta = (*msg_metadata_prod_)[seq];
        meta.first_nic_timestamp_ns = timing.hw_timestamp_oldest_ns;
        meta.first_nic_frame_poll_cycle = timing.recv_start_cycle;
        meta.latest_nic_timestamp_ns = timing.hw_timestamp_latest_ns;
        meta.latest_nic_frame_poll_cycle = timing.recv_end_cycle;
        meta.latest_raw_frame_poll_cycle = timing.recv_end_cycle;
        meta.ssl_read_cycle = timing.recv_end_cycle;
        meta.msg_inbox_offset = write_offset;
        meta.decrypted_len = len;
        meta.nic_packet_ct = timing.hw_timestamp_count;
        msg_metadata_prod_->publish(seq);
    }

    // ========================================================================
    // PONG Processing
    // ========================================================================

    void process_pongs() {
        PongFrameAligned pong;
        while (pongs_cons_->try_consume(pong)) {
            if (pong.data_len == 0) continue;

            // Send PONG via SSL
            size_t total_sent = 0;
            while (total_sent < pong.data_len) {
                transport_.poll();
                ssize_t sent = ssl_.write(pong.data + total_sent, pong.data_len - total_sent);
                if (sent > 0) {
                    total_sent += sent;
                } else if (sent < 0 && errno != EAGAIN) {
                    fprintf(stderr, "[TRANSPORT] PONG send error: %s\n", strerror(errno));
                    break;
                }
                usleep(100);
            }

            pong_count_++;
            fprintf(stderr, "[PONG-TX] Sent PONG #%lu (%u bytes)\n", pong_count_, pong.data_len);
        }
    }

    // ========================================================================
    // MSG_OUTBOX Processing (optional outbound messages)
    // ========================================================================

    void process_msg_outbox() {
        MsgOutboxEvent evt;
        while (msg_outbox_cons_->try_consume(evt)) {
            if (evt.data_len == 0) continue;

            size_t total_sent = 0;
            while (total_sent < evt.data_len) {
                transport_.poll();
                ssize_t sent = ssl_.write(evt.data + total_sent, evt.data_len - total_sent);
                if (sent > 0) {
                    total_sent += sent;
                } else if (sent < 0 && errno != EAGAIN) {
                    fprintf(stderr, "[TRANSPORT] MSG_OUTBOX send error: %s\n", strerror(errno));
                    break;
                }
                usleep(100);
            }
        }
    }

    // ========================================================================
    // Timing Breakdown
    // ========================================================================

    void print_timing_breakdown(uint32_t len, timing_record_t& timing) {
        uint64_t callback_cycle = rdtscp();

        printf("\n[SSL_READ #%lu] decrypted_len=%u\n", ssl_read_count_ + 1, len);
        printf("  Latency Breakdown:\n");

        // Stage 1: Hardware timestamp from NIC
        if (timing.hw_timestamp_latest_ns > 0) {
            struct timespec ts_real, ts_mono;
            clock_gettime(CLOCK_REALTIME, &ts_real);
            clock_gettime(CLOCK_MONOTONIC, &ts_mono);
            uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
            uint64_t monotonic_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;

            int64_t hw_ts_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                    (int64_t)realtime_now_ns + (int64_t)monotonic_now_ns;
            printf("    [Stage 1] NIC HW timestamp: %.6f s (MONOTONIC)\n",
                   hw_ts_mono_ns / 1e9);

            uint64_t stage2_to_6_ns = cycles_to_ns(callback_cycle - timing.event_cycle, tsc_freq_hz_);
            int64_t stage2_mono_ns = (int64_t)monotonic_now_ns - (int64_t)stage2_to_6_ns;
            int64_t stage1_to_2_ns = stage2_mono_ns - hw_ts_mono_ns;
            printf("    [Stage 1->2] NIC->Event: %.3f us\n", stage1_to_2_ns / 1000.0);
        }

        if (timing.recv_start_cycle > timing.event_cycle) {
            printf("    [Stage 2->3] Event->Recv: %.3f us\n",
                   cycles_to_ns(timing.recv_start_cycle - timing.event_cycle, tsc_freq_hz_) / 1000.0);
        }

        if (timing.recv_end_cycle > timing.recv_start_cycle) {
            printf("    [Stage 3->4] SSL decrypt: %.3f us\n",
                   cycles_to_ns(timing.recv_end_cycle - timing.recv_start_cycle, tsc_freq_hz_) / 1000.0);
        }

        if (callback_cycle > timing.event_cycle) {
            printf("    [Total] Event->Callback: %.3f us\n",
                   cycles_to_ns(callback_cycle - timing.event_cycle, tsc_freq_hz_) / 1000.0);
        }
    }

    // ========================================================================
    // Running Check
    // ========================================================================

    bool check_running() const {
        if (conn_state_) {
            return conn_state_->is_running(PROC_TRANSPORT);
        }
        return true;
    }

    // ========================================================================
    // Member Variables
    // ========================================================================

    // Configuration
    const char* url_;
    void* umem_area_;
    uint32_t frame_size_;
    ParsedURL parsed_url_;

    // IPC ring pointers
    RawInboxCons* raw_inbox_cons_ = nullptr;
    RawOutboxProd* raw_outbox_prod_ = nullptr;

    // IPC interfaces
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;

    // Transport and SSL
    PacketTransport<DisruptorPacketIO> transport_;
    SSLPolicy ssl_;

    // Timing
    uint64_t tsc_freq_hz_ = 0;

    // Profiling (optional)
    CycleSampleBuffer* profiling_data_ = nullptr;

    // State
    std::atomic<bool> running_{false};

    // Counters
    uint64_t ssl_read_count_ = 0;
    uint64_t pong_count_ = 0;
};

}  // namespace websocket::pipeline
