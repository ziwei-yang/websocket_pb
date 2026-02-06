// pipeline/98_xdp_tcp_ssl_process.hpp
// Unified XDP + TCP + SSL Single-Process Pipeline (WITHOUT WebSocket)
//
// Combines XDP transport, TCP stack, and SSL in a single process.
// Outputs to MSG_INBOX + MSG_METADATA rings for downstream WebSocket parsing.
//
// Data Flow:
//   NIC -> XDP -> Userspace TCP -> SSL decrypt -> MSG_INBOX
//                                                    |
//                                   Publish MSG_METADATA -> 20_ws_process.hpp
//
// Key differences from 99_xdp_tcp_ssl_ws_process.hpp:
//   - No WebSocket frame parsing (delegated to 20_ws_process.hpp)
//   - Outputs MsgMetadata instead of WSFrameInfo
//   - Consumes PONGs ring (receives pre-built PONG frames from WS process)
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

// Pipeline data structures (must be included BEFORE pipeline_config.hpp)
#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"

#include "../policy/transport.hpp"
#include "../xdp/xdp_packet_io.hpp"
#include "../core/http.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

using namespace websocket::transport;
using namespace websocket::http;

// ============================================================================
// URL Parsing (shared with 99_*)
// ============================================================================

struct ParsedURL98 {
    std::string host;       // e.g., "stream.binance.com"
    uint16_t port = 443;    // e.g., 443
    std::string path;       // e.g., "/ws"
    bool is_wss = true;     // true for wss://, false for ws://

    bool valid = false;
};

inline ParsedURL98 parse_url_98(const char* url) {
    ParsedURL98 result;
    std::string url_str(url);

    // Check scheme
    if (url_str.rfind("wss://", 0) == 0) {
        result.is_wss = true;
        result.port = 443;
        url_str = url_str.substr(6);
    } else if (url_str.rfind("ws://", 0) == 0) {
        result.is_wss = false;
        result.port = 80;
        url_str = url_str.substr(5);
    } else {
        return result;  // Invalid scheme
    }

    // Find path start
    size_t path_pos = url_str.find('/');
    std::string host_port;
    if (path_pos != std::string::npos) {
        host_port = url_str.substr(0, path_pos);
        result.path = url_str.substr(path_pos);
    } else {
        host_port = url_str;
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
// UnifiedXDPSSLProcess - Single-process XDP + TCP + SSL (without WebSocket)
//
// Template Parameters:
//   - SSLPolicy: SSL/TLS implementation (OpenSSLPolicy, WolfSSLPolicy)
//   - MsgMetadataProd: IPCRingProducer<MsgMetadata> for publishing metadata
//   - PongsCons: IPCRingConsumer<PongFrameAligned> for PONG responses to send
//   - Profiling: Enable profiling counters
//
// This process runs on a single core and handles:
//   1. XDP transport initialization
//   2. Userspace TCP connection
//   3. SSL/TLS handshake
//   4. HTTP WebSocket upgrade
//   5. SSL read -> MSG_INBOX
//   6. Publishing MsgMetadata to downstream WS process
//   7. Consuming PONGs from WS process and sending via SSL
// ============================================================================

template<typename SSLPolicy,
         typename MsgMetadataProd,
         typename PongsCons,
         bool Profiling = false>
struct UnifiedXDPSSLProcess {
public:
    // ========================================================================
    // Initialization
    // ========================================================================

    UnifiedXDPSSLProcess(const char* interface,
                         const char* bpf_path,
                         const char* url,
                         MsgInbox* msg_inbox,
                         MsgMetadataProd* msg_metadata_prod,
                         PongsCons* pongs_cons,
                         ConnStateShm* conn_state)
        : interface_(interface)
        , bpf_path_(bpf_path)
        , url_(url)
        , msg_inbox_(msg_inbox)
        , msg_metadata_prod_(msg_metadata_prod)
        , pongs_cons_(pongs_cons)
        , conn_state_(conn_state) {

        parsed_url_ = parse_url_98(url);
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    bool init() {
        printf("[UNIFIED-SSL] Initializing XDP + TCP + SSL\n");
        printf("[UNIFIED-SSL] URL: %s\n", url_);
        printf("[UNIFIED-SSL] Interface: %s\n", interface_);

        if (!parsed_url_.valid) {
            fprintf(stderr, "[UNIFIED-SSL] Invalid URL: %s\n", url_);
            return false;
        }

        printf("[UNIFIED-SSL] Host: %s, Port: %u, Path: %s\n",
               parsed_url_.host.c_str(), parsed_url_.port, parsed_url_.path.c_str());

        // Calibrate TSC
        printf("[UNIFIED-SSL] Calibrating TSC...\n");
        tsc_freq_hz_ = calibrate_tsc_freq();
        printf("[UNIFIED-SSL] TSC frequency: %.2f GHz\n", tsc_freq_hz_ / 1e9);

        if (conn_state_) {
            conn_state_->tsc_freq_hz = tsc_freq_hz_;
        }

        // Phase 1: XDP + Userspace TCP Initialization
        printf("[UNIFIED-SSL] Phase 1: XDP Transport Init\n");
        transport_.init(interface_, bpf_path_);

        // Resolve and configure BPF filter
        auto ips = resolve_hostname(parsed_url_.host.c_str());
        if (ips.empty()) {
            fprintf(stderr, "[UNIFIED-SSL] Failed to resolve %s\n", parsed_url_.host.c_str());
            return false;
        }

        printf("[UNIFIED-SSL] Resolved %zu IP(s): ", ips.size());
        for (size_t i = 0; i < ips.size(); i++) {
            printf("%s%s", ips[i].c_str(), (i < ips.size() - 1) ? ", " : "\n");
            transport_.add_exchange_ip(ips[i].c_str());
        }
        transport_.add_exchange_port(parsed_url_.port);

        printf("[UNIFIED-SSL] XDP Mode: %s\n", transport_.get_xdp_mode());
        printf("[UNIFIED-SSL] BPF Filter: %s\n", transport_.is_bpf_enabled() ? "ENABLED" : "DISABLED");

        // Phase 2: TCP Connection
        printf("[UNIFIED-SSL] Phase 2: TCP Connect to %s:%u\n",
               parsed_url_.host.c_str(), parsed_url_.port);
        transport_.connect(parsed_url_.host.c_str(), parsed_url_.port);

        // Phase 3: SSL/TLS Handshake
        printf("[UNIFIED-SSL] Phase 3: SSL/TLS Handshake\n");
        ssl_.init();
        ssl_.handshake_userspace_transport(&transport_);
        printf("[UNIFIED-SSL] SSL handshake complete\n");

        // Signal TLS ready for downstream WS process
        if (conn_state_) {
            conn_state_->set_handshake_tls_ready();
        }

        // Phase 4: HTTP WebSocket Upgrade
        printf("[UNIFIED-SSL] Phase 4: HTTP WebSocket Upgrade\n");
        if (!perform_ws_upgrade()) {
            fprintf(stderr, "[UNIFIED-SSL] WebSocket upgrade failed\n");
            return false;
        }
        printf("[UNIFIED-SSL] WebSocket upgrade complete\n");

        // Extract TLS record keys for direct AES-CTR decryption
        websocket::crypto::TLSRecordKeys tls_keys;
        if (ssl_.extract_record_keys(tls_keys)) {
            transport_.set_tls_record_keys(tls_keys);
            if (tls_keys.is_tls13) {
                transport_.set_tls_seq_num(ssl_.get_server_record_count());
            }
            printf("[UNIFIED-SSL] Direct AES-CTR decryption enabled (seq=%lu)\n",
                   tls_keys.is_tls13 ? ssl_.get_server_record_count() : 0UL);
        }

        // Reset stats before message streaming
        transport_.reset_hw_timestamps();
        transport_.reset_recv_stats();

        return true;
    }

    void run() {
        printf("[UNIFIED-SSL] Phase 5: SSL Message Streaming\n");

        // Mark WS ready (this process handles the upgrade)
        if (conn_state_) {
            conn_state_->set_handshake_ws_ready();
        }

        running_ = true;

        // Timing record for latency breakdown
        timing_record_t timing;
        memset(&timing, 0, sizeof(timing));

        while (running_ && check_running()) {
            // 1. Poll transport (handles TX completions, etc.)
            transport_.poll();

            // 2. Process PONGs (consume from PONGS ring, encrypt, send)
            process_pongs();

            // 3. SSL read -> MSG_INBOX
            // Calculate linear space available in circular buffer
            uint32_t write_pos = msg_inbox_->current_write_pos();
            uint32_t linear_space = MSG_INBOX_SIZE - write_pos;
            if (linear_space > 16384) linear_space = 16384;  // Limit read size

            timing.recv_start_cycle = rdtsc();
            ssize_t read_len;
            if (transport_.has_tls_record_keys()) {
                read_len = transport_.ssl_read_by_chunk(
                    msg_inbox_->write_ptr(), linear_space,
                    [](const uint8_t*, size_t) {});
                if (read_len == -1) read_len = 0;
            } else {
                read_len = ssl_.read(msg_inbox_->write_ptr(), linear_space);
            }
            timing.recv_end_cycle = rdtscp();

            if (read_len > 0) {
                // Capture timestamps from transport before advancing write pointer
                timing.hw_timestamp_count = transport_.get_recv_packet_count();
                if (timing.hw_timestamp_count > 0) {
                    timing.hw_timestamp_oldest_ns = transport_.get_recv_oldest_timestamp();
                    timing.hw_timestamp_latest_ns = transport_.get_recv_latest_timestamp();
                    // New packets arrived — these are valid SSL timestamps
                    last_valid_ssl_start_cycle_ = timing.recv_start_cycle;
                    last_valid_ssl_end_cycle_ = timing.recv_end_cycle;
                } else {
                    timing.hw_timestamp_oldest_ns = 0;
                    timing.hw_timestamp_latest_ns = 0;
                    // packets==0: SSL returned from internal buffer, reuse last valid timestamps
                }
                timing.bpf_entry_oldest_ns = transport_.get_recv_oldest_bpf_entry_ns();
                timing.bpf_entry_latest_ns = transport_.get_recv_latest_bpf_entry_ns();
                timing.poll_cycle_oldest = transport_.get_recv_oldest_poll_cycle();
                timing.poll_cycle_latest = transport_.get_recv_latest_poll_cycle();
                timing.oldest_pkt_mem_idx = transport_.get_recv_oldest_pkt_mem_idx();
                timing.latest_pkt_mem_idx = transport_.get_recv_latest_pkt_mem_idx();

                uint32_t write_offset = msg_inbox_->current_write_pos();
                msg_inbox_->advance_write(static_cast<uint32_t>(read_len));

                // 4. Publish MsgMetadata
                bool tls_boundary = transport_.has_tls_record_keys()
                                    ? transport_.tls_record_boundary() : false;
                publish_metadata(write_offset, static_cast<uint32_t>(read_len), timing, tls_boundary);

                // 5. Print timing breakdown (if Profiling and DEBUG)
#if DEBUG
                if constexpr (Profiling) {
                    print_timing_breakdown(static_cast<uint32_t>(read_len), timing);
                }
#endif

                // Reset timestamps for next batch
                transport_.reset_recv_stats();

                ssl_read_count_++;

            } else if (read_len < 0) {
                if (!transport_.has_tls_record_keys() && errno != EAGAIN) {
                    fprintf(stderr, "[UNIFIED-SSL] SSL read error: %s\n", strerror(errno));
                    break;
                }
            }

            // Pure busy-poll for lowest latency
        }

        printf("[UNIFIED-SSL] Streaming ended. SSL reads: %lu, PONGs sent: %lu\n",
               ssl_read_count_, pong_count_);
    }

    void cleanup() {
        printf("[UNIFIED-SSL] Cleanup\n");
        ssl_.shutdown();
        transport_.close();
        transport_.print_bpf_stats();
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
    // WebSocket Upgrade
    // ========================================================================

    bool perform_ws_upgrade() {
        // Build upgrade request
        std::vector<std::pair<std::string, std::string>> headers;
        char upgrade_req[2048];
        size_t req_len = build_websocket_upgrade_request(
            parsed_url_.host.c_str(), parsed_url_.path.c_str(),
            headers, upgrade_req, sizeof(upgrade_req)
        );

        printf("[UNIFIED-SSL] Sending HTTP upgrade request (%zu bytes)\n", req_len);

        // Send upgrade request
        size_t total_sent = 0;
        while (total_sent < req_len) {
            transport_.poll();
            ssize_t sent = ssl_.write(upgrade_req + total_sent, req_len - total_sent);
            if (sent > 0) {
                total_sent += sent;
            } else if (sent < 0 && errno != EAGAIN) {
                fprintf(stderr, "[UNIFIED-SSL] Failed to send upgrade request\n");
                return false;
            }
            usleep(1000);
        }

        // Receive upgrade response
        printf("[UNIFIED-SSL] Waiting for HTTP 101 response...\n");
        uint8_t response_buf[4096];
        bool response_validated = false;
        int poll_attempts = 0;
        int max_attempts = 1000;

        while (poll_attempts < max_attempts && !response_validated) {
            transport_.poll();
            ssize_t received = ssl_.read(response_buf, sizeof(response_buf));

            if (received > 0) {
                if (validate_http_upgrade_response(response_buf, received)) {
                    printf("[UNIFIED-SSL] HTTP 101 Switching Protocols validated\n");
                    response_validated = true;
                    break;
                }
            } else if (received < 0 && errno != EAGAIN) {
                fprintf(stderr, "[UNIFIED-SSL] SSL read error during upgrade\n");
                return false;
            }

            usleep(1000);
            poll_attempts++;
        }

        return response_validated;
    }

    // ========================================================================
    // MsgMetadata Publishing
    // ========================================================================

    void publish_metadata(uint32_t write_offset, uint32_t len,
                          timing_record_t& timing, bool tls_record_end) {
        int64_t seq = msg_metadata_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[UNIFIED-SSL] FATAL: MSG_METADATA full\n");
            abort();
        }

        auto& meta = (*msg_metadata_prod_)[seq];
        meta.first_nic_timestamp_ns = timing.hw_timestamp_oldest_ns;
        meta.latest_nic_timestamp_ns = timing.hw_timestamp_latest_ns;
        meta.first_bpf_entry_ns = timing.bpf_entry_oldest_ns;
        meta.latest_bpf_entry_ns = timing.bpf_entry_latest_ns;
        meta.first_nic_frame_poll_cycle = timing.poll_cycle_oldest;
        meta.latest_nic_frame_poll_cycle = timing.poll_cycle_latest;
        meta.ssl_read_start_cycle = last_valid_ssl_start_cycle_;
        meta.ssl_read_end_cycle = last_valid_ssl_end_cycle_;
        meta.ssl_read_id = ssl_read_count_;
        meta.msg_inbox_offset = write_offset;
        meta.decrypted_len = len;
        meta.nic_packet_ct = timing.hw_timestamp_count;
        meta.ssl_last_op_cycle = last_op_cycle_;
        meta.tls_record_end = tls_record_end;
        meta.first_pkt_mem_idx = timing.oldest_pkt_mem_idx;
        meta.last_pkt_mem_idx = timing.latest_pkt_mem_idx;
        msg_metadata_prod_->publish(seq);
        last_op_cycle_ = rdtscp();
    }

    // ========================================================================
    // PONG Processing (from 10_tcp_ssl_process.hpp pattern)
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
                    fprintf(stderr, "[UNIFIED-SSL] PONG send error: %s\n", strerror(errno));
                    break;
                }
                usleep(100);
            }

            pong_count_++;
        }
    }

    // ========================================================================
    // Timing Breakdown (from xdp_binance.cpp)
    // ========================================================================

    void print_timing_breakdown(uint32_t len, timing_record_t& timing) {
        uint64_t callback_cycle = rdtscp();
        struct timespec ts_mono, ts_real;
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        clock_gettime(CLOCK_REALTIME, &ts_real);
        uint64_t mono_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;
        uint64_t real_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;

        // Header line
        fprintf(stderr, "[%ld.%06ld] [SSL_READ #%lu] packets=%u decrypted_len=%u\n",
                ts_mono.tv_sec, ts_mono.tv_nsec / 1000, ssl_read_count_ + 1,
                timing.hw_timestamp_count, len);

        // Helper lambda to format a NIC/BPF/poll line
        auto print_packet_line = [&](const char* label,
                                     uint64_t nic_ns, uint64_t bpf_ns, uint64_t poll_cycle) {
            // NIC ~ (CLOCK_REALTIME, unreliable in XDP mode)
            char nic_str[32];
            if (nic_ns > 0 && real_now_ns > nic_ns) {
                snprintf(nic_str, sizeof(nic_str), "~ %.1fus ago", (double)(real_now_ns - nic_ns) / 1000.0);
            } else {
                snprintf(nic_str, sizeof(nic_str), "N/A");
            }

            // BPF (CLOCK_MONOTONIC)
            char bpf_str[32];
            if (bpf_ns > 0 && mono_now_ns > bpf_ns) {
                snprintf(bpf_str, sizeof(bpf_str), "%.1fus ago", (double)(mono_now_ns - bpf_ns) / 1000.0);
            } else {
                snprintf(bpf_str, sizeof(bpf_str), "N/A");
            }

            // Poll (TSC cycles)
            char poll_str[32];
            if (poll_cycle > 0 && tsc_freq_hz_ > 0 && callback_cycle > poll_cycle) {
                snprintf(poll_str, sizeof(poll_str), "%.1fus ago",
                         cycles_to_ns(callback_cycle - poll_cycle, tsc_freq_hz_) / 1000.0);
            } else {
                snprintf(poll_str, sizeof(poll_str), "N/A");
            }

            fprintf(stderr, "  %s | NIC %s | BPF %s | poll %s |\n", label, nic_str, bpf_str, poll_str);
        };

        // Oldest/latest packet lines
        if (timing.hw_timestamp_count > 1) {
            print_packet_line("oldest", timing.hw_timestamp_oldest_ns,
                             timing.bpf_entry_oldest_ns, timing.poll_cycle_oldest);
            print_packet_line("latest", timing.hw_timestamp_latest_ns,
                             timing.bpf_entry_latest_ns, timing.poll_cycle_latest);
        } else {
            print_packet_line("packet", timing.hw_timestamp_latest_ns,
                             timing.bpf_entry_latest_ns, timing.poll_cycle_latest);
        }

        // Pipeline stages
        double poll_recv_us = 0, ssl_us = 0, total_us = 0;
        if (timing.poll_cycle_latest > 0 && timing.recv_start_cycle > timing.poll_cycle_latest) {
            poll_recv_us = cycles_to_ns(timing.recv_start_cycle - timing.poll_cycle_latest, tsc_freq_hz_) / 1000.0;
        }
        if (timing.recv_end_cycle > timing.recv_start_cycle) {
            ssl_us = cycles_to_ns(timing.recv_end_cycle - timing.recv_start_cycle, tsc_freq_hz_) / 1000.0;
        }
        if (timing.poll_cycle_latest > 0 && callback_cycle > timing.poll_cycle_latest) {
            total_us = cycles_to_ns(callback_cycle - timing.poll_cycle_latest, tsc_freq_hz_) / 1000.0;
        }
        fprintf(stderr, "  poll->recv %.1fus | SSL decrypt %.1fus | total poll->cb %.1fus\n",
                poll_recv_us, ssl_us, total_us);
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
    const char* interface_;
    const char* bpf_path_;
    const char* url_;
    ParsedURL98 parsed_url_;

    // IPC interfaces
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // Transport and SSL
    PacketTransport<websocket::xdp::XDPPacketIO> transport_;
    SSLPolicy ssl_;

    // Timing
    uint64_t tsc_freq_hz_ = 0;
    uint64_t last_op_cycle_ = 0;

    // Last-valid SSL read timestamps (for packets=0 case)
    uint64_t last_valid_ssl_start_cycle_ = 0;
    uint64_t last_valid_ssl_end_cycle_ = 0;

    // State
    std::atomic<bool> running_{false};

    // Counters
    uint64_t ssl_read_count_ = 0;
    uint64_t pong_count_ = 0;
};

}  // namespace websocket::pipeline
