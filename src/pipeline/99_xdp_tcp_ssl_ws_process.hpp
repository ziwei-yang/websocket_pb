// pipeline/99_xdp_tcp_ssl_ws_process.hpp
// Unified XDP + TCP + SSL + WebSocket Single-Process Pipeline
//
// Combines all network stack layers in a single process for minimal IPC overhead.
// Based on test/integration/xdp_binance.cpp but outputs to IPC rings instead of printing.
//
// Data Flow:
//   NIC -> XDP -> Userspace TCP -> SSL decrypt -> MSG_INBOX
//                                                    |
//                                   WS parse -> WS_FRAME_INFO ring
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
#include "20_ws_process.hpp"  // For WebSocket frame parsing utilities

#include "../policy/transport.hpp"
#include "../xdp/xdp_packet_io.hpp"
#include "../core/http.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

using namespace websocket::transport;
using namespace websocket::http;

// ============================================================================
// URL Parsing
// ============================================================================

struct ParsedURL {
    std::string host;       // e.g., "stream.binance.com"
    uint16_t port = 443;    // e.g., 443
    std::string path;       // e.g., "/ws"
    bool is_wss = true;     // true for wss://, false for ws://

    bool valid = false;
};

inline ParsedURL parse_url(const char* url) {
    ParsedURL result;
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
// UnifiedXDPProcess - Single-process XDP + TCP + SSL + WebSocket
//
// Template Parameters:
//   - SSLPolicy: SSL/TLS implementation (OpenSSLPolicy, WolfSSLPolicy)
//   - WSFrameInfoProd: IPCRingProducer<WSFrameInfo> for publishing frame info
//   - PongsProd: IPCRingProducer<PongFrameAligned> for PONG responses (optional)
//   - Profiling: Enable profiling counters
//
// This process runs on a single core and handles:
//   1. XDP transport initialization
//   2. Userspace TCP connection
//   3. SSL/TLS handshake
//   4. HTTP WebSocket upgrade
//   5. WebSocket frame parsing
//   6. Publishing to IPC rings
// ============================================================================

template<typename SSLPolicy,
         typename WSFrameInfoProd,
         typename PongsProd = void*,
         bool Profiling = false>
struct UnifiedXDPProcess {
public:
    // ========================================================================
    // Initialization
    // ========================================================================

    UnifiedXDPProcess(const char* interface,
                      const char* bpf_path,
                      const char* url,
                      MsgInbox* msg_inbox,
                      WSFrameInfoProd* ws_frame_info_prod,
                      ConnStateShm* conn_state,
                      PongsProd* pongs_prod = nullptr)
        : interface_(interface)
        , bpf_path_(bpf_path)
        , url_(url)
        , msg_inbox_(msg_inbox)
        , ws_frame_info_prod_(ws_frame_info_prod)
        , conn_state_(conn_state)
        , pongs_prod_(pongs_prod) {

        parsed_url_ = parse_url(url);
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    bool init() {
        printf("[UNIFIED] Initializing XDP + TCP + SSL + WebSocket\n");
        printf("[UNIFIED] URL: %s\n", url_);
        printf("[UNIFIED] Interface: %s\n", interface_);

        if (!parsed_url_.valid) {
            fprintf(stderr, "[UNIFIED] Invalid URL: %s\n", url_);
            return false;
        }

        printf("[UNIFIED] Host: %s, Port: %u, Path: %s\n",
               parsed_url_.host.c_str(), parsed_url_.port, parsed_url_.path.c_str());

        // Calibrate TSC
        printf("[UNIFIED] Calibrating TSC...\n");
        tsc_freq_hz_ = calibrate_tsc_freq();
        printf("[UNIFIED] TSC frequency: %.2f GHz\n", tsc_freq_hz_ / 1e9);

        if (conn_state_) {
            conn_state_->tsc_freq_hz = tsc_freq_hz_;
        }

        // Phase 1: XDP + Userspace TCP Initialization
        printf("[UNIFIED] Phase 1: XDP Transport Init\n");
        transport_.init(interface_, bpf_path_);

        // Resolve and configure BPF filter
        auto ips = resolve_hostname(parsed_url_.host.c_str());
        if (ips.empty()) {
            fprintf(stderr, "[UNIFIED] Failed to resolve %s\n", parsed_url_.host.c_str());
            return false;
        }

        printf("[UNIFIED] Resolved %zu IP(s): ", ips.size());
        for (size_t i = 0; i < ips.size(); i++) {
            printf("%s%s", ips[i].c_str(), (i < ips.size() - 1) ? ", " : "\n");
            transport_.add_exchange_ip(ips[i].c_str());
        }
        transport_.add_exchange_port(parsed_url_.port);

        printf("[UNIFIED] XDP Mode: %s\n", transport_.get_xdp_mode());
        printf("[UNIFIED] BPF Filter: %s\n", transport_.is_bpf_enabled() ? "ENABLED" : "DISABLED");

        // Phase 2: TCP Connection
        printf("[UNIFIED] Phase 2: TCP Connect to %s:%u\n",
               parsed_url_.host.c_str(), parsed_url_.port);
        transport_.connect(parsed_url_.host.c_str(), parsed_url_.port);

        // Phase 3: SSL/TLS Handshake
        printf("[UNIFIED] Phase 3: SSL/TLS Handshake\n");
        ssl_.init();
        ssl_.handshake_userspace_transport(&transport_);
        printf("[UNIFIED] SSL handshake complete\n");

        // Phase 4: HTTP WebSocket Upgrade
        printf("[UNIFIED] Phase 4: HTTP WebSocket Upgrade\n");
        if (!perform_ws_upgrade()) {
            fprintf(stderr, "[UNIFIED] WebSocket upgrade failed\n");
            return false;
        }
        printf("[UNIFIED] WebSocket upgrade complete\n");

        // Reset stats before message streaming
        transport_.reset_hw_timestamps();
        transport_.reset_recv_stats();

        return true;
    }

    void run() {
        printf("[UNIFIED] Phase 5: WebSocket Message Streaming\n");

        // Mark ready if conn_state available
        if (conn_state_) {
            conn_state_->set_handshake_ws_ready();
        }

        running_ = true;

        // Timing record for latency breakdown
        timing_record_t timing;
        memset(&timing, 0, sizeof(timing));

        while (running_ && check_running()) {
            // Stage 2: Event loop start
            timing.event_cycle = rdtsc();

            // Poll transport (handles TX completions, etc.)
            transport_.poll();

            // Stage 3: Before SSL read
            timing.recv_start_cycle = rdtsc();

            // Read from SSL
            ssize_t read_len = ssl_.read(frame_buffer_ + buffer_offset_,
                                          sizeof(frame_buffer_) - buffer_offset_);

            // Stage 4: After SSL read
            timing.recv_end_cycle = rdtscp();

            if (read_len > 0) {
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                const uint8_t* rd = reinterpret_cast<const uint8_t*>(frame_buffer_ + buffer_offset_);
                fprintf(stderr, "[%ld.%06ld] [SSL-READ] %zd bytes \"",
                        ts.tv_sec, ts.tv_nsec / 1000, read_len);
                for (ssize_t i = 0; i < read_len; ++i) {
                    uint8_t c = rd[i];
                    if (c >= 0x20 && c < 0x7f) fputc(c, stderr);
                    else fprintf(stderr, "\\x%02x", c);
                }
                fprintf(stderr, "\"\n");
                buffer_offset_ += read_len;

                // Parse all complete frames in buffer
                size_t consumed = 0;
                while (consumed < buffer_offset_) {
                    WebSocketFrame frame;
                    if (!parse_websocket_frame(frame_buffer_ + consumed,
                                               buffer_offset_ - consumed, frame)) {
                        break;  // Incomplete frame
                    }

                    uint64_t parse_cycle = rdtscp();
                    size_t total_frame_size = frame.header_len + frame.payload_len;

                    // Handle frame by opcode
                    handle_frame(frame, parse_cycle, timing);

                    consumed += total_frame_size;
                }

                // Shift remaining data to front of buffer
                if (consumed > 0 && consumed < buffer_offset_) {
                    memmove(frame_buffer_, frame_buffer_ + consumed, buffer_offset_ - consumed);
                    buffer_offset_ -= consumed;
                } else if (consumed == buffer_offset_) {
                    buffer_offset_ = 0;
                }

            } else if (read_len < 0 && errno != EAGAIN) {
                fprintf(stderr, "[UNIFIED] SSL read error: %s\n", strerror(errno));
                break;
            }

            // Pure busy-poll for lowest latency
        }

        printf("[UNIFIED] Streaming ended. Messages: %lu, PINGs: %lu, PONGs: %lu\n",
               msg_count_, ping_count_, pong_count_);
    }

    void cleanup() {
        printf("[UNIFIED] Cleanup\n");
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

    uint64_t message_count() const { return msg_count_; }
    uint64_t ping_count() const { return ping_count_; }
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

        printf("[UNIFIED] Sending HTTP upgrade request (%zu bytes)\n", req_len);

        // Send upgrade request
        size_t total_sent = 0;
        while (total_sent < req_len) {
            transport_.poll();
            ssize_t sent = ssl_.write(upgrade_req + total_sent, req_len - total_sent);
            if (sent > 0) {
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                fprintf(stderr, "[%ld.%06ld] [SSL-WRITE] %zd bytes\n",
                        ts.tv_sec, ts.tv_nsec / 1000, sent);
                total_sent += sent;
            } else if (sent < 0 && errno != EAGAIN) {
                fprintf(stderr, "[UNIFIED] Failed to send upgrade request\n");
                return false;
            }
            usleep(1000);
        }

        // Receive upgrade response
        printf("[UNIFIED] Waiting for HTTP 101 response...\n");
        uint8_t response_buf[4096];
        bool response_validated = false;
        int poll_attempts = 0;
        int max_attempts = 1000;

        while (poll_attempts < max_attempts && !response_validated) {
            transport_.poll();
            ssize_t received = ssl_.read(response_buf, sizeof(response_buf));

            if (received > 0) {
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                fprintf(stderr, "[%ld.%06ld] [SSL-READ] %zd bytes\n",
                        ts.tv_sec, ts.tv_nsec / 1000, received);
                if (validate_http_upgrade_response(response_buf, received)) {
                    printf("[UNIFIED] HTTP 101 Switching Protocols validated\n");
                    response_validated = true;
                    break;
                }
            } else if (received < 0 && errno != EAGAIN) {
                fprintf(stderr, "[UNIFIED] SSL read error during upgrade\n");
                return false;
            }

            usleep(1000);
            poll_attempts++;
        }

        return response_validated;
    }

    // ========================================================================
    // Frame Handling
    // ========================================================================

    void handle_frame(const WebSocketFrame& frame, uint64_t parse_cycle,
                      timing_record_t& timing) {
        // Capture NIC timestamps
        timing.hw_timestamp_count = transport_.get_recv_packet_count();
        if (timing.hw_timestamp_count > 0) {
            timing.hw_timestamp_oldest_ns = transport_.get_recv_oldest_timestamp();
            timing.hw_timestamp_latest_ns = transport_.get_recv_latest_timestamp();
        } else {
            timing.hw_timestamp_oldest_ns = 0;
            timing.hw_timestamp_latest_ns = 0;
        }

        switch (frame.opcode) {
            case 0x01:  // TEXT
            case 0x02:  // BINARY
                handle_data_frame(frame, parse_cycle, timing);
                break;

            case 0x09:  // PING
                handle_ping(frame, parse_cycle, timing);
                break;

            case 0x0A:  // PONG
                // Ignore unsolicited PONGs
                break;

            case 0x08:  // CLOSE
                printf("[UNIFIED] CLOSE frame received\n");
                running_ = false;
                break;

            default:
                break;
        }
    }

    void handle_data_frame(const WebSocketFrame& frame, uint64_t parse_cycle,
                           timing_record_t& timing) {
        msg_count_++;

        // Write payload to MSG_INBOX
        uint32_t inbox_offset = msg_inbox_->current_write_pos();
        msg_inbox_->write_data(frame.payload, frame.payload_len);

        // Publish WSFrameInfo
        publish_ws_frame_info(frame, inbox_offset, parse_cycle, timing, false);

        // Reset recv stats for next batch
        transport_.reset_recv_stats();

        // Print timing breakdown
        if constexpr (Profiling) {
            print_timing_breakdown(frame, parse_cycle, timing);
        }
    }

    void handle_ping(const WebSocketFrame& frame, uint64_t parse_cycle,
                     timing_record_t& timing) {
        ping_count_++;

        printf("[UNIFIED] PING #%lu received (payload_len=%zu)\n",
               ping_count_, frame.payload_len);

        // Write PING payload to MSG_INBOX (for reference)
        uint32_t inbox_offset = msg_inbox_->current_write_pos();
        msg_inbox_->write_data(frame.payload, frame.payload_len);

        // Publish WSFrameInfo for PING
        publish_ws_frame_info(frame, inbox_offset, parse_cycle, timing, true);

        // Send PONG response
        send_pong(frame);
    }

    void send_pong(const WebSocketFrame& ping_frame) {
        pong_count_++;

        // Build PONG frame
        uint8_t pong_buffer[256];
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        size_t pong_len = build_pong_frame(ping_frame.payload, ping_frame.payload_len,
                                            pong_buffer, mask);

        // If pongs_prod_ is available, publish to ring
        if constexpr (!std::is_same_v<PongsProd, void*>) {
            if (pongs_prod_) {
                int64_t seq = pongs_prod_->try_claim();
                if (seq >= 0) {
                    auto& pong = (*pongs_prod_)[seq];
                    pong.clear();
                    pong.set(pong_buffer, pong_len);
                    pongs_prod_->publish(seq);
                }
            }
        }

        // Send PONG directly via SSL
        size_t pong_total = 0;
        while (pong_total < pong_len) {
            transport_.poll();
            ssize_t pong_sent_bytes = ssl_.write(pong_buffer + pong_total,
                                                  pong_len - pong_total);
            if (pong_sent_bytes > 0) {
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                fprintf(stderr, "[%ld.%06ld] [SSL-WRITE] %zd bytes\n",
                        ts.tv_sec, ts.tv_nsec / 1000, pong_sent_bytes);
                pong_total += pong_sent_bytes;
            }
            usleep(100);
        }
    }

    void publish_ws_frame_info(const WebSocketFrame& frame, uint32_t inbox_offset,
                               uint64_t parse_cycle, timing_record_t& timing,
                               bool is_ping) {
        int64_t seq = ws_frame_info_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[UNIFIED] WS_FRAME_INFO ring full!\n");
            return;
        }

        auto& info = (*ws_frame_info_prod_)[seq];
        info.clear();

        info.msg_inbox_offset = inbox_offset;
        info.payload_len = static_cast<uint32_t>(frame.payload_len);
        info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
        info.opcode = frame.opcode;
        info.is_fin = true;
        info.is_fragmented = false;
        info.is_last_fragment = false;

        // Timestamps
        info.first_byte_ts = timing.hw_timestamp_oldest_ns;
        info.last_byte_ts = timing.hw_timestamp_latest_ns;
        info.first_nic_frame_poll_cycle = timing.recv_start_cycle;
        info.latest_nic_frame_poll_cycle = timing.recv_end_cycle;
        info.latest_raw_frame_poll_cycle = timing.recv_end_cycle;
        info.first_ssl_read_cycle = timing.recv_start_cycle;
        info.last_ssl_read_cycle = timing.recv_end_cycle;
        info.ssl_read_ct = 1;
        info.nic_packet_ct = timing.hw_timestamp_count;
        info.ws_parse_cycle = parse_cycle;

        ws_frame_info_prod_->publish(seq);
    }

    void print_timing_breakdown(const WebSocketFrame& frame, uint64_t parse_cycle,
                                timing_record_t& timing) {
        uint64_t callback_cycle = rdtscp();

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        fprintf(stderr, "[%ld.%06ld] [WS-MSG] #%lu payload_len=%zu\n",
                ts.tv_sec, ts.tv_nsec / 1000, msg_count_, frame.payload_len);

        // Parse "E" (event time) field from Binance JSON
        uint64_t event_time_ms = 0;
        const char* e_pos = strstr((const char*)frame.payload, "\"E\":");
        if (e_pos) {
            event_time_ms = strtoull(e_pos + 4, nullptr, 10);
        }

        // Calculate exchange-to-local latency
        if (event_time_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t local_time_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            int64_t exchange_latency_ms = (int64_t)local_time_ms - (int64_t)event_time_ms;
            printf("  Exchange Latency: %ld ms\n", exchange_latency_ms);
        }

        printf("  Latency Breakdown:\n");

        // Stage 1: Hardware timestamp
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

        if (parse_cycle > timing.recv_end_cycle) {
            printf("    [Stage 4->5] WS parse: %.3f us\n",
                   cycles_to_ns(parse_cycle - timing.recv_end_cycle, tsc_freq_hz_) / 1000.0);
        }

        if (callback_cycle > parse_cycle) {
            printf("    [Stage 5->6] To callback: %.3f us\n",
                   cycles_to_ns(callback_cycle - parse_cycle, tsc_freq_hz_) / 1000.0);
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
    const char* interface_;
    const char* bpf_path_;
    const char* url_;
    ParsedURL parsed_url_;

    // IPC interfaces
    MsgInbox* msg_inbox_ = nullptr;
    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    PongsProd* pongs_prod_ = nullptr;

    // Transport and SSL
    PacketTransport<websocket::xdp::XDPPacketIO> transport_;
    SSLPolicy ssl_;

    // Timing
    uint64_t tsc_freq_hz_ = 0;

    // Frame buffer
    uint8_t frame_buffer_[65536];
    size_t buffer_offset_ = 0;

    // State
    std::atomic<bool> running_{false};

    // Counters
    uint64_t msg_count_ = 0;
    uint64_t ping_count_ = 0;
    uint64_t pong_count_ = 0;
};

}  // namespace websocket::pipeline
