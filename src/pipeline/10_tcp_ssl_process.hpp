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
//   - LowPrioCons: IPCRingConsumer<PongFrameAligned> for low-priority outbound (PONGs, etc.)
//   - Profiling: Enable profiling counters
//
// This process runs on a single core and handles:
//   1. Consuming RX packets from RAW_INBOX (via DisruptorPacketIO)
//   2. Userspace TCP connection
//   3. SSL/TLS handshake (via SSLPolicy; no-op for NoSSLPolicy)
//   4. SSL/raw read -> MSG_INBOX
//   5. Publishing MsgMetadata to downstream process
//   6. Consuming low-priority outbox (PONGs) from WS process and sending via SSL/raw
//   7. Consuming MSG_OUTBOX events and sending via SSL/raw (optional)
//   8. Producing TX packets to RAW_OUTBOX (via DisruptorPacketIO)
// ============================================================================

template<typename SSLPolicy,
         typename MsgMetadataProd,
         typename LowPrioCons,
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
                     LowPrioCons* low_prio_cons,
                     ConnStateShm* conn_state,
                     MsgOutboxCons* msg_outbox_cons = nullptr)
        : url_(url)
        , umem_area_(umem_area)
        , frame_size_(frame_size)
        , raw_inbox_cons_(raw_inbox_cons)
        , raw_outbox_prod_(raw_outbox_prod)
        , msg_inbox_(msg_inbox)
        , msg_metadata_prod_(msg_metadata_prod)
        , low_prio_cons_(low_prio_cons)
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
        transport_.set_conn_state(conn_state_);

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

        // Extract TLS record keys for direct AES-CTR decryption
        websocket::crypto::TLSRecordKeys tls_keys;
        if (ssl_.extract_record_keys(tls_keys)) {
            transport_.set_tls_record_keys(tls_keys);
            printf("[TRANSPORT] Direct AES-CTR decryption enabled (seq=0)\n");
        }

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
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                slot = profiling_data_->next_slot();
            }

            // Op 0: Poll transport
            profile_op<Profiling>([this]{ return static_cast<int32_t>(transport_.poll()); }, slot, 0);

            // Op 1: Process MSG_OUTBOX (high priority outbound messages)
            profile_op<Profiling>(
                [this]{ return process_msg_outbox(); }, slot, 1,
                msg_outbox_cons_ != nullptr);

            // Op 2: SSL/raw read -> MSG_INBOX (manually profiled via timing struct)
            int32_t ssl_bytes = process_ssl_read(timing);
            if constexpr (Profiling) {
                slot->op_details[2] = ssl_bytes;
                slot->op_cycles[2] = (timing.recv_end_cycle > timing.recv_start_cycle)
                    ? static_cast<int32_t>(timing.recv_end_cycle - timing.recv_start_cycle)
                    : 0;
            }

            if (ssl_bytes < 0) break;  // Fatal error

            // Op 3: Process LOW_MSG_OUTBOX (always — PING/PONG must not be
            // starved by continuous SSL reads or the PONG watchdog triggers)
            profile_op<Profiling>(
                [this]{ return process_low_prio_outbox(); }, slot, 3);

            // Commit profiling sample
            if constexpr (Profiling) {
                slot->transport_poll_cycle = timing.recv_start_cycle;
                slot->packet_nic_ns = 0;
                slot->nic_poll_cycle = 0;
                profiling_data_->commit();
            }
        }

        on_disconnect();

        printf("[TRANSPORT] Streaming ended. Reads: %lu, Low-prio TX: %lu\n",
               ssl_read_count_, low_prio_tx_count_);
    }

    void cleanup() {
        printf("[TRANSPORT] Cleanup\n");
        ssl_.shutdown();
        transport_.close();
    }

    void on_disconnect() {
        struct timespec _ts;
        clock_gettime(CLOCK_MONOTONIC, &_ts);

        auto reason = conn_state_ ? conn_state_->get_disconnect_reason() : DisconnectReason::UNKNOWN;
        const char* reason_str = "Unknown";
        switch (reason) {
            case DisconnectReason::TCP_RST:         reason_str = "TCP RST (connection reset by peer)"; break;
            case DisconnectReason::TCP_FIN:         reason_str = "TCP FIN (graceful close by peer)"; break;
            case DisconnectReason::WS_CLOSE:        reason_str = "WebSocket CLOSE frame"; break;
            case DisconnectReason::WS_PONG_TIMEOUT: reason_str = "WebSocket watchdog (PING+PONG missing)"; break;
            case DisconnectReason::SSL_READ_ERROR:  reason_str = "SSL read error"; break;
            default:                                reason_str = "Unknown"; break;
        }

        fprintf(stderr, "\n");
        fprintf(stderr, "[%ld.%06ld] ╔══════════════════════════════════════════════════════════════╗\n", _ts.tv_sec, _ts.tv_nsec / 1000);
        fprintf(stderr, "[%ld.%06ld] ║  [DISCONNECT] Connection lost                               ║\n", _ts.tv_sec, _ts.tv_nsec / 1000);
        fprintf(stderr, "[%ld.%06ld] ╠══════════════════════════════════════════════════════════════╣\n", _ts.tv_sec, _ts.tv_nsec / 1000);
        fprintf(stderr, "[%ld.%06ld] ║  Reason: %-51s║\n", _ts.tv_sec, _ts.tv_nsec / 1000, reason_str);
        if (conn_state_ && reason == DisconnectReason::WS_CLOSE) {
            fprintf(stderr, "[%ld.%06ld] ║  WS close code: %-44u║\n", _ts.tv_sec, _ts.tv_nsec / 1000, conn_state_->disconnect.ws_close_code);
        }
        if (conn_state_ && conn_state_->disconnect.detail[0]) {
            fprintf(stderr, "[%ld.%06ld] ║  Detail: %-51s║\n", _ts.tv_sec, _ts.tv_nsec / 1000, conn_state_->disconnect.detail);
        }
        fprintf(stderr, "[%ld.%06ld] ║  SSL reads: %-48lu║\n", _ts.tv_sec, _ts.tv_nsec / 1000, ssl_read_count_);
        fprintf(stderr, "[%ld.%06ld] ║  Low-prio TX: %-46lu║\n", _ts.tv_sec, _ts.tv_nsec / 1000, low_prio_tx_count_);
        fprintf(stderr, "[%ld.%06ld] ╚══════════════════════════════════════════════════════════════╝\n", _ts.tv_sec, _ts.tv_nsec / 1000);

        if (conn_state_) {
            conn_state_->shutdown_all();
        }
    }

    void stop() {
        running_ = false;
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    uint64_t ssl_read_count() const { return ssl_read_count_; }
    uint64_t low_prio_tx_count() const { return low_prio_tx_count_; }

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

    void publish_metadata(uint32_t write_offset, uint32_t len,
                          timing_record_t& timing, bool tls_record_end) {
        int64_t seq = msg_metadata_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: MSG_METADATA full\n");
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
        msg_metadata_prod_->publish(seq);
        last_op_cycle_ = rdtscp();
    }

    // ========================================================================
    // SSL Read -> MSG_INBOX
    // ========================================================================

    int32_t process_ssl_read(timing_record_t& timing) {
        uint32_t write_pos = msg_inbox_->current_write_pos();
        uint32_t linear_space = MSG_INBOX_SIZE - write_pos;
        if (linear_space > 16384) linear_space = 16384;

        timing.recv_start_cycle = rdtsc();
        ssize_t read_len;
        if (transport_.has_tls_record_keys()) {
            // Direct AES-CTR decryption — bypass SSL library
            read_len = transport_.ssl_read_by_chunk(
                msg_inbox_->write_ptr(), linear_space,
                [](const uint8_t*, size_t) {});
            if (read_len == -1) read_len = 0;  // non-app-data skipped
        } else {
            // Fallback to SSL library (non-AES-GCM cipher)
            read_len = ssl_.read(msg_inbox_->write_ptr(), linear_space);
        }
        timing.recv_end_cycle = rdtscp();

        if (read_len > 0) {
            // Capture timestamps from transport before advancing write pointer
            timing.hw_timestamp_count = transport_.get_recv_packet_count();
            if (timing.hw_timestamp_count > 0) {
                timing.hw_timestamp_oldest_ns = transport_.get_recv_oldest_timestamp();
                timing.hw_timestamp_latest_ns = transport_.get_recv_latest_timestamp();
                last_valid_ssl_start_cycle_ = timing.recv_start_cycle;
                last_valid_ssl_end_cycle_ = timing.recv_end_cycle;
            } else {
                timing.hw_timestamp_oldest_ns = 0;
                timing.hw_timestamp_latest_ns = 0;
            }
            timing.bpf_entry_oldest_ns = transport_.get_recv_oldest_bpf_entry_ns();
            timing.bpf_entry_latest_ns = transport_.get_recv_latest_bpf_entry_ns();
            timing.poll_cycle_oldest = transport_.get_recv_oldest_poll_cycle();
            timing.poll_cycle_latest = transport_.get_recv_latest_poll_cycle();

            uint32_t write_offset = msg_inbox_->current_write_pos();
            msg_inbox_->advance_write(static_cast<uint32_t>(read_len));

            bool tls_boundary = transport_.has_tls_record_keys()
                                ? transport_.tls_record_boundary() : false;
            publish_metadata(write_offset, static_cast<uint32_t>(read_len), timing, tls_boundary);

            transport_.reset_recv_stats();
            ssl_read_count_++;
            return static_cast<int32_t>(read_len);

        } else if (read_len < 0) {
            if (!transport_.has_tls_record_keys() && errno != EAGAIN) {
                // Only SSL library path can set errno
                fprintf(stderr, "[TRANSPORT] Read error: %s\n", strerror(errno));
                if (conn_state_) {
                    conn_state_->set_disconnect(DisconnectReason::SSL_READ_ERROR, 0, strerror(errno));
                }
                running_ = false;
                return -1;
            }
        }

        return 0;  // No data (EAGAIN)
    }

    // ========================================================================
    // Low-Priority Outbox Processing (PONGs, etc.)
    // ========================================================================

    int32_t process_low_prio_outbox() {
        int32_t count = 0;
        PongFrameAligned pong;
        while (low_prio_cons_->try_consume(pong)) {
            if (pong.data_len == 0) continue;

            // Send via SSL
            size_t total_sent = 0;
            while (total_sent < pong.data_len) {
                transport_.poll();
                ssize_t sent = ssl_.write(pong.data + total_sent, pong.data_len - total_sent);
                if (sent > 0) {
                    total_sent += sent;
                } else if (sent < 0 && errno != EAGAIN) {
                    fprintf(stderr, "[TRANSPORT] Low-prio send error: %s\n", strerror(errno));
                    break;
                }
                usleep(100);
            }

            low_prio_tx_count_++;
            count++;
        }
        return count;
    }

    // ========================================================================
    // MSG_OUTBOX Processing (high priority outbound messages)
    // ========================================================================

    int32_t process_msg_outbox() {
        int32_t count = 0;
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
            count++;
        }
        return count;
    }

    // ========================================================================
    // Timing Breakdown
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
    LowPrioCons* low_prio_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;

    // Transport and SSL
    PacketTransport<DisruptorPacketIO> transport_;
    SSLPolicy ssl_;

    // Timing
    uint64_t tsc_freq_hz_ = 0;
    uint64_t last_op_cycle_ = 0;

    // Last-valid SSL read timestamps (for packets=0 case)
    uint64_t last_valid_ssl_start_cycle_ = 0;
    uint64_t last_valid_ssl_end_cycle_ = 0;

    // Profiling (optional)
    CycleSampleBuffer* profiling_data_ = nullptr;

    // State
    std::atomic<bool> running_{false};

    // Counters
    uint64_t ssl_read_count_ = 0;
    uint64_t low_prio_tx_count_ = 0;
};

}  // namespace websocket::pipeline
