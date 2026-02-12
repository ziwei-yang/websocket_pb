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
#include <type_traits>
#include <algorithm>
#include <stdexcept>
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
#include "../policy/transport_ab.hpp"
#include "../core/timing.hpp"
// ip_probe.hpp no longer needed — reconnect uses startup IP pool from conn_state

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
// ConnPhase - Per-connection transport phase (state machine)
// ============================================================================

enum class ConnPhase : uint8_t {
    ACTIVE = 0,          // Normal: direct AES-CTR decrypt → msg_metadata
    TCP_CONNECTING,      // SYN sent, waiting for SYN-ACK
    TLS_HANDSHAKING,     // wolfSSL_connect() in progress (non-blocking steps)
    TLS_READY,           // TLS done, reading via wolfSSL for WS handshake
    WAITING_RETRY,       // Error occurred, waiting for backoff before retry
};

struct ReconnectCtx {
    ConnPhase phase = ConnPhase::TCP_CONNECTING;  // Start in TCP_CONNECTING
    uint32_t attempts = 0;
    uint64_t phase_start_cycle = 0;
    uint64_t last_attempt_cycle = 0;  // For backoff timing

    void reset() {
        phase = ConnPhase::ACTIVE;
        attempts = 0;
        phase_start_cycle = 0;
        last_attempt_cycle = 0;
    }
};

// ============================================================================
// TransportProcess - Protocol-agnostic TCP + SSL using DisruptorPacketIO
//
// Template Parameters:
//   - SSLPolicy: SSL/TLS implementation (OpenSSLPolicy, WolfSSLPolicy, NoSSLPolicy)
//   - MsgMetadataProd: IPCRingProducer<MsgMetadata> for publishing metadata
//   - LowPrioCons: IPCRingConsumer<PongFrameAligned> for low-priority outbound
//   - Profiling: Enable profiling counters
// ============================================================================

template<typename SSLPolicy,
         typename MsgMetadataProd,
         typename LowPrioCons,
         bool EnableAB = false,
         bool AutoReconnect = false,
         bool Profiling = false>
struct TransportProcess {
public:
    // Type aliases for IPC rings
    using RawInboxCons = IPCRingConsumer<websocket::xdp::PacketFrameDescriptor>;
    using RawOutboxProd = IPCRingProducer<websocket::xdp::PacketFrameDescriptor>;
    using MsgOutboxCons = IPCRingConsumer<MsgOutboxEvent>;

    // Transport type: PacketTransportAB when EnableAB, single PacketTransport otherwise
    using TransportType = std::conditional_t<EnableAB,
        websocket::transport::PacketTransportAB<DisruptorPacketIO>,
        websocket::transport::PacketTransport<DisruptorPacketIO>>;

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
                     MsgOutboxCons* msg_outbox_cons = nullptr,
                     MsgInbox* msg_inbox_b = nullptr,
                     MsgMetadataProd* msg_metadata_prod_b = nullptr)
        : url_(url)
        , umem_area_(umem_area)
        , frame_size_(frame_size)
        , raw_inbox_cons_(raw_inbox_cons)
        , raw_outbox_prod_(raw_outbox_prod)
        , low_prio_cons_(low_prio_cons)
        , conn_state_(conn_state)
        , msg_outbox_cons_(msg_outbox_cons) {

        msg_inbox_[0] = msg_inbox;
        msg_metadata_prod_[0] = msg_metadata_prod;
        if constexpr (EnableAB) {
            msg_inbox_[1] = msg_inbox_b;
            msg_metadata_prod_[1] = msg_metadata_prod_b;
        }

        parsed_url_ = parse_url(url);
    }

    void set_profiling_data(CycleSampleBuffer* data) {
        profiling_data_ = data;
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    bool init() {
        printf("[TRANSPORT] Initializing Transport Process%s%s\n",
               EnableAB ? " (Dual A/B)" : "",
               AutoReconnect ? " (AutoReconnect)" : "");
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

        if constexpr (AutoReconnect) {
            // Non-blocking startup: initiate TCP connect for all connections
            // State machine in run() handles TCP→TLS→TLS_READY→ACTIVE
            if constexpr (EnableAB) {
                // Use per-connection target IPs from parent probe
                transport_.start_connect_ip(0, ntohl(conn_state_->conn_target_ip[0]), parsed_url_.port);
                reconn_[0].phase = ConnPhase::TCP_CONNECTING;
                reconn_[0].phase_start_cycle = rdtsc();

                transport_.start_connect_ip(1, ntohl(conn_state_->conn_target_ip[1]), parsed_url_.port);
                reconn_[1].phase = ConnPhase::TCP_CONNECTING;
                reconn_[1].phase_start_cycle = rdtsc();
            } else {
                transport_.initiate_connect_ip(ntohl(conn_state_->conn_target_ip[0]), parsed_url_.port);
                reconn_[0].phase = ConnPhase::TCP_CONNECTING;
                reconn_[0].phase_start_cycle = rdtsc();
            }
        } else {
            // Non-reconnect: blocking TCP + TLS handshake (original path)
            if constexpr (EnableAB) {
                transport_.start_connect_ip(0, ntohl(conn_state_->conn_target_ip[0]), parsed_url_.port);
                // Blocking wait for TCP
                while (!transport_.handshake_complete(0)) {
                    transport_.poll();
                    usleep(100);
                }
                transport_.set_connected(0);

                if (ssl_[0].init() != 0) return false;
                if (ssl_[0].handshake_userspace_transport(&transport_.a, parsed_url_.host.c_str()) != 0) return false;
                websocket::crypto::TLSRecordKeys tls_keys_a;
                if (ssl_[0].extract_record_keys(tls_keys_a)) {
                    transport_.a.set_tls_record_keys(tls_keys_a);
                }
                transport_.a.reset_hw_timestamps();
                transport_.a.reset_recv_stats();

                transport_.start_connect_ip(1, ntohl(conn_state_->conn_target_ip[1]), parsed_url_.port);
                while (!transport_.handshake_complete(1)) {
                    transport_.poll();
                    usleep(100);
                }
                transport_.set_connected(1);

                if (ssl_[1].init() != 0) return false;
                if (ssl_[1].handshake_userspace_transport(&transport_.b, parsed_url_.host.c_str()) != 0) return false;
                websocket::crypto::TLSRecordKeys tls_keys_b;
                if (ssl_[1].extract_record_keys(tls_keys_b)) {
                    transport_.b.set_tls_record_keys(tls_keys_b);
                }
                transport_.b.reset_hw_timestamps();
                transport_.b.reset_recv_stats();
            } else {
                transport_.initiate_connect_ip(ntohl(conn_state_->conn_target_ip[0]), parsed_url_.port);
                // Blocking wait for TCP
                while (!transport_.handshake_complete()) {
                    transport_.poll();
                    usleep(100);
                }
                transport_.set_connected();
                if (ssl_[0].init() != 0) return false;
                if (ssl_[0].handshake_userspace_transport(&transport_, parsed_url_.host.c_str()) != 0) return false;
                websocket::crypto::TLSRecordKeys tls_keys;
                if (ssl_[0].extract_record_keys(tls_keys)) {
                    transport_.set_tls_record_keys(tls_keys);
                }
                transport_.reset_hw_timestamps();
                transport_.reset_recv_stats();
            }

            // Signal TLS ready for downstream process
            if (conn_state_) {
                conn_state_->set_handshake_tls_ready();
            }
        }

        return true;
    }

    void run() {
        printf("[TRANSPORT] Phase 4: Message Streaming%s%s\n",
               EnableAB ? " (Dual A/B)" : "",
               AutoReconnect ? " (AutoReconnect)" : "");

        running_ = true;

        // Timing records for latency breakdown
        timing_record_t timing[NUM_CONN];
        for (size_t i = 0; i < NUM_CONN; i++) {
            memset(&timing[i], 0, sizeof(timing_record_t));
        }

        while (running_ && check_running()) {
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                slot = profiling_data_->next_slot();
            }

            if constexpr (EnableAB) {
                // ── Dual A/B: Demuxed poll ──
                // Op 0: Demuxed poll (processes RX for BOTH A and B)
                profile_op<Profiling>([this]{ return static_cast<int32_t>(transport_.poll()); }, slot, 0);
            } else {
                // ── Single connection ──
                // Op 0: Poll transport
                profile_op<Profiling>([this]{ return static_cast<int32_t>(transport_.poll()); }, slot, 0);
            }

            // Op 1: Process MSG_OUTBOX (high priority outbound messages)
            profile_op<Profiling>(
                [this]{ return process_msg_outbox(); }, slot, 1,
                msg_outbox_cons_ != nullptr);

            // ── Per-connection state machine dispatch ──
            for (uint8_t ci = 0; ci < NUM_CONN; ci++) {
                if constexpr (AutoReconnect) {
                    // Check WS-initiated reconnect request
                    if (conn_state_->get_reconnect_request(ci)) {
                        conn_state_->clear_reconnect_request(ci);
                        if (reconn_[ci].phase == ConnPhase::ACTIVE) {
                            if constexpr (EnableAB) {
                                uint8_t other = 1 - ci;
                                struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                                fprintf(stderr, "[%ld.%06ld] [RECONNECT] WS-watchdog triggered conn %u "
                                        "(other conn %u phase=%u)\n",
                                        _ts.tv_sec, _ts.tv_nsec / 1000, ci, other,
                                        static_cast<unsigned>(reconn_[other].phase));
                            }
                            start_reconnect(ci);
                        } else {
                            // Already reconnecting — request arrived during intermediate phase
                            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                            fprintf(stderr, "[%ld.%06ld] [RECONNECT] Ignoring WS reconnect request for conn %u "
                                    "(already in phase %u)\n",
                                    _ts.tv_sec, _ts.tv_nsec / 1000, ci,
                                    static_cast<unsigned>(reconn_[ci].phase));
                        }
                    }

                    // Check transport-level TCP failure
                    if (reconn_[ci].phase == ConnPhase::ACTIVE) {
                        auto& conn = get_transport(ci);
                        if (conn.needs_reconnect()) {
                            conn.clear_reconnect_flag();
                            start_reconnect(ci);
                        }
                    }

                    // Dispatch based on phase
                    switch (reconn_[ci].phase) {
                    case ConnPhase::TCP_CONNECTING:
                        step_tcp_connect(ci);
                        break;
                    case ConnPhase::TLS_HANDSHAKING:
                        step_tls_handshake(ci);
                        break;
                    case ConnPhase::TLS_READY:
                        // Read via wolfSSL and publish to msg_metadata
                        process_ssl_read_wolfssl(ci, timing[ci]);
                        // Check if WS handshake is done → extract keys → ACTIVE
                        if (conn_state_->get_ws_handshake_done(ci)) {
                            conn_state_->clear_ws_handshake_done(ci);
                            switch_to_direct_decrypt(ci);
                        }
                        break;
                    case ConnPhase::WAITING_RETRY:
                        if (!should_backoff(ci)) {
                            start_reconnect_from_tcp(ci);
                        }
                        break;
                    case ConnPhase::ACTIVE:
                        // Normal direct AES-CTR decrypt path
                        {
                            int32_t ssl_bytes = process_ssl_read_for_conn(ci, timing[ci]);
                            if constexpr (Profiling) {
                                // Map conn 0 → op slot 2, conn 1 → op slot 4
                                size_t op_idx = (ci == 0) ? 2 : 4;
                                slot->op_details[op_idx] = ssl_bytes;
                                slot->op_cycles[op_idx] = (timing[ci].recv_end_cycle > timing[ci].recv_start_cycle)
                                    ? static_cast<int32_t>(timing[ci].recv_end_cycle - timing[ci].recv_start_cycle) : 0;
                            }
                            if (!AutoReconnect && ssl_bytes < 0) {
                                running_ = false;
                            }
                        }
                        break;
                    }
                } else {
                    // Non-reconnect: all connections already ACTIVE from init()
                    int32_t ssl_bytes = process_ssl_read_for_conn(ci, timing[ci]);
                    if constexpr (Profiling) {
                        size_t op_idx = (ci == 0) ? 2 : 4;
                        slot->op_details[op_idx] = ssl_bytes;
                        slot->op_cycles[op_idx] = (timing[ci].recv_end_cycle > timing[ci].recv_start_cycle)
                            ? static_cast<int32_t>(timing[ci].recv_end_cycle - timing[ci].recv_start_cycle) : 0;
                    }
                    if (ssl_bytes < 0) {
                        running_ = false;
                    }
                }
            }

            // Op 3: Process LOW_MSG_OUTBOX (PONGs)
            profile_op<Profiling>(
                [this]{ return process_low_prio_outbox(); }, slot, 3);

            // Commit profiling sample
            if constexpr (Profiling) {
                slot->transport_poll_cycle = timing[0].recv_start_cycle;
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
        for (size_t i = 0; i < NUM_CONN; i++) {
            ssl_[i].shutdown();
        }
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
    // Transport accessor helper (works for both EnableAB and single)
    // ========================================================================

    auto& get_transport(uint8_t ci) {
        if constexpr (EnableAB) {
            return transport_.transport(ci);
        } else {
            (void)ci;
            return transport_;
        }
    }

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
    // Reconnect State Machine: start_reconnect, step_tcp_connect, step_tls_handshake
    // ========================================================================

    void start_reconnect(uint8_t ci) {
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [RECONNECT] Starting reconnect for conn %u (attempt %u)\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci, reconn_[ci].attempts + 1);

        // Publish TCP_DISCONNECTED event so WS knows
        publish_control_event(ci, MetaEventType::TCP_DISCONNECTED);

        // Shutdown SSL session
        ssl_[ci].shutdown();

        // Pick a different IP from the startup pool (all IPs are already in BPF filter)
        if (conn_state_->exchange_ip_count > 1) {
            uint32_t current_ip = conn_state_->conn_target_ip[ci];
            uint32_t other_ip = 0;
            if constexpr (EnableAB) {
                other_ip = conn_state_->conn_target_ip[1 - ci];
            }

            // Round-robin through the pool, skip current and other connection's IP
            uint32_t new_ip = current_ip;
            uint8_t count = conn_state_->exchange_ip_count;
            for (uint8_t i = 0; i < count; i++) {
                uint8_t idx = (reconn_[ci].attempts + i) % count;
                uint32_t candidate = conn_state_->exchange_ips[idx];
                if (candidate != current_ip && candidate != other_ip) {
                    new_ip = candidate;
                    break;
                }
            }

            if (new_ip != current_ip) {
                if constexpr (EnableAB) {
                    transport_.set_remote_ip(ci, ntohl(new_ip));
                } else {
                    transport_.set_remote_ip(ntohl(new_ip));
                }
                conn_state_->conn_target_ip[ci] = new_ip;

                char ip_str[INET_ADDRSTRLEN];
                struct in_addr tmp;
                tmp.s_addr = new_ip;
                inet_ntop(AF_INET, &tmp, ip_str, sizeof(ip_str));
                fprintf(stderr, "[%ld.%06ld] [RECONNECT] Switched to pool IP: conn %u -> %s\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000, ci, ip_str);
            }
        }

        // Reset and reconnect TCP (uses updated remote IP)
        int rc;
        if constexpr (EnableAB) {
            rc = transport_.start_reconnect(ci);
        } else {
            transport_.reset_for_reconnect();
            rc = transport_.initiate_reconnect();
        }

        reconn_[ci].phase = (rc == 0) ? ConnPhase::TCP_CONNECTING : ConnPhase::WAITING_RETRY;
        reconn_[ci].phase_start_cycle = rdtsc();
        reconn_[ci].attempts++;
        reconn_[ci].last_attempt_cycle = rdtsc();
    }

    void step_tcp_connect(uint8_t ci) {
        auto& conn = get_transport(ci);

        if (conn.handshake_complete()) {
            // SYN-ACK received, TCP ESTABLISHED
            conn.set_connected();
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TCP established for conn %u\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);

            // Prepare TLS handshake
            if (ssl_[ci].init() != 0 ||
                ssl_[ci].prepare_handshake(&conn, parsed_url_.host.c_str()) != 0) {
                fprintf(stderr, "[RECONNECT] TLS init failed for conn %u, restarting\n", ci);
                if (should_backoff(ci)) {
                    reconn_[ci].phase = ConnPhase::WAITING_RETRY;
                    return;
                }
                start_reconnect_from_tcp(ci);
                return;
            }
            reconn_[ci].phase = ConnPhase::TLS_HANDSHAKING;
            reconn_[ci].phase_start_cycle = rdtsc();
            return;
        }

        // Timeout check (5s)
        uint64_t elapsed = rdtsc() - reconn_[ci].phase_start_cycle;
        uint64_t timeout_cycles = 5ULL * tsc_freq_hz_;
        if (elapsed > timeout_cycles) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TCP connect timeout for conn %u, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            // Apply backoff then restart
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
        }
    }

    void step_tls_handshake(uint8_t ci) {
        // Single step of wolfSSL_connect (need poll first for data)
        auto result = ssl_[ci].step_handshake();

        using HR = typename SSLPolicy::HandshakeResult;
        if (result == HR::SUCCESS) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake complete for conn %u\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);

            // Publish TLS_CONNECTED event
            publish_control_event(ci, MetaEventType::TLS_CONNECTED);

            // Enter TLS_READY: read via wolfSSL until WS signals handshake done
            reconn_[ci].phase = ConnPhase::TLS_READY;
            reconn_[ci].phase_start_cycle = rdtsc();

            // Signal TLS ready on first connection for non-reconnect startup path
            if (!tls_ready_signaled_) {
                conn_state_->set_handshake_tls_ready();
                tls_ready_signaled_ = true;
            }
            return;
        }

        if (result == HR::ERROR) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake error for conn %u, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
            return;
        }

        // IN_PROGRESS: timeout check (5s)
        uint64_t elapsed = rdtsc() - reconn_[ci].phase_start_cycle;
        uint64_t timeout_cycles = 5ULL * tsc_freq_hz_;
        if (elapsed > timeout_cycles) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake timeout for conn %u, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
        }
    }

    /**
     * Switch from wolfSSL reads (TLS_READY) to direct AES-CTR decrypt (ACTIVE).
     * Called when WS process signals ws_handshake_done.
     */
    void switch_to_direct_decrypt(uint8_t ci) {
        auto& conn = get_transport(ci);

        // Extract TLS keys for direct decryption
        websocket::crypto::TLSRecordKeys tls_keys;
        if (ssl_[ci].extract_record_keys(tls_keys)) {
            conn.set_tls_record_keys(tls_keys);
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] Direct AES-CTR decrypt enabled for conn %u\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
        }

        // Stop trickle thread (if applicable)
        conn.stop_rx_trickle_thread();

        conn.reset_hw_timestamps();
        conn.reset_recv_stats();

        reconn_[ci].reset();  // phase → ACTIVE, attempts → 0
    }

    /**
     * Restart from TCP level (shutdown SSL, reset transport, SYN).
     */
    void start_reconnect_from_tcp(uint8_t ci) {
        ssl_[ci].shutdown();
        int rc;
        if constexpr (EnableAB) {
            rc = transport_.start_reconnect(ci);
        } else {
            transport_.reset_for_reconnect();
            rc = transport_.initiate_reconnect();
        }
        reconn_[ci].phase = (rc == 0) ? ConnPhase::TCP_CONNECTING : ConnPhase::WAITING_RETRY;
        reconn_[ci].phase_start_cycle = rdtsc();
        reconn_[ci].last_attempt_cycle = rdtsc();
    }

    /**
     * Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s cap.
     * Returns true if we should skip this iteration (too soon).
     */
    bool should_backoff(uint8_t ci) {
        if (reconn_[ci].attempts == 0) return false;
        uint32_t backoff_ms = RECONNECT_BACKOFF_BASE_MS
            << std::min(reconn_[ci].attempts - 1, 4u);
        if (backoff_ms > RECONNECT_BACKOFF_MAX_MS) backoff_ms = RECONNECT_BACKOFF_MAX_MS;
        uint64_t backoff_cycles = static_cast<uint64_t>(backoff_ms) * (tsc_freq_hz_ / 1000);
        uint64_t now = rdtsc();
        return (now - reconn_[ci].last_attempt_cycle < backoff_cycles);
    }

    // ========================================================================
    // Publish Control Events on MSG_METADATA
    // ========================================================================

    void publish_control_event(uint8_t ci, MetaEventType event_type) {
        auto* prod = msg_metadata_prod_[ci];
        int64_t seq = prod->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[TRANSPORT] WARNING: MSG_METADATA full for control event\n");
            return;
        }
        auto& meta = (*prod)[seq];
        meta.clear();
        meta.event_type = static_cast<uint8_t>(event_type);
        prod->publish(seq);
    }

    // ========================================================================
    // MsgMetadata Publishing (for data events)
    // ========================================================================

    void publish_metadata(MsgMetadataProd* prod, uint32_t write_offset, uint32_t len,
                          timing_record_t& timing, bool tls_record_end) {
        int64_t seq = prod->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: MSG_METADATA full\n");
            abort();
        }

        auto& meta = (*prod)[seq];
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
        meta.event_type = static_cast<uint8_t>(MetaEventType::DATA);
        prod->publish(seq);
        last_op_cycle_ = rdtscp();
    }

    // ========================================================================
    // SSL Read → MSG_INBOX (unified for single and AB connections)
    // ========================================================================

    int32_t process_ssl_read_for_conn(uint8_t ci, timing_record_t& timing) {
        auto& conn = get_transport(ci);
        auto* inbox = msg_inbox_[ci];
        auto* meta_prod = msg_metadata_prod_[ci];

        // Use modulo'd position — current_write_pos() grows monotonically past
        // MSG_INBOX_SIZE; raw subtraction underflows after the first buffer wrap,
        // causing SSL_read to overflow past the end of data[].
        uint32_t linear_space = inbox->linear_space_to_wrap();
        if (linear_space > 16384) linear_space = 16384;

        timing.recv_start_cycle = rdtsc();
        ssize_t read_len;
        if (conn.has_tls_record_keys()) {
            read_len = conn.ssl_read_by_chunk(
                inbox->write_ptr(), linear_space,
                [](const uint8_t*, size_t) {});
            if (read_len == -1) read_len = 0;
        } else {
            read_len = ssl_[ci].read(inbox->write_ptr(), linear_space);
        }
        timing.recv_end_cycle = rdtscp();

        if (read_len > 0) {
            timing.hw_timestamp_count = conn.get_recv_packet_count();
            if (timing.hw_timestamp_count > 0) {
                timing.hw_timestamp_oldest_ns = conn.get_recv_oldest_timestamp();
                timing.hw_timestamp_latest_ns = conn.get_recv_latest_timestamp();
                last_valid_ssl_start_cycle_ = timing.recv_start_cycle;
                last_valid_ssl_end_cycle_ = timing.recv_end_cycle;
            } else {
                timing.hw_timestamp_oldest_ns = 0;
                timing.hw_timestamp_latest_ns = 0;
            }
            timing.bpf_entry_oldest_ns = conn.get_recv_oldest_bpf_entry_ns();
            timing.bpf_entry_latest_ns = conn.get_recv_latest_bpf_entry_ns();
            timing.poll_cycle_oldest = conn.get_recv_oldest_poll_cycle();
            timing.poll_cycle_latest = conn.get_recv_latest_poll_cycle();
            timing.oldest_pkt_mem_idx = conn.get_recv_oldest_pkt_mem_idx();
            timing.latest_pkt_mem_idx = conn.get_recv_latest_pkt_mem_idx();

            uint32_t write_offset = inbox->current_write_pos();
            inbox->advance_write(static_cast<uint32_t>(read_len));

            bool tls_boundary = conn.has_tls_record_keys()
                                ? conn.tls_record_boundary() : false;
            publish_metadata(meta_prod, write_offset, static_cast<uint32_t>(read_len), timing, tls_boundary);

            conn.reset_recv_stats();
            ssl_read_count_++;
            return static_cast<int32_t>(read_len);

        } else if (read_len < 0) {
            if (!conn.has_tls_record_keys() && errno != EAGAIN) {
                fprintf(stderr, "[TRANSPORT] Read error (conn %u): %s\n", ci, strerror(errno));
                if (conn_state_) {
                    conn_state_->set_disconnect(DisconnectReason::SSL_READ_ERROR, 0, strerror(errno));
                }
                if constexpr (AutoReconnect) {
                    start_reconnect(ci);
                    return 0;
                }
                running_ = false;
                return -1;
            }
        }

        return 0;
    }

    // ========================================================================
    // SSL Read via wolfSSL (TLS_READY phase — before direct decrypt switch)
    // ========================================================================

    void process_ssl_read_wolfssl(uint8_t ci, timing_record_t& timing) {
        auto& conn = get_transport(ci);
        auto* inbox = msg_inbox_[ci];
        auto* meta_prod = msg_metadata_prod_[ci];

        uint32_t linear_space = inbox->linear_space_to_wrap();
        if (linear_space > 16384) linear_space = 16384;

        timing.recv_start_cycle = rdtsc();
        ssize_t read_len = ssl_[ci].read(inbox->write_ptr(), linear_space);
        timing.recv_end_cycle = rdtscp();

        if (read_len > 0) {
            timing.hw_timestamp_count = conn.get_recv_packet_count();
            if (timing.hw_timestamp_count > 0) {
                timing.hw_timestamp_oldest_ns = conn.get_recv_oldest_timestamp();
                timing.hw_timestamp_latest_ns = conn.get_recv_latest_timestamp();
                last_valid_ssl_start_cycle_ = timing.recv_start_cycle;
                last_valid_ssl_end_cycle_ = timing.recv_end_cycle;
            } else {
                timing.hw_timestamp_oldest_ns = 0;
                timing.hw_timestamp_latest_ns = 0;
            }
            timing.bpf_entry_oldest_ns = conn.get_recv_oldest_bpf_entry_ns();
            timing.bpf_entry_latest_ns = conn.get_recv_latest_bpf_entry_ns();
            timing.poll_cycle_oldest = conn.get_recv_oldest_poll_cycle();
            timing.poll_cycle_latest = conn.get_recv_latest_poll_cycle();
            timing.oldest_pkt_mem_idx = conn.get_recv_oldest_pkt_mem_idx();
            timing.latest_pkt_mem_idx = conn.get_recv_latest_pkt_mem_idx();

            uint32_t write_offset = inbox->current_write_pos();
            inbox->advance_write(static_cast<uint32_t>(read_len));

            // Publish as DATA event
            publish_metadata(meta_prod, write_offset, static_cast<uint32_t>(read_len), timing, false);

            conn.reset_recv_stats();
            ssl_read_count_++;
        }
    }

    // ========================================================================
    // Low-Priority Outbox Processing (PONGs, etc.)
    // ========================================================================

    int32_t process_low_prio_outbox() {
        int32_t count = 0;
        PongFrameAligned pong;
        while (low_prio_cons_->try_consume(pong)) {
            if (pong.data_len == 0) continue;

            uint8_t ci = EnableAB ? pong.connection_id : 0;

            // Skip if connection is not in a sendable state
            if constexpr (AutoReconnect) {
                if (reconn_[ci].phase != ConnPhase::ACTIVE &&
                    reconn_[ci].phase != ConnPhase::TLS_READY) {
                    continue;  // Drop: connection not ready
                }
            }

            size_t total_sent = 0;
            int retries = 0;
            static constexpr int MAX_WRITE_RETRIES = 50;  // 50 * 100us = 5ms max
            while (total_sent < pong.data_len) {
                transport_.poll();
                ssize_t sent = ssl_[ci].write(pong.data + total_sent, pong.data_len - total_sent);
                if (sent > 0) {
                    total_sent += sent;
                    retries = 0;
                } else if (sent < 0 && errno != EAGAIN) {
                    break;
                } else if (++retries >= MAX_WRITE_RETRIES) {
                    fprintf(stderr, "[TRANSPORT] Low-prio send stalled (conn %u, %zu/%u bytes)\n",
                            ci, total_sent, pong.data_len);
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

            uint8_t ci = EnableAB ? evt.connection_id : 0;

            // Skip if connection is not in a sendable state
            if constexpr (AutoReconnect) {
                if (reconn_[ci].phase != ConnPhase::ACTIVE &&
                    reconn_[ci].phase != ConnPhase::TLS_READY) {
                    continue;  // Drop: connection not ready
                }
            }

            size_t total_sent = 0;
            int retries = 0;
            static constexpr int MAX_WRITE_RETRIES = 50;
            while (total_sent < evt.data_len) {
                transport_.poll();
                ssize_t sent = ssl_[ci].write(evt.data + total_sent, evt.data_len - total_sent);
                if (sent > 0) {
                    total_sent += sent;
                    retries = 0;
                } else if (sent < 0 && errno != EAGAIN) {
                    break;
                } else if (++retries >= MAX_WRITE_RETRIES) {
                    fprintf(stderr, "[TRANSPORT] MSG_OUTBOX send stalled (conn %u, %zu/%u bytes)\n",
                            ci, total_sent, evt.data_len);
                    break;
                }
                usleep(100);
            }
            count++;
        }
        return count;
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
    static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;
    MsgInbox* msg_inbox_[NUM_CONN]{};
    MsgMetadataProd* msg_metadata_prod_[NUM_CONN]{};
    LowPrioCons* low_prio_cons_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;

    // Transport and SSL
    TransportType transport_;
    SSLPolicy ssl_[NUM_CONN]{};

    // Reconnect state machine (per-connection)
    ReconnectCtx reconn_[NUM_CONN]{};
    bool tls_ready_signaled_ = false;  // First TLS_CONNECTED → set_handshake_tls_ready()

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

    // Reconnect backoff constants
    static constexpr uint32_t RECONNECT_BACKOFF_BASE_MS = 1000;   // 1s initial
    static constexpr uint32_t RECONNECT_BACKOFF_MAX_MS  = 30000;  // 30s cap

    // Counters
    uint64_t ssl_read_count_ = 0;
    uint64_t low_prio_tx_count_ = 0;
};

}  // namespace websocket::pipeline
