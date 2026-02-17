// pipeline/21_ws_core.hpp
// WSCore - Extracted WebSocket processing engine
//
// Contains all WS frame parsing, HTTP upgrade handshake, ping/pong,
// and watchdog logic. Decoupled from IPC ring input (caller drives via feed())
// and TX output (via TXSink concept).
//
// Two modes:
//   1. IPC mode (IPCTXSink): WebSocketProcess polls metadata ring → feed()
//   2. Inline mode (DirectTXSink): Transport calls feed() directly after decrypt
//
// C++20, policy-based design
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <array>
#include <concepts>

#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"
#include "20_ws_process.hpp"
#include "../core/http.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// TXSink Concept — zero-copy claim/publish pattern
//
// The caller claims a writable buffer, builds directly into it, then publishes.
// For IPC mode this writes directly into the ring slot (zero-copy).
// For direct mode this writes into a local buffer then sends via ssl_.write().
// ============================================================================

template<typename T>
concept TXSinkConcept = requires(T& t, uint8_t ci, size_t len) {
    { t.outbox_claim(ci) } -> std::same_as<uint8_t*>;
    { t.outbox_publish(len) };
    { t.pong_claim(ci) } -> std::same_as<uint8_t*>;
    { t.pong_publish(len) };
};

// ============================================================================
// IPCTXSink — for existing multi-process mode (zero-copy into ring slot)
// ============================================================================

template<typename MsgOutboxProd, typename PongsProd>
struct IPCTXSink {
    MsgOutboxProd* msg_outbox_prod_ = nullptr;
    PongsProd* pongs_prod_ = nullptr;
    int64_t outbox_seq_ = -1;
    int64_t pong_seq_ = -1;

    uint8_t* outbox_claim(uint8_t ci) {
        outbox_seq_ = msg_outbox_prod_->try_claim();
        if (outbox_seq_ < 0) return nullptr;
        auto& event = (*msg_outbox_prod_)[outbox_seq_];
        event.connection_id = ci;
        event.msg_type = MSG_TYPE_DATA;
        return event.data;
    }

    void outbox_publish(size_t len) {
        (*msg_outbox_prod_)[outbox_seq_].data_len = static_cast<uint16_t>(len);
        msg_outbox_prod_->publish(outbox_seq_);
    }

    uint8_t* pong_claim(uint8_t ci) {
        pong_seq_ = pongs_prod_->try_claim();
        if (pong_seq_ < 0) return nullptr;
        auto& pong = (*pongs_prod_)[pong_seq_];
        pong.clear();
        pong.connection_id = ci;
        return pong.data;
    }

    void pong_publish(size_t len) {
        (*pongs_prod_)[pong_seq_].data_len = static_cast<uint8_t>(len);
        pongs_prod_->publish(pong_seq_);
    }
};

// ============================================================================
// DirectTXSink — for inline mode (local buffer → ssl_.write())
// ============================================================================

template<typename SSLPolicy, bool EnableAB>
struct DirectTXSink {
    static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;
    SSLPolicy* ssl_ = nullptr;   // points to transport's ssl_[NUM_CONN] array
    uint8_t outbox_buf_[4096];
    uint8_t pong_buf_[131];      // PONG/PING frames (max 125 payload + 6 header)
    uint8_t pending_ci_ = 0;

    uint8_t* outbox_claim(uint8_t ci) { pending_ci_ = ci; return outbox_buf_; }
    void outbox_publish(size_t len) { ssl_[pending_ci_].write(outbox_buf_, len); }

    uint8_t* pong_claim(uint8_t ci) { pending_ci_ = ci; return pong_buf_; }
    void pong_publish(size_t len) { ssl_[pending_ci_].write(pong_buf_, len); }
};

// ============================================================================
// WSCore - WebSocket processing engine
//
// Template parameters:
//   TXSink         — IPCTXSink or DirectTXSink
//   WSFrameInfoProd — IPCRingProducer<WSFrameInfo> (for output to parent)
//   EnableAB        — dual A/B connections
//   AutoReconnect   — event-driven handshake
//   Profiling       — compile-time profiling gates
//   AppHandler      — inline callback (replaces WSFrameInfo ring when enabled)
//   UpgradeCustomizer — custom HTTP headers for upgrade request
// ============================================================================

template<typename TXSink,
         typename WSFrameInfoProd,
         bool EnableAB, bool AutoReconnect, bool Profiling,
         AppHandlerConcept AppHandler,
         UpgradeCustomizerConcept UpgradeCustomizer>
struct WSCore {
public:
    static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;
    static constexpr bool HasAppHandler = AppHandler::enabled;

    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(MsgInbox* msg_inbox,
              WSFrameInfoProd* ws_frame_info_prod,
              TXSink* tx_sink,
              ConnStateShm* conn_state,
              MsgInbox* msg_inbox_b = nullptr) {

        msg_inbox_[0] = msg_inbox;
        if constexpr (!HasAppHandler) {
            ws_frame_info_prod_ = ws_frame_info_prod;
        }
        tx_sink_ = tx_sink;
        conn_state_ = conn_state;

        if constexpr (EnableAB) {
            msg_inbox_[1] = msg_inbox_b;
        }

        for (size_t i = 0; i < NUM_CONN; i++) {
            pending_frame_[i].clear();
            has_pending_frame_[i] = false;
            reset_accumulator(i);
            reset_fragment_state(i);
            has_pending_ping_[i] = false;

            if constexpr (AutoReconnect) {
                ws_phase_[i] = WsConnPhase::DISCONNECTED;
                http_response_[i].clear();
            } else {
                ws_phase_[i] = WsConnPhase::ACTIVE;
            }
        }

        printf("[WS-CORE] Initialized%s%s\n",
               EnableAB ? " (Dual A/B)" : "",
               AutoReconnect ? " (AutoReconnect)" : "");
        return true;
    }

    // ========================================================================
    // Main Entry Point — processes one metadata event
    // ========================================================================

    void feed(uint8_t ci, MsgMetadata& meta) {
        auto event_type = static_cast<MetaEventType>(meta.event_type);

        // ── Control events: TCP_DISCONNECTED and TLS_CONNECTED ──
        if constexpr (AutoReconnect) {
            if (event_type == MetaEventType::TCP_DISCONNECTED) {
                on_tcp_disconnected(ci);
                return;
            }
            if (event_type == MetaEventType::TLS_CONNECTED) {
                on_tls_connected(ci);
                return;
            }
        }

        // ── DATA events ──

        // DISCONNECTED: drain stale data (prevents ring backup)
        if constexpr (AutoReconnect) {
            if (ws_phase_[ci] == WsConnPhase::DISCONNECTED) {
                return;
            }
        }

        // WS_UPGRADE_SENT: accumulate HTTP response bytes
        if constexpr (AutoReconnect) {
            if (ws_phase_[ci] == WsConnPhase::WS_UPGRADE_SENT) {
                on_http_response_data(ci, meta);
                return;
            }
        }

        // ACTIVE: normal WS frame parsing
        on_ws_data(ci, meta);
    }

    // ========================================================================
    // Idle Tick — ping/pong/watchdog for all connections
    // ========================================================================

    void idle_tick() {
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            if (has_pending_ping_[ci]) {
                flush_pending_pong(static_cast<uint8_t>(ci));
            }
        }
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            if (ws_phase_[ci] == WsConnPhase::ACTIVE) {
                maybe_send_client_ping(static_cast<uint8_t>(ci));
            }
        }
        check_dual_dead();
        check_upgrade_timeout();
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    AppHandler& app_handler() { return app_handler_; }
    WsConnPhase ws_phase(uint8_t ci) const { return ws_phase_[ci]; }

    // ========================================================================
    // AutoReconnect State Machine Handlers
    // ========================================================================

    void on_tcp_disconnected(uint8_t ci) {
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] TCP_DISCONNECTED for conn %u\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);

        ws_phase_[ci] = WsConnPhase::DISCONNECTED;

        // Reset per-connection parse state
        parse_state_[ci] = PerConnParseState{};
        has_pending_frame_[ci] = false;
        pending_frame_[ci].clear();
        has_pending_ping_[ci] = false;
        reset_accumulator(ci);
        reset_fragment_state(ci);
        http_response_[ci].clear();

        // Reset watchdog for this connection
        reset_watchdog_state(ci);
    }

    void on_tls_connected(uint8_t ci) {
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] TLS_CONNECTED for conn %u, sending HTTP upgrade\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);

        // Send HTTP upgrade request via TXSink
        send_http_upgrade_request(ci);
        ws_phase_[ci] = WsConnPhase::WS_UPGRADE_SENT;
        upgrade_sent_cycle_[ci] = rdtscp();
        http_response_[ci].clear();
    }

private:
    // ========================================================================
    // Handshake Helpers
    // ========================================================================

    void send_http_upgrade_request(uint8_t ci) {
        char request_buf[4096];
        std::vector<std::pair<std::string, std::string>> custom_headers;
        UpgradeCustomizer::customize(conn_state_, custom_headers);

        size_t request_len = websocket::http::build_websocket_upgrade_request(
            conn_state_->target_host,
            conn_state_->target_path,
            custom_headers,
            request_buf,
            sizeof(request_buf)
        );

        // Publish via TXSink
        uint8_t* buf = tx_sink_->outbox_claim(ci);
        if (!buf) {
            fprintf(stderr, "[WS-CORE] FATAL: TX outbox full during handshake\n");
            std::abort();
        }
        std::memcpy(buf, request_buf, request_len);
        tx_sink_->outbox_publish(request_len);
    }

    void send_subscription_message(uint8_t ci) {
        const char* json = conn_state_->subscription_json;
        size_t json_len = std::strlen(json);

        if (json_len == 0) {
            printf("[WS-CORE] No subscription message configured\n");
            return;
        }

        // Build complete WS TEXT frame via TXSink
        uint8_t* buf = tx_sink_->outbox_claim(ci);
        if (!buf) {
            fprintf(stderr, "[WS-CORE] FATAL: TX outbox full during subscription\n");
            std::abort();
        }

        uint8_t mask_key[4] = {0, 0, 0, 0};
        size_t frame_len = websocket::http::build_websocket_frame(
            reinterpret_cast<const uint8_t*>(json),
            json_len,
            buf,
            4096,  // outbox_claim buffer size
            mask_key,
            static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT)
        );

        tx_sink_->outbox_publish(frame_len);
        printf("[WS-CORE] Subscription sent (conn %u, %zu bytes)\n", ci, json_len);
    }

    // ========================================================================
    // HTTP Response Accumulation (AutoReconnect handshake)
    // ========================================================================

    void on_http_response_data(uint8_t ci, MsgMetadata& meta) {
        if (meta.decrypted_len == 0) return;

        auto& resp = http_response_[ci];
        size_t prev_accumulated = resp.accumulated;
        const uint8_t* data = msg_inbox_[ci]->data_at(meta.msg_inbox_offset);
        size_t to_copy = std::min(static_cast<size_t>(meta.decrypted_len),
                                  sizeof(resp.buffer) - resp.accumulated);
        std::memcpy(resp.buffer + resp.accumulated, data, to_copy);
        resp.accumulated += to_copy;

        if (!resp.try_complete()) {
            return;
        }

        // HTTP headers complete — validate 101
        bool upgrade_ok = websocket::http::validate_http_upgrade_response(
            resp.buffer, resp.accumulated);

        if (!upgrade_ok) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] HTTP upgrade failed for conn %u, requesting reconnect\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            ws_phase_[ci] = WsConnPhase::DISCONNECTED;
            conn_state_->set_reconnect_request(ci);
            return;
        }

        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] HTTP 101 received for conn %u, sending subscription\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);

        // Send subscription message
        send_subscription_message(ci);

        // Signal Transport to switch to direct AES-CTR decrypt
        conn_state_->set_ws_handshake_done(ci);

        // Transition to ACTIVE
        ws_phase_[ci] = WsConnPhase::ACTIVE;

        // Reset parse state for clean start
        parse_state_[ci] = PerConnParseState{};
        has_pending_frame_[ci] = false;
        pending_frame_[ci].clear();

        // Reset dual-dead baseline
        last_data_cycle_[ci] = 0;

        // Reset + resume watchdog for this connection
        reset_watchdog_state(ci);

        // Signal ws_ready on first successful handshake
        if (!ws_ready_signaled_) {
            bool all_active = true;
            for (size_t i = 0; i < NUM_CONN; i++) {
                if (ws_phase_[i] != WsConnPhase::ACTIVE) {
                    all_active = false;
                    break;
                }
            }
            if (all_active) {
                conn_state_->set_handshake_ws_ready();
                ws_ready_signaled_ = true;
                fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] All connections ACTIVE, ws_ready signaled\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000);
            }
        }

        fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] Connection %u fully restored\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);

        // Forward leftover WS bytes
        size_t http_bytes_in_this_meta = resp.headers_end > prev_accumulated
            ? (resp.headers_end - prev_accumulated)
            : 0;
        if (http_bytes_in_this_meta < to_copy) {
            size_t ws_bytes = to_copy - http_bytes_in_this_meta;
            MsgMetadata ws_meta = meta;
            ws_meta.msg_inbox_offset = (meta.msg_inbox_offset +
                static_cast<uint32_t>(http_bytes_in_this_meta)) % MSG_INBOX_SIZE;
            ws_meta.decrypted_len = static_cast<uint32_t>(ws_bytes);
            on_ws_data(ci, ws_meta);
        }
    }

    // ========================================================================
    // Normal WS Frame Parsing (ws_phase == ACTIVE)
    // ========================================================================

    void on_ws_data(uint8_t ci, MsgMetadata& meta) {
        last_data_cycle_[ci] = rdtscp();
        auto& ps = parse_state_[ci];
        auto* inbox = msg_inbox_[ci];

        __builtin_prefetch(inbox->data_at(meta.msg_inbox_offset), 0, 3);
        __builtin_prefetch(inbox->data_at(meta.msg_inbox_offset) + 64, 0, 3);

        if (!has_pending_frame_[ci]) {
            ps.data_start_offset = meta.msg_inbox_offset;
            ps.data_accumulated = 0;
            ps.parse_offset = 0;
            ps.accumulated_metadata_count = 0;
            ps.has_carry_over = false;
            ps.batch_frame_num = 0;
        }

        ps.data_accumulated += meta.decrypted_len;

        if (ps.accumulated_metadata_count < MAX_ACCUMULATED_METADATA) {
            ps.accumulated_metadata[ps.accumulated_metadata_count++] = meta;
        }

        ps.current_metadata = meta;

        while (ps.parse_offset < ps.data_accumulated) {
            uint32_t offset = (ps.data_start_offset + ps.parse_offset) % MSG_INBOX_SIZE;
            const uint8_t* data = inbox->data_at(offset);
            size_t available = ps.data_accumulated - ps.parse_offset;

            size_t linear_avail = std::min(available, static_cast<size_t>(MSG_INBOX_SIZE - offset));

            if (linear_avail < available && linear_avail < sizeof(ps.ws_header_wrap_buffer)) {
                size_t first_part = MSG_INBOX_SIZE - offset;
                size_t second_part = std::min(available - first_part,
                                              sizeof(ps.ws_header_wrap_buffer) - first_part);
                std::memcpy(ps.ws_header_wrap_buffer, data, first_part);
                std::memcpy(ps.ws_header_wrap_buffer + first_part, inbox->data_at(0), second_part);
                data = ps.ws_header_wrap_buffer;
                linear_avail = first_part + second_part;
            }

            size_t consumed = 0;
            bool frame_complete = false;

            if (has_pending_frame_[ci]) {
                consumed = continue_partial_frame(pending_frame_[ci], data, linear_avail);

                if (!pending_frame_[ci].header_complete) {
                    ps.parse_offset += consumed;
                    return;
                }

                size_t available_for_payload = linear_avail - consumed;
                uint64_t payload_remaining = pending_frame_[ci].payload_len - pending_frame_[ci].payload_bytes_received;
                size_t payload_in_chunk = std::min(available_for_payload, static_cast<size_t>(payload_remaining));
                pending_frame_[ci].payload_bytes_received += payload_in_chunk;
                consumed += payload_in_chunk;

                uint64_t total_needed = pending_frame_[ci].expected_header_len + pending_frame_[ci].payload_len;
                uint64_t total_received = pending_frame_[ci].header_bytes_received + pending_frame_[ci].payload_bytes_received;

                if (total_received < total_needed) {
                    publish_partial_frame_info(ci);
                    ps.parse_offset += consumed;
                    return;
                }

                frame_complete = true;
            } else {
                ps.frame_start_parse_offset = ps.parse_offset;
                consumed = start_parse_frame(pending_frame_[ci], data, linear_avail);
                has_pending_frame_[ci] = true;

                if (!pending_frame_[ci].header_complete) {
                    ps.parse_offset += consumed;
                    return;
                }

                uint64_t total_needed = pending_frame_[ci].expected_header_len + pending_frame_[ci].payload_len;
                size_t total_available = consumed + (linear_avail - consumed);

                if (total_available < total_needed) {
                    size_t payload_in_this_chunk = linear_avail - pending_frame_[ci].expected_header_len;
                    pending_frame_[ci].payload_bytes_received = payload_in_this_chunk;

                    publish_partial_frame_info(ci);
                    ps.parse_offset += linear_avail;
                    return;
                }

                pending_frame_[ci].payload_bytes_received = pending_frame_[ci].payload_len;
                frame_complete = true;
                consumed = pending_frame_[ci].expected_header_len + pending_frame_[ci].payload_len;
            }

            if (frame_complete) {
                ps.current_payload_offset = (ps.data_start_offset + ps.frame_start_parse_offset +
                                            pending_frame_[ci].expected_header_len) % MSG_INBOX_SIZE;

                if (ps.accumulated_metadata_count > 0) {
                    ps.first_packet_metadata = ps.accumulated_metadata[0];
                }

                bool is_last_in_data = (ps.parse_offset + consumed >= ps.data_accumulated);
                ps.pending_tls_record_end = is_last_in_data && ps.current_metadata.tls_record_end;

                handle_complete_frame(ci);

                ps.parse_offset += consumed;
                has_pending_frame_[ci] = false;
                pending_frame_[ci].clear();

                ps.accumulated_metadata_count = 0;
                ps.has_carry_over = false;
                if (ps.parse_offset < ps.data_accumulated) {
                    ps.accumulated_metadata[ps.accumulated_metadata_count++] = ps.current_metadata;
                    ps.has_carry_over = true;
                }
            }
        }

        ps.data_accumulated = 0;
        ps.parse_offset = 0;
    }

    // ========================================================================
    // Partial Frame WSFrameInfo
    // ========================================================================

    void publish_partial_frame_info(uint8_t ci) {
        if constexpr (HasAppHandler) return;

        auto& ps = parse_state_[ci];

        int64_t seq = ws_frame_info_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-CORE] FATAL: WS_FRAME_INFO full\n");
            std::abort();
        }

        auto& info = (*ws_frame_info_prod_)[seq];
        info.clear();

        info.msg_inbox_offset = (ps.data_start_offset + ps.frame_start_parse_offset +
                               pending_frame_[ci].expected_header_len) % MSG_INBOX_SIZE;
        info.payload_len = static_cast<uint32_t>(pending_frame_[ci].payload_bytes_received);
        info.opcode = pending_frame_[ci].opcode;
        info.set_fin(pending_frame_[ci].fin);
        info.set_fragmented(true);
        info.set_last_fragment(false);
        info.connection_id = ci;

        populate_timestamps(info, ps);
        info.set_tls_record_end(false);
        info.ws_parse_cycle = rdtscp();

        info.ws_frame_publish_cycle = rdtscp();
        {
            struct timespec _ts;
            clock_gettime(CLOCK_MONOTONIC, &_ts);
            info.publish_time_ts = _ts.tv_sec * 1000000000ULL + _ts.tv_nsec;
        }
        ws_frame_info_prod_->publish(seq);
    }

    // ========================================================================
    // Complete Frame Handling
    // ========================================================================

    void handle_complete_frame(uint8_t ci) {
        auto& ps = parse_state_[ci];
        uint64_t parse_cycle = rdtscp();

        uint8_t opcode = pending_frame_[ci].opcode;
        bool fin = pending_frame_[ci].fin;
        uint64_t payload_len = pending_frame_[ci].payload_len;
        uint32_t frame_total_len = pending_frame_[ci].expected_header_len +
                                   static_cast<uint32_t>(payload_len);

        switch (opcode) {
            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT):
            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::BINARY):
                handle_data_frame(ci, opcode, fin, payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::CONTINUATION):
                handle_continuation_frame(ci, fin, payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::PING):
                handle_ping(ci, payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::PONG):
                handle_pong(ci, payload_len);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::CLOSE):
                handle_close(ci, payload_len);
                break;

            default:
                fprintf(stderr, "[WS-CORE] Unknown opcode: 0x%02X (conn %u)\n", opcode, ci);
                break;
        }
    }

    void handle_data_frame(uint8_t ci, uint8_t opcode, bool fin, uint64_t payload_len,
                          uint32_t frame_total_len, uint64_t parse_cycle) {
        auto& ps = parse_state_[ci];
        if (fin) {
            publish_frame_info(ci, opcode, payload_len, frame_total_len, parse_cycle,
                              false, false);
        } else {
            ps.accumulating_fragments = true;
            ps.fragment_opcode = opcode;
            ps.fragment_start_offset = ps.current_payload_offset;
            ps.fragment_total_len = static_cast<uint32_t>(payload_len);
            ps.fragment_total_frame_len = frame_total_len;
            ps.fragment_first_metadata = ps.first_packet_metadata;

            publish_frame_info(ci, opcode, payload_len, frame_total_len, parse_cycle,
                              true, false);
        }
    }

    void handle_continuation_frame(uint8_t ci, bool fin, uint64_t payload_len,
                                   uint32_t frame_total_len, uint64_t parse_cycle) {
        auto& ps = parse_state_[ci];
        if (!ps.accumulating_fragments) {
            fprintf(stderr, "[WS-CORE] Unexpected continuation frame (conn %u)\n", ci);
            return;
        }

        ps.fragment_total_len += static_cast<uint32_t>(payload_len);
        ps.fragment_total_frame_len += frame_total_len;

        if (!fin) {
            publish_frame_info(ci, ps.fragment_opcode, payload_len, frame_total_len, parse_cycle,
                              true, false);
        } else {
            publish_frame_info(ci, ps.fragment_opcode, payload_len, frame_total_len, parse_cycle,
                              true, true);
            reset_fragment_state(ci);
        }
    }

    void flush_pending_pong(uint8_t ci) {
        if (!has_pending_ping_[ci]) return;

        if constexpr (AutoReconnect) {
            if (ws_phase_[ci] != WsConnPhase::ACTIVE) {
                has_pending_ping_[ci] = false;
                return;
            }
        }

        const uint8_t* ping_payload = msg_inbox_[ci]->data_at(pending_ping_[ci].payload_offset);
        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};

        size_t safe_payload_len = pending_ping_[ci].payload_len;
        if (safe_payload_len > 119) {
            safe_payload_len = 119;
        }

        uint8_t* buf = tx_sink_->pong_claim(ci);
        if (!buf) {
            fprintf(stderr, "[WS-CORE] FATAL: TX pong full\n");
            std::abort();
        }

        size_t pong_len = websocket::http::build_pong_frame(
            ping_payload, safe_payload_len, buf, mask_key);
        tx_sink_->pong_publish(pong_len);

        {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            char payload_str[128] = {0};
            size_t plen = std::min(static_cast<size_t>(pending_ping_[ci].payload_len),
                                   sizeof(payload_str) - 1);
            if (plen > 0)
                std::memcpy(payload_str, ping_payload, plen);
            fprintf(stderr, "[%ld.%06ld] [WS-PONG-TX] Sent PONG reply (conn %u) len=%u payload=\"%s\"\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, pending_ping_[ci].payload_len, payload_str);
        }

        has_pending_ping_[ci] = false;
    }

    void handle_ping(uint8_t ci, uint64_t payload_len, [[maybe_unused]] uint32_t frame_total_len, uint64_t parse_cycle) {
        auto& ps = parse_state_[ci];
        {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            char payload_str[128] = {0};
            size_t plen = std::min(payload_len, static_cast<uint64_t>(sizeof(payload_str) - 1));
            if (plen > 0)
                std::memcpy(payload_str, msg_inbox_[ci]->data_at(ps.current_payload_offset), plen);
            fprintf(stderr, "[%ld.%06ld] [WS-PING] Received server PING (conn %u) len=%lu payload=\"%s\"\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, (unsigned long)payload_len, payload_str);
        }

        // Server PING interval learning
        {
            auto& w = wd_[ci];
            uint64_t now_cycle = rdtscp();
            w.last_server_ping_cycle = now_cycle;

            uint32_t idx = w.server_ping_count;
            if (idx < WatchdogState::PING_LEARN_SAMPLES) {
                w.server_ping_cycles[idx] = now_cycle;
            }
            w.server_ping_count++;

            if (w.server_ping_count >= 2) {
                uint32_t n = std::min(w.server_ping_count, WatchdogState::PING_LEARN_SAMPLES);
                uint64_t total_delta = w.server_ping_cycles[n - 1] - w.server_ping_cycles[0];
                uint64_t avg_delta = total_delta / (n - 1);
                w.learned_interval_cycles = avg_delta;

                uint64_t tsc_freq = conn_state_->tsc_freq_hz;
                uint64_t avg_ms = (avg_delta * 1000ULL) / tsc_freq;
                w.learned_interval_ms = ((avg_ms + 50) / 100) * 100;

                if (w.server_ping_count <= WatchdogState::PING_LEARN_SAMPLES) {
                    fprintf(stderr, "[WS-WATCHDOG] Server PING interval (conn %u): %lums "
                            "(avg %lums, %u/%u samples)\n",
                            ci, (unsigned long)w.learned_interval_ms,
                            (unsigned long)avg_ms, n, WatchdogState::PING_LEARN_SAMPLES);
                }
            }
        }

        // Publish WSFrameInfo for PING
        if constexpr (!HasAppHandler) {
            int64_t ws_seq = ws_frame_info_prod_->try_claim();
            if (ws_seq < 0) {
                fprintf(stderr, "[WS-CORE] FATAL: WS_FRAME_INFO full\n");
                std::abort();
            }

            auto& info = (*ws_frame_info_prod_)[ws_seq];
            info.clear();

            info.msg_inbox_offset = ps.current_payload_offset;
            info.payload_len = static_cast<uint32_t>(payload_len);
            info.opcode = static_cast<uint8_t>(websocket::http::WebSocketOpcode::PING);
            info.set_fin(true);
            info.set_fragmented(false);
            info.set_last_fragment(false);
            info.connection_id = ci;

            populate_timestamps(info, ps);
            info.ws_parse_cycle = parse_cycle;

            info.ws_frame_publish_cycle = rdtscp();
            {
                struct timespec _ts;
                clock_gettime(CLOCK_MONOTONIC, &_ts);
                info.publish_time_ts = _ts.tv_sec * 1000000000ULL + _ts.tv_nsec;
            }
            ws_frame_info_prod_->publish(ws_seq);
        }

        if (has_pending_ping_[ci]) {
            flush_pending_pong(ci);
        }

        pending_ping_[ci].payload_offset = ps.current_payload_offset;
        pending_ping_[ci].payload_len = static_cast<uint16_t>(payload_len);
        has_pending_ping_[ci] = true;
    }

    void handle_close(uint8_t ci, uint64_t payload_len) {
        auto& ps = parse_state_[ci];
        uint16_t close_code = 1005;
        const uint8_t* payload = nullptr;

        if (payload_len >= 2) {
            payload = msg_inbox_[ci]->data_at(ps.current_payload_offset);
            close_code = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
        }

        if (close_code != 1005 && (close_code < 1000 || close_code > 4999)) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [WS-PARSE-ERROR] Spurious CLOSE "
                    "(conn %u, code=%u) — frame parse desync, requesting reconnect\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, close_code);
            if constexpr (AutoReconnect) {
                conn_state_->set_reconnect_request(ci);
            } else {
                conn_state_->set_disconnect(DisconnectReason::WS_CLOSE, close_code, "parse_desync");
                conn_state_->shutdown_all();
            }
            return;
        }

        char close_reason[128] = {0};
        if (payload_len > 2 && payload != nullptr) {
            size_t reason_len = std::min(payload_len - 2, static_cast<uint64_t>(sizeof(close_reason) - 1));
            std::memcpy(close_reason, payload + 2, reason_len);
            close_reason[reason_len] = '\0';
        }

        if constexpr (AutoReconnect) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [WS-CLOSE] Received CLOSE (conn %u, code=%u, reason=%s) — requesting reconnect\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, close_code, close_reason);
            conn_state_->set_reconnect_request(ci);
        } else {
            conn_state_->set_disconnect(DisconnectReason::WS_CLOSE, close_code, close_reason);
            conn_state_->shutdown_all();
        }
    }

    void handle_pong(uint8_t ci, uint64_t payload_len) {
        auto& ps = parse_state_[ci];

        wd_[ci].last_pong_recv_cycle = rdtscp();

        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        char payload_str[128] = {0};
        size_t plen = std::min(payload_len, static_cast<uint64_t>(sizeof(payload_str) - 1));
        if (plen > 0) {
            std::memcpy(payload_str, msg_inbox_[ci]->data_at(ps.current_payload_offset), plen);
        }

        bool is_ts = (plen >= 12 && plen <= 14);
        for (size_t i = 0; is_ts && i < plen; i++)
            is_ts = (payload_str[i] >= '0' && payload_str[i] <= '9');

        if (is_ts) {
            int64_t ping_ms = 0;
            for (size_t i = 0; i < plen; i++)
                ping_ms = ping_ms * 10 + (payload_str[i] - '0');
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            int64_t rtt_ms = now_ms - ping_ms;
            fprintf(stderr, "[%ld.%06ld] [WS-PONG] Received PONG (conn %u) payload=\"%s\" RTT=%ldms\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, payload_str, rtt_ms);
        } else {
            fprintf(stderr, "[%ld.%06ld] [WS-PONG] Received PONG (conn %u) len=%lu payload=\"%s\"\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci, (unsigned long)payload_len, payload_str);
        }
    }

    void maybe_send_client_ping(uint8_t ci) {
        auto& w = wd_[ci];
        uint64_t now_cycle = rdtscp();
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;

        if (w.last_client_ping_cycle == 0) {
            w.last_client_ping_cycle = now_cycle;
            w.last_pong_recv_cycle = now_cycle;
            return;
        }

        if ((now_cycle - w.last_client_ping_cycle) < tsc_freq) return;

        bool interval_learned = (w.server_ping_count >= 2 && w.learned_interval_cycles > 0);
        uint64_t pong_timeout_cycles = interval_learned
            ? w.learned_interval_cycles
            : (DEFAULT_PONG_TIMEOUT_MS * tsc_freq) / 1000;

        uint64_t since_last_pong = now_cycle - w.last_pong_recv_cycle;
        bool server_pong_missing = (since_last_pong > pong_timeout_cycles);

        bool server_ping_missing = false;
        if (interval_learned && w.last_server_ping_cycle > 0) {
            uint64_t since_last_ping = now_cycle - w.last_server_ping_cycle;
            uint64_t threshold = w.learned_interval_cycles + (w.learned_interval_cycles / 2);
            server_ping_missing = (since_last_ping > threshold);
        }

        bool should_reconnect = interval_learned
            ? (server_pong_missing && server_ping_missing)
            : server_pong_missing;

        if (should_reconnect) {
            trigger_watchdog_reconnect(ci, now_cycle, tsc_freq);
            ws_phase_[ci] = WsConnPhase::DISCONNECTED;
            return;
        }

        // Send client PING via TXSink
        auto now = std::chrono::system_clock::now();
        int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        char payload_ascii[16];
        int payload_len = snprintf(payload_ascii, sizeof(payload_ascii), "%ld", unix_ms);

        uint8_t* buf = tx_sink_->pong_claim(ci);
        if (!buf) return;  // Full, retry next second

        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};
        size_t frame_len = websocket::http::build_ping_frame(
            reinterpret_cast<const uint8_t*>(payload_ascii),
            static_cast<size_t>(payload_len), buf, mask_key);
        tx_sink_->pong_publish(frame_len);

        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-CLIENT-PING] Sent PING (conn %u) payload=\"%s\"\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci, payload_ascii);

        w.last_client_ping_cycle = now_cycle;
    }

    void publish_frame_info(uint8_t ci, uint8_t opcode, uint64_t payload_len,
                           [[maybe_unused]] uint32_t frame_total_len,
                           uint64_t parse_cycle, bool is_fragmented, bool is_last_fragment) {
        auto& ps = parse_state_[ci];

        if constexpr (HasAppHandler) {
            WSFrameInfo info{};
            info.clear();
            info.msg_inbox_offset = ps.current_payload_offset;
            info.payload_len = static_cast<uint32_t>(payload_len);
            info.opcode = opcode;
            info.set_fin(!is_fragmented || is_last_fragment);
            info.set_fragmented(is_fragmented);
            info.set_last_fragment(is_last_fragment);
            info.connection_id = ci;
            populate_timestamps(info, ps);
            info.set_tls_record_end(ps.pending_tls_record_end);
            info.ws_parse_cycle = parse_cycle;
            info.ws_frame_publish_cycle = rdtscp();
            {
                struct timespec _ts;
                clock_gettime(CLOCK_MONOTONIC, &_ts);
                info.publish_time_ts = _ts.tv_sec * 1000000000ULL + _ts.tv_nsec;
            }

            if (opcode == 0x01 || opcode == 0x02) {
                if (!is_fragmented || is_last_fragment) {
                    const uint8_t* payload = msg_inbox_[ci]->data_at(info.msg_inbox_offset);
                    app_handler_.on_ws_frame(ci, opcode, payload,
                                             static_cast<uint32_t>(payload_len), info);
                }
            }
        } else {
            int64_t seq = ws_frame_info_prod_->try_claim();
            if (seq < 0) {
                fprintf(stderr, "[WS-CORE] FATAL: WS_FRAME_INFO full\n");
                std::abort();
            }

            auto& info = (*ws_frame_info_prod_)[seq];
            info.clear();

            info.msg_inbox_offset = ps.current_payload_offset;
            info.payload_len = static_cast<uint32_t>(payload_len);
            info.opcode = opcode;
            info.set_fin(!is_fragmented || is_last_fragment);
            info.set_fragmented(is_fragmented);
            info.set_last_fragment(is_last_fragment);
            info.connection_id = ci;

            populate_timestamps(info, ps);
            info.set_tls_record_end(ps.pending_tls_record_end);
            info.ws_parse_cycle = parse_cycle;

            info.ws_frame_publish_cycle = rdtscp();
            {
                struct timespec _ts;
                clock_gettime(CLOCK_MONOTONIC, &_ts);
                info.publish_time_ts = _ts.tv_sec * 1000000000ULL + _ts.tv_nsec;
            }
            ws_frame_info_prod_->publish(seq);
        }

        reset_accumulator(ci);
    }

    // ========================================================================
    // Watchdog Helpers
    // ========================================================================

    void trigger_watchdog_reconnect(uint8_t ci, uint64_t now_cycle, uint64_t tsc_freq) {
        auto& w = wd_[ci];
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        uint64_t pong_gap_ms = ((now_cycle - w.last_pong_recv_cycle) * 1000ULL) / tsc_freq;
        uint64_t ping_gap_ms = (w.last_server_ping_cycle > 0)
            ? ((now_cycle - w.last_server_ping_cycle) * 1000ULL) / tsc_freq : 0;
        bool interval_learned = (w.server_ping_count >= 2 && w.learned_interval_cycles > 0);

        uint64_t data_gap_ms = (last_data_cycle_[ci] > 0)
            ? ((now_cycle - last_data_cycle_[ci]) * 1000ULL) / tsc_freq : 0;

        uint8_t other = 1 - ci;
        uint64_t other_data_gap_ms = 0;
        const char* other_phase = "N/A";
        if constexpr (EnableAB) {
            if (last_data_cycle_[other] > 0)
                other_data_gap_ms = ((now_cycle - last_data_cycle_[other]) * 1000ULL) / tsc_freq;
            other_phase = (ws_phase_[other] == WsConnPhase::ACTIVE) ? "ACTIVE" :
                          (ws_phase_[other] == WsConnPhase::DISCONNECTED) ? "DISCONNECTED" :
                          "WS_UPGRADE_SENT";
        }

        fprintf(stderr, "[%ld.%06ld] [WS-WATCHDOG] %s: conn %u dead\n"
                "  PONG missing: last %lums ago (threshold %lums)\n"
                "  server PING missing: last %lums ago (threshold %lums)\n"
                "  last DATA: %lums ago\n",
                _ts.tv_sec, _ts.tv_nsec / 1000,
                AutoReconnect ? "RECONNECT" : "FATAL", ci,
                (unsigned long)pong_gap_ms,
                (unsigned long)(interval_learned ? w.learned_interval_ms : DEFAULT_PONG_TIMEOUT_MS),
                (unsigned long)ping_gap_ms,
                (unsigned long)(interval_learned ? (w.learned_interval_ms * 3 / 2) : 0),
                (unsigned long)data_gap_ms);

        if constexpr (EnableAB) {
            fprintf(stderr, "  other conn %u: phase=%s, last DATA %lums ago\n",
                    other, other_phase, (unsigned long)other_data_gap_ms);
        }

        if constexpr (AutoReconnect) {
            conn_state_->set_reconnect_request(ci);
            w.server_ping_count = 0;
            w.last_server_ping_cycle = now_cycle;
            w.last_client_ping_cycle = 0;
            w.last_pong_recv_cycle = now_cycle;
        } else {
            conn_state_->set_disconnect(DisconnectReason::WS_PONG_TIMEOUT);
            conn_state_->shutdown_all();
        }
    }

    void reset_watchdog_state(uint8_t ci) {
        wd_[ci] = WatchdogState{};
    }

    void check_dual_dead() {
        if constexpr (!EnableAB || !AutoReconnect) return;

        if (ws_phase_[0] != WsConnPhase::ACTIVE || ws_phase_[1] != WsConnPhase::ACTIVE) return;
        if (last_data_cycle_[0] == 0 || last_data_cycle_[1] == 0) return;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        uint64_t threshold_ms = conn_state_->dual_dead_threshold_ms;
        if (threshold_ms == 0 || freq == 0) return;

        uint64_t gap_0 = ((now - last_data_cycle_[0]) * 1000ULL) / freq;
        uint64_t gap_1 = ((now - last_data_cycle_[1]) * 1000ULL) / freq;

        if (gap_0 > threshold_ms && gap_1 > threshold_ms) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            fprintf(stderr, "[%ld.%06ld] [WS-DUAL-DEAD] Both connections silent "
                    "(conn0: %lums, conn1: %lums, threshold: %lums)\n",
                    ts.tv_sec, ts.tv_nsec / 1000,
                    (unsigned long)gap_0, (unsigned long)gap_1,
                    (unsigned long)threshold_ms);

            trigger_watchdog_reconnect(0, now, freq);
            trigger_watchdog_reconnect(1, now, freq);

            ws_phase_[0] = WsConnPhase::DISCONNECTED;
            ws_phase_[1] = WsConnPhase::DISCONNECTED;
        }
    }

    void check_upgrade_timeout() {
        if constexpr (!AutoReconnect) return;

        static constexpr uint64_t UPGRADE_TIMEOUT_MS = 10000;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        if (freq == 0) return;

        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            if (ws_phase_[ci] != WsConnPhase::WS_UPGRADE_SENT) continue;
            if (upgrade_sent_cycle_[ci] == 0) continue;

            uint64_t elapsed_ms = ((now - upgrade_sent_cycle_[ci]) * 1000ULL) / freq;
            if (elapsed_ms > UPGRADE_TIMEOUT_MS) {
                struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] HTTP upgrade timeout for conn %zu "
                        "(%lu ms elapsed), requesting reconnect\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000, ci, (unsigned long)elapsed_ms);

                ws_phase_[ci] = WsConnPhase::DISCONNECTED;
                upgrade_sent_cycle_[ci] = 0;
                conn_state_->set_reconnect_request(ci);
            }
        }
    }

    // ========================================================================
    // Timestamp Helpers
    // ========================================================================

    struct PerConnParseState;

    void populate_timestamps(WSFrameInfo& info, PerConnParseState& ps) {
        if (ps.accumulated_metadata_count > 0) {
            size_t first_idx = 0;
            if (ps.has_carry_over && ps.accumulated_metadata_count > 1) {
                first_idx = 1;
            }
            const auto& first_meta = ps.accumulated_metadata[first_idx];
            info.first_byte_ts = first_meta.first_nic_timestamp_ns;
            info.first_bpf_entry_ns = first_meta.first_bpf_entry_ns;
            info.first_poll_cycle = first_meta.first_nic_frame_poll_cycle;
            info.first_ssl_read_start_cycle = first_meta.ssl_read_start_cycle;
            info.ssl_last_op_cycle = first_meta.ssl_last_op_cycle;
            info.first_pkt_mem_idx = first_meta.first_pkt_mem_idx;
        }

        info.ws_last_op_cycle = last_op_cycle_;
        info.last_byte_ts = ps.current_metadata.latest_nic_timestamp_ns;
        info.latest_bpf_entry_ns = ps.current_metadata.latest_bpf_entry_ns;
        info.latest_poll_cycle = ps.current_metadata.latest_nic_frame_poll_cycle;
        info.latest_ssl_read_end_cycle = ps.current_metadata.ssl_read_end_cycle;
        info.ssl_read_ct = static_cast<uint8_t>(ps.accumulated_metadata_count);
        info.last_pkt_mem_idx = ps.current_metadata.last_pkt_mem_idx;

        if (ps.has_carry_over && ps.accumulated_metadata_count == 1) {
            info.first_poll_cycle = info.latest_poll_cycle;
            info.first_byte_ts = info.last_byte_ts;
            info.first_bpf_entry_ns = info.latest_bpf_entry_ns;
        }

        uint32_t total_nic_packets = 0;
        size_t pkt_start = (ps.has_carry_over && ps.accumulated_metadata_count > 1) ? 1 : 0;
        for (size_t i = pkt_start; i < ps.accumulated_metadata_count; ++i) {
            total_nic_packets += ps.accumulated_metadata[i].nic_packet_ct;
        }
        if (ps.has_carry_over && ps.accumulated_metadata_count == 1) {
            total_nic_packets = 0;
        }
        info.nic_packet_ct = static_cast<uint8_t>(total_nic_packets);

        info.ssl_read_batch_num = static_cast<uint16_t>(++ps.batch_frame_num);

        uint32_t total_bytes = 0;
        for (size_t i = 0; i < ps.accumulated_metadata_count; ++i) {
            total_bytes += ps.accumulated_metadata[i].decrypted_len;
        }
        info.ssl_read_total_bytes = total_bytes;
    }

    // ========================================================================
    // State Management
    // ========================================================================

    void reset_accumulator(uint8_t ci) {
        parse_state_[ci].accumulated_metadata_count = 0;
        parse_state_[ci].has_carry_over = false;
    }

    void reset_fragment_state(uint8_t ci) {
        auto& ps = parse_state_[ci];
        ps.accumulating_fragments = false;
        ps.fragment_opcode = 0;
        ps.fragment_start_offset = 0;
        ps.fragment_total_len = 0;
        ps.fragment_total_frame_len = 0;
    }

    // ========================================================================
    // Per-Connection Parse State
    // ========================================================================

    struct PendingPing {
        uint32_t payload_offset;
        uint16_t payload_len;
    };

    struct PerConnParseState {
        uint32_t data_start_offset = 0;
        uint32_t data_accumulated = 0;
        uint32_t parse_offset = 0;

        std::array<MsgMetadata, MAX_ACCUMULATED_METADATA> accumulated_metadata;
        size_t accumulated_metadata_count = 0;
        bool has_carry_over = false;
        MsgMetadata first_packet_metadata;
        MsgMetadata current_metadata;

        uint32_t current_payload_offset = 0;
        uint32_t frame_start_parse_offset = 0;
        bool pending_tls_record_end = false;

        uint8_t ws_header_wrap_buffer[64];

        uint32_t batch_frame_num = 0;

        bool accumulating_fragments = false;
        uint8_t fragment_opcode = 0;
        uint32_t fragment_start_offset = 0;
        uint32_t fragment_total_len = 0;
        uint32_t fragment_total_frame_len = 0;
        MsgMetadata fragment_first_metadata;
    };

    // ========================================================================
    // Member Variables
    // ========================================================================

    MsgInbox* msg_inbox_[NUM_CONN]{};
    PerConnParseState parse_state_[NUM_CONN]{};
    PartialWebSocketFrame pending_frame_[NUM_CONN]{};
    bool has_pending_frame_[NUM_CONN]{};
    PendingPing pending_ping_[NUM_CONN]{};
    bool has_pending_ping_[NUM_CONN]{};

    WsConnPhase ws_phase_[NUM_CONN]{};
    PartialHttpResponse http_response_[NUM_CONN]{};

    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    TXSink* tx_sink_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    [[no_unique_address]] AppHandler app_handler_{};

    bool ws_ready_signaled_ = false;
    uint64_t last_op_cycle_ = 0;

    struct WatchdogState {
        uint64_t last_client_ping_cycle = 0;
        uint64_t last_pong_recv_cycle = 0;

        static constexpr uint32_t PING_LEARN_SAMPLES = 5;
        uint64_t server_ping_cycles[PING_LEARN_SAMPLES]{};
        uint32_t server_ping_count = 0;
        uint64_t learned_interval_cycles = 0;
        uint64_t learned_interval_ms = 0;

        uint64_t last_server_ping_cycle = 0;
    };
    WatchdogState wd_[NUM_CONN]{};
    uint64_t last_data_cycle_[NUM_CONN]{};
    uint64_t upgrade_sent_cycle_[NUM_CONN]{};

    static constexpr uint64_t DEFAULT_PONG_TIMEOUT_MS = 5000;
};

}  // namespace websocket::pipeline
