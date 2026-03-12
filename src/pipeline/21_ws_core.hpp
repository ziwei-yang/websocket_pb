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
#include "../policy/watchdog.hpp"

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

template<typename SSLPolicy, size_t MaxConn>
struct DirectTXSink {
    static constexpr size_t NUM_CONN = MaxConn;
    SSLPolicy* ssl_ = nullptr;   // points to transport's ssl_[NUM_CONN] array
    uint8_t outbox_buf_[4096];
    uint8_t pong_buf_[131];      // PONG/PING frames (max 125 payload + 6 header)
    uint8_t pending_ci_ = 0;
    int32_t tx_bytes_ = 0;

    uint8_t* outbox_claim(uint8_t ci) { pending_ci_ = ci; return outbox_buf_; }
    void outbox_publish(size_t len) { ssl_[pending_ci_].write(outbox_buf_, len); }

    uint8_t* pong_claim(uint8_t ci) { pending_ci_ = ci; return pong_buf_; }
    void pong_publish(size_t len) {
        ssl_[pending_ci_].write(pong_buf_, len);
        tx_bytes_ += static_cast<int32_t>(len);
    }
};

// ============================================================================
// WSCore - WebSocket processing engine
//
// Template parameters:
//   TXSink         — IPCTXSink or DirectTXSink
//   WSFrameInfoProd — IPCRingProducer<WSFrameInfo> (for output to parent)
//   MaxConn         — max simultaneous connections (1 = single, >1 = multi)
//   AutoReconnect   — event-driven handshake
//   Profiling       — compile-time profiling gates
//   MktEventHandler      — inline callback for market data processing
//   UpgradeCustomizer — custom HTTP headers for upgrade request
//   WSFrameInfoRing — when true, publish to WSFrameInfo ring even with MktEventHandler
// ============================================================================

template<typename TXSink,
         typename WSFrameInfoProd,
         size_t MaxConn, bool AutoReconnect, bool Profiling,
         MktEventHandlerConcept MktEventHandler,
         UpgradeCustomizerConcept UpgradeCustomizer,
         bool WSFrameInfoRing = false>
struct WSCore {
public:
    static constexpr size_t NUM_CONN = MaxConn;
    static constexpr bool HasMktEventHandler = MktEventHandler::enabled;
    static constexpr bool PublishRing = !HasMktEventHandler || WSFrameInfoRing;

    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(std::array<MsgInbox*, MaxConn> msg_inboxes,
              WSFrameInfoProd* ws_frame_info_prod,
              TXSink* tx_sink,
              ConnStateShm* conn_state) {

        for (size_t i = 0; i < MaxConn; ++i) msg_inbox_[i] = msg_inboxes[i];
        if constexpr (PublishRing) {
            ws_frame_info_prod_ = ws_frame_info_prod;
        }
        if constexpr (PublishRing && HasMktEventHandler) {
            mkt_event_handler_.ws_frame_info_prod_ = ws_frame_info_prod;
        }
        tx_sink_ = tx_sink;
        conn_state_ = conn_state;

        if constexpr (MaxConn > 1) {
            n_active_ = conn_state_ ? conn_state_->actual_conn_count : NUM_CONN;
            if (n_active_ > NUM_CONN) n_active_ = NUM_CONN;
        }

        for (size_t i = 0; i < n_active_; i++) {
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

        printf("[WS-CORE] Initialized (MaxConn=%zu)%s\n",
               MaxConn,
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
        for (size_t ci = 0; ci < n_active_; ci++) {
            if (has_pending_ping_[ci]) {
                flush_pending_pong(static_cast<uint8_t>(ci));
            }
        }
        for (size_t ci = 0; ci < n_active_; ci++) {
            if (ws_phase_[ci] == WsConnPhase::ACTIVE) {
                maybe_send_client_ping(static_cast<uint8_t>(ci));
            }
        }
        check_all_dead();
        check_latency_outlier();
        check_upgrade_timeout();
    }

    // ========================================================================
    // Batch End — called by TransportProcess when ssl_read drains to 0
    // ========================================================================

    void on_batch_end(uint8_t ci) {
        if constexpr (HasMktEventHandler) {
            mkt_event_handler_.on_batch_end(ci);
        }
    }

    /// Called by transport after each RX poll cycle per connection.
    /// Fires on_batch_end only if on_ws_data() was called since last cycle.
    void end_rx_cycle(uint8_t ci) {
        if constexpr (HasMktEventHandler) {
            if (feed_since_batch_end_[ci]) {
                feed_since_batch_end_[ci] = false;
                mkt_event_handler_.on_batch_end(ci);
            }
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    MktEventHandler& mkt_event_handler() { return mkt_event_handler_; }
    WsConnPhase ws_phase(uint8_t ci) const { return ws_phase_[ci]; }
    void set_transport_mode(uint8_t mode) { transport_mode_ = mode; }

    // ========================================================================
    // AutoReconnect State Machine Handlers
    // ========================================================================

    void on_tcp_disconnected(uint8_t ci) {
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] TCP_DISCONNECTED for conn %u\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);

        ws_phase_[ci] = WsConnPhase::DISCONNECTED;
        notify_disconnected(ci);

        // Reset per-connection parse state
        feed_since_batch_end_[ci] = false;
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
            conn_state_->target_path[ci],
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
            notify_disconnected(ci);
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
        notify_reconnected(ci);

        // Reset parse state for clean start
        parse_state_[ci] = PerConnParseState{};
        has_pending_frame_[ci] = false;
        pending_frame_[ci].clear();

        // Reset dual-dead baseline
        last_data_cycle_[ci] = 0;

        // Reset + resume watchdog for this connection
        reset_watchdog_state(ci);
        if constexpr (MaxConn > 1 && HasMktEventHandler) {
            uint64_t freq = conn_state_->tsc_freq_hz;
            if (freq > 0)
                latency_grace_until_cycle_[ci] = rdtscp() + (LATENCY_GRACE_PERIOD_MS * freq) / 1000;
        }

        // Signal ws_ready on first successful handshake
        if (!ws_ready_signaled_) {
            bool all_active = true;
            for (size_t i = 0; i < n_active_; i++) {
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
        if constexpr (HasMktEventHandler) feed_since_batch_end_[ci] = true;
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
                    break;
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
                    break;
                }

                frame_complete = true;
            } else {
                ps.frame_start_parse_offset = ps.parse_offset;
                consumed = start_parse_frame(pending_frame_[ci], data, linear_avail);
                has_pending_frame_[ci] = true;

                if (!pending_frame_[ci].header_complete) {
                    ps.parse_offset += consumed;
                    break;
                }

                uint64_t total_needed = pending_frame_[ci].expected_header_len + pending_frame_[ci].payload_len;
                size_t total_available = consumed + (linear_avail - consumed);

                if (total_available < total_needed) {
                    size_t payload_in_this_chunk = linear_avail - pending_frame_[ci].expected_header_len;
                    pending_frame_[ci].payload_bytes_received = payload_in_this_chunk;

                    publish_partial_frame_info(ci);
                    ps.parse_offset += linear_avail;
                    break;
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

                ps.is_last_in_batch = (ps.parse_offset + consumed >= ps.data_accumulated);
                bool is_last_in_data = ps.is_last_in_batch;
                ps.pending_tls_record_end = is_last_in_data && ps.current_metadata.tls_record_end();

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

        // (flush deferred to on_batch_end() via on_batch_end() from transport)

        if (!has_pending_frame_[ci]) {
            ps.data_accumulated = 0;
            ps.parse_offset = 0;
        }
    }

    // ========================================================================
    // Partial Frame WSFrameInfo
    // ========================================================================

    void publish_partial_frame_info(uint8_t ci) {
        if constexpr (!PublishRing) return;

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
        info.transport_mode = transport_mode_;
        info.conn_target_ip = conn_state_ ? conn_state_->conn_target_ip[ci] : 0;

        populate_timestamps(info, ps);
        info.set_tls_record_end(false);
        info.ws_parse_cycle = rdtscp();

        if constexpr (HasMktEventHandler) {
            if ((pending_frame_[ci].opcode == 0x01 || pending_frame_[ci].opcode == 0x02) && info.payload_len >= 64) {
                const uint8_t* payload = msg_inbox_[ci]->data_at(info.msg_inbox_offset);
                WSFrameInfo frag_info{};
                frag_info.first_byte_ts = info.first_byte_ts;
                frag_info.latest_bpf_entry_ns = info.latest_bpf_entry_ns;
                frag_info.first_bpf_entry_ns = info.first_bpf_entry_ns;
                mkt_event_handler_.on_ws_data(mkt_event_handler_.sbe_state_[ci],
                                              ci, payload, info.payload_len, frag_info);
                info.mkt_event_type = frag_info.mkt_event_type;
                info.mkt_event_count = frag_info.mkt_event_count;
                info.mkt_event_seq = frag_info.mkt_event_seq;
                info.exchange_event_time_us = frag_info.exchange_event_time_us;
                info.flags |= (frag_info.flags & 0xF0);  // Propagate discard_early etc.
            } else if (pending_frame_[ci].opcode == 0x00) {
                // Continuation frame partial: propagate type from SBE state for display
                auto& st = mkt_event_handler_.sbe_state_[ci];
                if (st.msg_type != 0) {
                    switch (st.msg_type) {
                    // SBE template IDs
                    case 10002: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
                    case 10003: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
                    case 10000: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
                    case 10001: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY); break;
                    // JSON UsdmStreamType values
                    case 1: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
                    case 2: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
                    case 3: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
                    }
                    info.mkt_event_seq = st.sequence;
                    info.exchange_event_time_us = st.event_time_us;
                    info.mkt_event_count = (st.bids_count > 0 || st.asks_count > 0)
                        ? st.bids_count + st.asks_count : st.group_count;
                }
            }
        }

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
            uint64_t tsc_freq = conn_state_->tsc_freq_hz;

            if constexpr (MaxConn <= 1) {
                // SelfLearnWatchdogPolicy: learn interval + log progress
                using SLWP = websocket::policy::SelfLearnWatchdogPolicy;
                uint32_t prev_count = w.server_ping_count;
                w.on_server_ping(now_cycle, tsc_freq);

                if (prev_count >= 1) {
                    if (w.server_ping_count == 0) {
                        // Bogus interval detected (count was reset)
                        fprintf(stderr, "[WS-WATCHDOG] Ignoring bogus PING interval (conn %u) "
                                "— too short, resetting\n", ci);
                    } else if (w.server_ping_count >= 2 && w.server_ping_count <= SLWP::PING_LEARN_SAMPLES
                               && w.learned_interval_ms > 0) {
                        uint32_t n = std::min(w.server_ping_count, SLWP::PING_LEARN_SAMPLES);
                        uint64_t total_delta = w.server_ping_cycles[n - 1] - w.server_ping_cycles[0];
                        uint64_t avg_ms = (total_delta / (n - 1) * 1000ULL) / tsc_freq;
                        fprintf(stderr, "[WS-WATCHDOG] Server PING interval (conn %u): %lums "
                                "(avg %lums, %u/%u samples)\n",
                                ci, (unsigned long)w.learned_interval_ms,
                                (unsigned long)avg_ms, n, SLWP::PING_LEARN_SAMPLES);
                    }
                }
            } else {
                w.on_server_ping(now_cycle, tsc_freq);  // no-op for FixedWatchdogPolicy
            }
        }

        // Publish WSFrameInfo for PING
        if constexpr (PublishRing) {
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
        info.transport_mode = transport_mode_;
        info.conn_target_ip = conn_state_ ? conn_state_->conn_target_ip[ci] : 0;

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
        if constexpr (HasMktEventHandler) mkt_event_handler_.on_heartbeat(ci, 0);
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

        wd_[ci].on_pong(rdtscp());

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
        if constexpr (HasMktEventHandler) mkt_event_handler_.on_heartbeat(ci, 1);
    }

    void maybe_send_client_ping(uint8_t ci) {
        auto& w = wd_[ci];
        uint64_t now_cycle = rdtscp();
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;

        if (w.last_client_ping_cycle == 0) {
            w.last_client_ping_cycle = now_cycle;
            w.on_pong(now_cycle);
            return;
        }

        // Rate limit: 1 PING per second
        if ((now_cycle - w.last_client_ping_cycle) < tsc_freq) return;

        if (w.check_alert(now_cycle, tsc_freq)) {
            trigger_watchdog_reconnect(ci, now_cycle, tsc_freq);
            ws_phase_[ci] = WsConnPhase::DISCONNECTED;
            notify_disconnected(ci);
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
        uint8_t saved_mkt_event_type = 0;
        uint16_t saved_mkt_event_count = 0;
        int64_t saved_mkt_event_seq = 0;
        int64_t saved_exchange_event_time_us = 0;
        uint8_t app_flags = 0;  // MktEventHandler-set flags (discard_early etc.)

        // MktEventHandler: streaming SBE parse for TEXT/BINARY frames
        if constexpr (HasMktEventHandler) {
            if (opcode == 0x01 || opcode == 0x02) {
                WSFrameInfo info{};
                info.clear();
                info.msg_inbox_offset = ps.current_payload_offset;
                info.payload_len = static_cast<uint32_t>(payload_len);
                info.opcode = opcode;
                info.set_fin(!is_fragmented || is_last_fragment);
                info.set_fragmented(is_fragmented);
                info.set_last_fragment(is_last_fragment);
                info.connection_id = ci;
        info.transport_mode = transport_mode_;
        info.conn_target_ip = conn_state_ ? conn_state_->conn_target_ip[ci] : 0;
                if constexpr (MaxConn > 1) {
                    if (ps.accumulated_metadata_count > 0 && ps.accumulated_metadata[0].is_active_conn())
                        info.set_active_conn(true);
                }
                auto saved_batch_num = ps.batch_frame_num;
                populate_timestamps(info, ps);
                if constexpr (PublishRing) ps.batch_frame_num = saved_batch_num;  // ring will increment
                info.debug_validate(ci);
                info.set_tls_record_end(ps.pending_tls_record_end);
                info.set_last_in_batch(ps.is_last_in_batch);
                info.ws_parse_cycle = parse_cycle;

                // Single code path: pass full accumulated payload for fragments,
                // or current payload for complete frames
                uint32_t payload_offset_raw = is_fragmented
                    ? ps.fragment_start_offset
                    : info.msg_inbox_offset;
                const uint8_t* ws_payload = msg_inbox_[ci]->data_at(payload_offset_raw);
                uint32_t avail = is_fragmented
                    ? ps.fragment_total_len
                    : static_cast<uint32_t>(payload_len);

                // Pre-populate from state (baseline for TLS-split frames where
                // partial already parsed essential fields)
                auto& st = mkt_event_handler_.sbe_state_[ci];
                if (st.msg_type != 0) {
                    switch (st.msg_type) {
                    // SBE template IDs
                    case 10002: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
                    case 10003: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
                    case 10000: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
                    case 10001: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY); break;
                    // JSON UsdmStreamType values
                    case 1: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
                    case 2: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
                    case 3: saved_mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
                    }
                    saved_mkt_event_seq = st.sequence;
                    saved_exchange_event_time_us = st.event_time_us;
                    saved_mkt_event_count = (st.bids_count > 0 || st.asks_count > 0)
                        ? st.bids_count + st.asks_count : st.group_count;
                }

                if (avail >= 8)
                    mkt_event_handler_.on_ws_data(mkt_event_handler_.sbe_state_[ci],
                                                  ci, ws_payload, avail, info);
                // Reset state when message is complete
                if (!is_fragmented || is_last_fragment)
                    mkt_event_handler_.sbe_state_[ci].reset();

                // Override with handler values if it produced useful metadata
                if (info.exchange_event_time_us != 0 || info.mkt_event_count != 0) {
                    saved_mkt_event_type = info.mkt_event_type;
                    saved_mkt_event_count = info.mkt_event_count;
                    saved_mkt_event_seq = info.mkt_event_seq;
                    saved_exchange_event_time_us = info.exchange_event_time_us;
                }
                app_flags = info.flags & 0xF0;  // Preserve MktEventHandler-set bits (4+)
                on_latency_sample(ci, saved_exchange_event_time_us);
            }
        }

        // Ring: publish WSFrameInfo for all frames (data, continuation, etc.)
        if constexpr (PublishRing) {
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
        info.transport_mode = transport_mode_;
        info.conn_target_ip = conn_state_ ? conn_state_->conn_target_ip[ci] : 0;
            if constexpr (MaxConn > 1) {
                if (ps.accumulated_metadata_count > 0 && ps.accumulated_metadata[0].is_active_conn())
                    info.set_active_conn(true);
            }

            populate_timestamps(info, ps);
            info.debug_validate(ci);
            info.set_tls_record_end(ps.pending_tls_record_end);
            info.mkt_event_type = saved_mkt_event_type;
            info.mkt_event_count = saved_mkt_event_count;
            info.mkt_event_seq = saved_mkt_event_seq;
            info.exchange_event_time_us = saved_exchange_event_time_us;
            info.flags |= app_flags;  // Merge MktEventHandler-set flags (discard_early etc.)

            info.ws_parse_cycle = parse_cycle;

            info.ws_frame_publish_cycle = rdtscp();
            {
                struct timespec _ts;
                clock_gettime(CLOCK_MONOTONIC, &_ts);
                info.publish_time_ts = _ts.tv_sec * 1000000000ULL + _ts.tv_nsec;
            }
            ws_frame_info_prod_->publish(seq);

            if constexpr (HasMktEventHandler) {
                if (mkt_event_handler_.pending_ring_seq_slot_) {
                    *mkt_event_handler_.pending_ring_seq_slot_ = seq;
                    mkt_event_handler_.pending_ring_seq_slot_ = nullptr;
                }
            }
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

        uint64_t data_gap_ms = (last_data_cycle_[ci] > 0)
            ? ((now_cycle - last_data_cycle_[ci]) * 1000ULL) / tsc_freq : 0;

        if constexpr (MaxConn <= 1) {
            uint64_t ping_gap_ms = (w.last_server_ping_cycle > 0)
                ? ((now_cycle - w.last_server_ping_cycle) * 1000ULL) / tsc_freq : 0;
            fprintf(stderr, "[%ld.%06ld] [WS-WATCHDOG] %s: conn %u dead\n"
                    "  PONG missing: last %lums ago (threshold %lums)\n"
                    "  server PING missing: last %lums ago (threshold %lums)\n"
                    "  last DATA: %lums ago\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000,
                    AutoReconnect ? "RECONNECT" : "FATAL", ci,
                    (unsigned long)pong_gap_ms,
                    (unsigned long)w.timeout_display_ms(),
                    (unsigned long)ping_gap_ms,
                    (unsigned long)w.server_ping_display_ms(),
                    (unsigned long)data_gap_ms);
        } else {
            fprintf(stderr, "[%ld.%06ld] [WS-WATCHDOG] %s: conn %u dead\n"
                    "  PONG missing: last %lums ago (threshold %lums)\n"
                    "  last DATA: %lums ago\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000,
                    AutoReconnect ? "RECONNECT" : "FATAL", ci,
                    (unsigned long)pong_gap_ms,
                    (unsigned long)w.timeout_display_ms(),
                    (unsigned long)data_gap_ms);

            for (size_t other = 0; other < n_active_; ++other) {
                if (other == ci) continue;
                uint64_t other_data_gap_ms = (last_data_cycle_[other] > 0)
                    ? ((now_cycle - last_data_cycle_[other]) * 1000ULL) / tsc_freq : 0;
                const char* other_phase = (ws_phase_[other] == WsConnPhase::ACTIVE) ? "ACTIVE" :
                                          (ws_phase_[other] == WsConnPhase::DISCONNECTED) ? "DISCONNECTED" :
                                          "WS_UPGRADE_SENT";
                fprintf(stderr, "  other conn %zu: phase=%s, last DATA %lums ago\n",
                        other, other_phase, (unsigned long)other_data_gap_ms);
            }
        }

        if constexpr (AutoReconnect) {
            conn_state_->set_reconnect_request(ci);
            w.reset(now_cycle);
        } else {
            conn_state_->set_disconnect(DisconnectReason::WS_PONG_TIMEOUT);
            conn_state_->shutdown_all();
        }
    }

    void reset_watchdog_state(uint8_t ci) {
        wd_[ci] = WatchdogPolicyType{};
        if constexpr (MaxConn > 1 && HasMktEventHandler) latency_tracker_[ci].reset();
    }

    void check_all_dead() {
        if constexpr (MaxConn <= 1 || !AutoReconnect) return;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        uint64_t threshold_ms = conn_state_->dual_dead_threshold_ms;
        if (threshold_ms == 0 || freq == 0) return;

        // All N connections must be ACTIVE with non-zero last_data_cycle_
        for (size_t i = 0; i < n_active_; ++i) {
            if (ws_phase_[i] != WsConnPhase::ACTIVE) return;
            if (last_data_cycle_[i] == 0) return;
        }

        // All N must exceed threshold
        bool all_dead = true;
        for (size_t i = 0; i < n_active_; ++i) {
            uint64_t last_alive = last_data_cycle_[i];
            if (wd_[i].last_pong_recv_cycle > last_alive)
                last_alive = wd_[i].last_pong_recv_cycle;
            uint64_t gap = ((now - last_alive) * 1000ULL) / freq;
            if (gap <= threshold_ms) { all_dead = false; break; }
        }

        if (all_dead) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            fprintf(stderr, "[%ld.%06ld] [WS-ALL-DEAD] All %u connections silent (threshold: %lums)\n",
                    ts.tv_sec, ts.tv_nsec / 1000, n_active_, (unsigned long)threshold_ms);
            for (size_t i = 0; i < n_active_; ++i) {
                uint64_t data_gap = (last_data_cycle_[i] > 0)
                    ? ((now - last_data_cycle_[i]) * 1000ULL) / freq : 0;
                uint64_t pong_gap = (wd_[i].last_pong_recv_cycle > 0)
                    ? ((now - wd_[i].last_pong_recv_cycle) * 1000ULL) / freq : 0;
                uint64_t ping_gap = (wd_[i].last_client_ping_cycle > 0)
                    ? ((now - wd_[i].last_client_ping_cycle) * 1000ULL) / freq : 0;
                uint64_t last_alive = last_data_cycle_[i];
                if (wd_[i].last_pong_recv_cycle > last_alive)
                    last_alive = wd_[i].last_pong_recv_cycle;
                uint64_t gap = ((now - last_alive) * 1000ULL) / freq;
                const char* src = (wd_[i].last_pong_recv_cycle > last_data_cycle_[i]) ? "PONG" : "DATA";
                fprintf(stderr, "  conn %zu: %lums ago (src=%s data=%lums pong=%lums ping_sent=%lums)\n",
                        i, (unsigned long)gap, src,
                        (unsigned long)data_gap, (unsigned long)pong_gap, (unsigned long)ping_gap);
            }

            for (size_t i = 0; i < n_active_; ++i) {
                trigger_watchdog_reconnect(static_cast<uint8_t>(i), now, freq);
                ws_phase_[i] = WsConnPhase::DISCONNECTED;
            }
            notify_disconnected(0);
        }
    }

    // ========================================================================
    // Latency-Based Outlier Detection (multi-conn only)
    // ========================================================================

    static constexpr int64_t STALE_REJECT_NS = 500'000'000LL;           // 500ms — drop stale
    static constexpr uint64_t LATENCY_GRACE_PERIOD_MS = 10000;          // 10s post-reconnect

    void on_latency_sample(uint8_t ci, int64_t exchange_event_time_us) {
        if constexpr (MaxConn <= 1 || !HasMktEventHandler) return;
        if (exchange_event_time_us <= 0) return;
        if (latency_grace_until_cycle_[ci] > 0) {
            if (rdtscp() < latency_grace_until_cycle_[ci]) return;
            latency_grace_until_cycle_[ci] = 0;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int64_t recv_ns = ts.tv_sec * 1'000'000'000LL + ts.tv_nsec;
        int64_t latency_ns = recv_ns - exchange_event_time_us * 1000;
        if (latency_ns > STALE_REJECT_NS) return;   // drop stale
        latency_tracker_[ci].on_sample(latency_ns);
    }

    void check_latency_outlier() {
        if constexpr (MaxConn <= 1 || !AutoReconnect || !HasMktEventHandler) return;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        if (freq == 0) return;

        // Rate-limit: check at most once per second
        if (last_outlier_check_cycle_ > 0) {
            uint64_t elapsed_ms = ((now - last_outlier_check_cycle_) * 1000ULL) / freq;
            if (elapsed_ms < 1000) return;
        }
        last_outlier_check_cycle_ = now;

        // 10s cooldown between outlier disconnects
        if (last_outlier_disconnect_cycle_ > 0) {
            uint64_t cooldown_ms = ((now - last_outlier_disconnect_cycle_) * 1000ULL) / freq;
            if (cooldown_ms < 10000) return;
        }

        // Require all connections ACTIVE
        for (size_t i = 0; i < n_active_; ++i)
            if (ws_phase_[i] != WsConnPhase::ACTIVE) return;

        auto result = websocket::policy::detect_latency_outlier(
            latency_tracker_, static_cast<uint8_t>(n_active_));
        if (result.outlier_ci < 0) return;

        uint8_t ci = static_cast<uint8_t>(result.outlier_ci);
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        fprintf(stderr, "[%ld.%06ld] [WS-LATENCY-OUTLIER] conn %u EMA=%ldms (min=%ldms)\n",
                ts.tv_sec, ts.tv_nsec / 1000, ci,
                result.outlier_ema_ns / 1'000'000, result.min_ema_ns / 1'000'000);
        for (size_t i = 0; i < n_active_; ++i) {
            fprintf(stderr, "  conn %zu: EMA=%ldms last=%ldms samples=%u\n",
                    i, latency_tracker_[i].ema_ms(),
                    latency_tracker_[i].last_sample_ns / 1'000'000,
                    latency_tracker_[i].sample_count);
        }

        last_outlier_disconnect_cycle_ = now;
        ws_phase_[ci] = WsConnPhase::DISCONNECTED;
        notify_disconnected(ci);
        conn_state_->set_reconnect_request(ci);
    }

    void check_upgrade_timeout() {
        if constexpr (!AutoReconnect) return;

        static constexpr uint64_t UPGRADE_TIMEOUT_MS = 10000;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        if (freq == 0) return;

        for (size_t ci = 0; ci < n_active_; ci++) {
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
                notify_disconnected(ci);
                conn_state_->set_reconnect_request(ci);
            }
        }
    }

    // ========================================================================
    // Connection Status Notification Helpers
    // ========================================================================

    void notify_disconnected(uint8_t ci) {
        if constexpr (!HasMktEventHandler) return;
        if constexpr (MaxConn > 1) {
            bool all_down = true;
            for (size_t i = 0; i < n_active_; i++)
                if (ws_phase_[i] != WsConnPhase::DISCONNECTED) { all_down = false; break; }
            if (all_down && !all_disconnected_) {
                all_disconnected_ = true;
                mkt_event_handler_.on_disconnected(0xFF);
            }
        } else {
            if (!all_disconnected_) {
                all_disconnected_ = true;
                mkt_event_handler_.on_disconnected(ci);
            }
        }
    }

    void notify_reconnected(uint8_t ci) {
        if constexpr (!HasMktEventHandler) return;
        if (all_disconnected_) {
            all_disconnected_ = false;
            mkt_event_handler_.on_reconnected(ci);
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
        bool is_last_in_batch = false;

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
    bool feed_since_batch_end_[NUM_CONN]{};
    PendingPing pending_ping_[NUM_CONN]{};
    bool has_pending_ping_[NUM_CONN]{};

    WsConnPhase ws_phase_[NUM_CONN]{};
    PartialHttpResponse http_response_[NUM_CONN]{};

    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    TXSink* tx_sink_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    [[no_unique_address]] MktEventHandler mkt_event_handler_{};

    uint8_t transport_mode_ = 0;
    uint8_t n_active_ = NUM_CONN;
    bool ws_ready_signaled_ = false;
    bool all_disconnected_ = false;
    uint64_t last_op_cycle_ = 0;

    using WatchdogPolicyType = std::conditional_t<(MaxConn > 1),
        websocket::policy::FixedWatchdogPolicy<5000>,
        websocket::policy::SelfLearnWatchdogPolicy>;
    WatchdogPolicyType wd_[NUM_CONN]{};
    uint64_t last_data_cycle_[NUM_CONN]{};
    uint64_t upgrade_sent_cycle_[NUM_CONN]{};

    // Latency-based outlier detection (multi-conn only)
    websocket::policy::LatencyTracker latency_tracker_[NUM_CONN]{};
    uint64_t latency_grace_until_cycle_[NUM_CONN]{};
    uint64_t last_outlier_check_cycle_ = 0;
    uint64_t last_outlier_disconnect_cycle_ = 0;
};

}  // namespace websocket::pipeline
