// pipeline/websocket_process.hpp
// WebSocket Process - HTTP+WS handshake and frame parsing
// Performs HTTP upgrade handshake after TLS ready, then parses WS frames
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <array>

// pipeline_data.hpp must be included BEFORE pipeline_config.hpp
// to avoid CACHE_LINE_SIZE macro conflict with disruptor
#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"
#include "ws_parser.hpp"
#include "../core/http.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// WebSocketProcess - HTTP+WS handshake and frame parsing
//
// Implements disruptor::event_handler_concept<MsgMetadata> for integration
// with event_processor pattern. The on_event() method handles each MsgMetadata
// event from MSG_METADATA_INBOX.
//
// Two-Phase Operation:
// - Phase 1 (Handshake): Manual polling, blocking until HTTP 101 received
// - Phase 2 (Main Loop): event_processor.run() pattern via on_event() handler
//
// Responsibilities:
// 1. Wait for tls_ready from Transport
// 2. Perform HTTP+WS handshake (upgrade request, validate 101, subscription)
// 3. Signal ws_ready when handshake complete
// 4. Consume MsgMetadata from MSG_METADATA ring via on_event()
// 5. Parse WebSocket frames from MSG_INBOX data
// 6. Handle control frames: PING -> PONGS + WSFrameInfo, CLOSE -> MSG_OUTBOX
// 7. Publish WSFrameInfo for TEXT/BINARY to AppClient
// 8. Track partial frames across SSL_read boundaries
// 9. Publish WSFrameInfo immediately when header complete (partial frames)
// ============================================================================

// Maximum metadata entries to accumulate before forced commit
// Value 64 is a practical optimization (reduced from 256):
//   - Reduces cache footprint by 12 KB (MsgMetadata is 64 bytes each)
//   - Still handles any realistic WebSocket frame (64 SSL_reads per frame is extreme)
//   - Better cache locality = lower latency variance
constexpr size_t MAX_ACCUMULATED_METADATA = 64;

// Handshake timeout in milliseconds
constexpr uint64_t HANDSHAKE_TIMEOUT_MS = 10000;

// Partial HTTP response accumulation for handshake
struct PartialHttpResponse {
    uint8_t buffer[4096];
    size_t accumulated = 0;
    bool headers_complete = false;

    void clear() {
        accumulated = 0;
        headers_complete = false;
    }

    // Check if we have complete HTTP headers (ends with \r\n\r\n)
    bool try_complete() {
        if (accumulated < 4) return false;
        for (size_t i = 0; i <= accumulated - 4; ++i) {
            if (buffer[i] == '\r' && buffer[i+1] == '\n' &&
                buffer[i+2] == '\r' && buffer[i+3] == '\n') {
                headers_complete = true;
                return true;
            }
        }
        return false;
    }
};

// Template parameters for each ring type used by WebSocketProcess
template<typename MsgMetadataCons,     // IPCRingConsumer<MsgMetadata>
         typename WSFrameInfoProd,     // IPCRingProducer<WSFrameInfo>
         typename PongsProd,           // IPCRingProducer<PongFrameAligned>
         typename MsgOutboxProd>       // IPCRingProducer<MsgOutboxEvent>
struct WebSocketProcess {
public:
    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(MsgInbox* msg_inbox,
              MsgMetadataCons* msg_metadata_cons,
              WSFrameInfoProd* ws_frame_info_prod,
              PongsProd* pongs_prod,
              MsgOutboxProd* msg_outbox_prod,
              ConnStateShm* conn_state) {

        msg_inbox_ = msg_inbox;
        msg_metadata_cons_ = msg_metadata_cons;
        ws_frame_info_prod_ = ws_frame_info_prod;
        pongs_prod_ = pongs_prod;
        msg_outbox_prod_ = msg_outbox_prod;
        conn_state_ = conn_state;

        pending_frame_.clear();
        reset_accumulator();
        reset_fragment_state();

        has_pending_ping_ = false;

        printf("[WS-PROCESS] Initialized\n");
        return true;
    }

    // ========================================================================
    // Phase 1: Handshake (blocking, before main loop)
    // ========================================================================

    bool perform_handshake() {
        printf("[WS-PROCESS] Waiting for TLS ready...\n");

        // Step 1: Wait for tls_ready from Transport
        uint64_t start_cycle = rdtscp();
        uint64_t timeout_cycles = HANDSHAKE_TIMEOUT_MS * (conn_state_->tsc_freq_hz / 1000);

        while (!conn_state_->is_handshake_tls_ready()) {
            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WS-PROCESS] Shutdown during TLS wait\n");
                return false;
            }
            if (rdtscp() - start_cycle > timeout_cycles) {
                fprintf(stderr, "[WS-PROCESS] Timeout waiting for TLS ready\n");
                return false;
            }
            __builtin_ia32_pause();
        }
        printf("[WS-PROCESS] TLS ready, sending HTTP upgrade\n");

        // Step 2: Send HTTP upgrade request
        send_http_upgrade_request();

        // Step 3: Wait for and validate HTTP 101 response
        if (!recv_http_upgrade_response()) {
            fprintf(stderr, "[WS-PROCESS] HTTP upgrade failed\n");
            return false;
        }
        printf("[WS-PROCESS] HTTP 101 received, sending subscription\n");

        // Step 4: Send subscription message
        send_subscription_message();

        // Step 5: Signal ws_ready
        conn_state_->set_handshake_ws_ready();
        printf("[WS-PROCESS] Handshake complete, ws_ready signaled\n");

        return true;
    }

    // ========================================================================
    // Phase 2: Main Loop (event_processor pattern)
    // ========================================================================

    void run() {
        printf("[WS-PROCESS] Running main loop\n");

        // Mark ourselves as ready
        conn_state_->set_ready(PROC_WEBSOCKET);

        // Counters for idle detection
        [[maybe_unused]] uint64_t idle_count = 0;
        [[maybe_unused]] uint64_t busy_count = 0;

        // Main event loop - event_processor.run() pattern
        // Uses on_event() handler for each MsgMetadata event
        while (conn_state_->is_running(PROC_WEBSOCKET)) {
            // Process batch of metadata events via event handler
            size_t processed = msg_metadata_cons_->process_manually(
                [this](MsgMetadata& meta, int64_t seq, bool end_of_batch) {
                    on_event(meta, seq, end_of_batch);
                    return true;  // Continue processing
                },
                MAX_ACCUMULATED_METADATA
            );

            if (processed > 0) {
                msg_metadata_cons_->commit_manually();
            }

            // Flush PONG on IDLE (no frames processed this round)
            if (processed == 0) {
                idle_count++;
                if (has_pending_ping_) {
                    flush_pending_pong();
                }
                __builtin_ia32_pause();
            } else {
                busy_count++;
            }
        }

        // Flush any remaining PONG on shutdown
        flush_pending_pong();

        printf("[WS-PROCESS] Exiting main loop\n");
    }

    // Shutdown: signal halt to stop the main loop
    void shutdown() {
        if (conn_state_) {
            conn_state_->shutdown_all();
        }
    }

    // Combined init + handshake + run
    void run_with_handshake() {
        if (!perform_handshake()) {
            fprintf(stderr, "[WS-PROCESS] Handshake failed, exiting\n");
            return;
        }
        run();
    }

private:
    // ========================================================================
    // Handshake Helpers
    // ========================================================================

    void send_http_upgrade_request() {
        char request_buf[4096];
        std::vector<std::pair<std::string, std::string>> custom_headers;

        size_t request_len = websocket::http::build_websocket_upgrade_request(
            conn_state_->target_host,
            conn_state_->target_path,
            custom_headers,
            request_buf,
            sizeof(request_buf)
        );

        // Publish to MSG_OUTBOX
        int64_t seq = msg_outbox_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: MSG_OUTBOX full during handshake\n");
            std::abort();
        }

        auto& event = (*msg_outbox_prod_)[seq];
        std::memcpy(event.data, request_buf, request_len);
        event.data_len = static_cast<uint16_t>(request_len);
        event.msg_type = MSG_TYPE_DATA;

        msg_outbox_prod_->publish(seq);
    }

    bool recv_http_upgrade_response() {
        PartialHttpResponse response;
        response.clear();

        uint64_t start_cycle = rdtscp();
        uint64_t timeout_cycles = HANDSHAKE_TIMEOUT_MS * (conn_state_->tsc_freq_hz / 1000);

        while (!response.headers_complete) {
            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                return false;
            }
            if (rdtscp() - start_cycle > timeout_cycles) {
                fprintf(stderr, "[WS-PROCESS] Timeout waiting for HTTP response\n");
                return false;
            }

            // Poll for metadata events
            MsgMetadata meta;
            if (msg_metadata_cons_->try_consume(meta)) {
                if (meta.decrypted_len > 0) {
                    const uint8_t* data = msg_inbox_->data_at(meta.msg_inbox_offset);
                    size_t to_copy = std::min(static_cast<size_t>(meta.decrypted_len),
                                              sizeof(response.buffer) - response.accumulated);
                    std::memcpy(response.buffer + response.accumulated, data, to_copy);
                    response.accumulated += to_copy;
                    response.try_complete();
                }
            } else {
                __builtin_ia32_pause();
            }
        }

        // Validate HTTP 101 response
        return websocket::http::validate_http_upgrade_response(response.buffer, response.accumulated);
    }

    void send_subscription_message() {
        const char* json = conn_state_->subscription_json;
        size_t json_len = std::strlen(json);

        if (json_len == 0) {
            printf("[WS-PROCESS] No subscription message configured\n");
            return;
        }

        // Build complete WS TEXT frame
        int64_t seq = msg_outbox_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: MSG_OUTBOX full during subscription\n");
            std::abort();
        }

        auto& event = (*msg_outbox_prod_)[seq];

        // Build WS frame header + masked payload
        uint8_t mask_key[4] = {0, 0, 0, 0};  // Zero mask for no-op XOR
        size_t frame_len = websocket::http::build_websocket_frame(
            reinterpret_cast<const uint8_t*>(json),
            json_len,
            event.data,
            sizeof(event.data),
            mask_key,
            static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT)
        );

        event.data_len = static_cast<uint16_t>(frame_len);
        event.msg_type = MSG_TYPE_DATA;

        msg_outbox_prod_->publish(seq);
        printf("[WS-PROCESS] Subscription sent (%zu bytes)\n", json_len);
    }

    // ========================================================================
    // Event Handler (satisfies disruptor::event_handler_concept)
    // ========================================================================

    void on_event(MsgMetadata& meta, int64_t sequence, bool end_of_batch) {
        (void)sequence;
        (void)end_of_batch;

        fprintf(stderr, "[WS] on_event: seq=%ld len=%u\n", sequence, meta.decrypted_len);

        // Accumulate metadata for timestamp recovery
        if (!has_pending_frame_) {
            // Starting fresh - record start offset and reset accumulators
            data_start_offset_ = meta.msg_inbox_offset;
            data_accumulated_ = 0;
            parse_offset_ = 0;
            accumulated_metadata_count_ = 0;
        }

        // Accumulate this SSL_read's data
        data_accumulated_ += meta.decrypted_len;

        // Add metadata to array (if space available)
        if (accumulated_metadata_count_ < MAX_ACCUMULATED_METADATA) {
            accumulated_metadata_[accumulated_metadata_count_++] = meta;
        }

        // Store current metadata for latest timestamps
        current_metadata_ = meta;

        // Parse WebSocket frames from accumulated data
        while (parse_offset_ < data_accumulated_) {
            uint32_t offset = (data_start_offset_ + parse_offset_) % MSG_INBOX_SIZE;
            const uint8_t* data = msg_inbox_->data_at(offset);
            size_t available = data_accumulated_ - parse_offset_;

            // Handle MSG_INBOX wrap-around (linear available bytes)
            size_t linear_avail = std::min(available, static_cast<size_t>(MSG_INBOX_SIZE - offset));

            // Handle header spanning wrap point - copy to contiguous buffer
            if (linear_avail < available && linear_avail < sizeof(ws_header_wrap_buffer_)) {
                size_t first_part = MSG_INBOX_SIZE - offset;
                size_t second_part = std::min(available - first_part,
                                              sizeof(ws_header_wrap_buffer_) - first_part);
                std::memcpy(ws_header_wrap_buffer_, data, first_part);
                std::memcpy(ws_header_wrap_buffer_ + first_part, msg_inbox_->data_at(0), second_part);
                data = ws_header_wrap_buffer_;
                linear_avail = first_part + second_part;
            }

            // Parse frame
            size_t consumed = 0;
            bool frame_complete = false;

            if (has_pending_frame_) {
                // Continue parsing partial frame
                consumed = continue_partial_frame(pending_frame_, data, linear_avail);

                if (!pending_frame_.header_complete) {
                    // Header still incomplete - DEFER
                    parse_offset_ += consumed;
                    return;
                }

                // FIX: Update payload_bytes_received with newly available data
                // After header continuation, remaining data in this chunk is payload
                size_t available_for_payload = linear_avail - consumed;
                uint64_t payload_remaining = pending_frame_.payload_len - pending_frame_.payload_bytes_received;
                size_t payload_in_chunk = std::min(available_for_payload, static_cast<size_t>(payload_remaining));
                pending_frame_.payload_bytes_received += payload_in_chunk;
                consumed += payload_in_chunk;

                // Check if payload complete
                uint64_t total_needed = pending_frame_.expected_header_len + pending_frame_.payload_len;
                uint64_t total_received = pending_frame_.header_bytes_received + pending_frame_.payload_bytes_received;

                if (total_received < total_needed) {
                    // Header complete but payload incomplete - publish partial WSFrameInfo
                    publish_partial_frame_info();
                    parse_offset_ += consumed;
                    return;
                }

                frame_complete = true;
            } else {
                // Start parsing new frame
                consumed = start_parse_frame(pending_frame_, data, linear_avail);
                has_pending_frame_ = true;

                if (!pending_frame_.header_complete) {
                    // Header incomplete - DEFER
                    parse_offset_ += consumed;
                    return;
                }

                // Check if we have complete payload
                uint64_t total_needed = pending_frame_.expected_header_len + pending_frame_.payload_len;
                size_t total_available = consumed + (linear_avail - consumed);

                if (total_available < total_needed) {
                    // Track payload bytes received so far
                    size_t payload_in_this_chunk = linear_avail - pending_frame_.expected_header_len;
                    pending_frame_.payload_bytes_received = payload_in_this_chunk;

                    // Header complete but payload incomplete - publish partial WSFrameInfo
                    publish_partial_frame_info();
                    parse_offset_ += linear_avail;
                    return;
                }

                // Frame complete in single chunk
                pending_frame_.payload_bytes_received = pending_frame_.payload_len;
                frame_complete = true;
                consumed = pending_frame_.expected_header_len + pending_frame_.payload_len;
            }

            if (frame_complete) {
                // Calculate payload offset in MSG_INBOX
                current_payload_offset_ = (data_start_offset_ + parse_offset_ +
                                          pending_frame_.expected_header_len) % MSG_INBOX_SIZE;

                // Recover first packet metadata
                if (accumulated_metadata_count_ > 0) {
                    first_packet_metadata_ = accumulated_metadata_[0];
                }

                // Handle complete frame
                handle_complete_frame();

                // Advance and reset
                parse_offset_ += consumed;
                has_pending_frame_ = false;
                pending_frame_.clear();

                // Reset metadata accumulator for next frame
                accumulated_metadata_count_ = 0;
                if (parse_offset_ < data_accumulated_) {
                    // More data in batch - current meta is start of next frame
                    accumulated_metadata_[accumulated_metadata_count_++] = current_metadata_;
                }
            }
        }

        // All data consumed - reset for next batch
        data_accumulated_ = 0;
        parse_offset_ = 0;
    }

    // ========================================================================
    // Partial Frame WSFrameInfo (header complete, payload incomplete)
    // ========================================================================

    void publish_partial_frame_info() {
        int64_t seq = ws_frame_info_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
            std::abort();
        }

        auto& info = (*ws_frame_info_prod_)[seq];
        info.clear();

        // Payload offset (after header)
        info.msg_inbox_offset = (data_start_offset_ + pending_frame_.expected_header_len) % MSG_INBOX_SIZE;
        info.payload_len = static_cast<uint32_t>(pending_frame_.payload_bytes_received);
        info.frame_total_len = static_cast<uint32_t>(pending_frame_.expected_header_len +
                                                     pending_frame_.payload_bytes_received);
        info.opcode = pending_frame_.opcode;
        info.is_fin = pending_frame_.fin;
        info.is_fragmented = true;       // Partial frame
        info.is_last_fragment = false;   // More data needed

        // Timestamps from accumulated metadata
        populate_timestamps(info);
        info.ws_parse_cycle = rdtscp();

        ws_frame_info_prod_->publish(seq);
    }

    // ========================================================================
    // Complete Frame Handling
    // ========================================================================

    void handle_complete_frame() {
        uint64_t parse_cycle = rdtscp();

        uint8_t opcode = pending_frame_.opcode;
        bool fin = pending_frame_.fin;
        uint64_t payload_len = pending_frame_.payload_len;
        uint32_t frame_total_len = pending_frame_.expected_header_len +
                                   static_cast<uint32_t>(payload_len);

        switch (opcode) {
            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT):
            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::BINARY):
                handle_data_frame(opcode, fin, payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::CONTINUATION):
                handle_continuation_frame(fin, payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::PING):
                handle_ping(payload_len, frame_total_len, parse_cycle);
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::PONG):
                // Ignore PONG frames
                break;

            case static_cast<uint8_t>(websocket::http::WebSocketOpcode::CLOSE):
                handle_close(payload_len);
                break;

            default:
                fprintf(stderr, "[WS-PROCESS] Unknown opcode: 0x%02X\n", opcode);
                break;
        }
    }

    void handle_data_frame(uint8_t opcode, bool fin, uint64_t payload_len,
                          uint32_t frame_total_len, uint64_t parse_cycle) {
        if (fin) {
            // Complete single-frame message
            publish_frame_info(opcode, payload_len, frame_total_len, parse_cycle,
                              false, false);
        } else {
            // First fragment of fragmented message
            accumulating_fragments_ = true;
            fragment_opcode_ = opcode;
            fragment_start_offset_ = current_payload_offset_;
            fragment_total_len_ = static_cast<uint32_t>(payload_len);
            fragment_total_frame_len_ = frame_total_len;
            fragment_first_metadata_ = first_packet_metadata_;

            // Publish WSFrameInfo for first fragment immediately
            publish_frame_info(opcode, payload_len, frame_total_len, parse_cycle,
                              true, false);
        }
    }

    void handle_continuation_frame(bool fin, uint64_t payload_len,
                                   uint32_t frame_total_len, uint64_t parse_cycle) {
        if (!accumulating_fragments_) {
            fprintf(stderr, "[WS-PROCESS] Unexpected continuation frame\n");
            return;
        }

        fragment_total_len_ += static_cast<uint32_t>(payload_len);
        fragment_total_frame_len_ += frame_total_len;

        if (!fin) {
            // Intermediate fragment - publish immediately
            publish_frame_info(fragment_opcode_, payload_len, frame_total_len, parse_cycle,
                              true, false);
        } else {
            // Final fragment - publish with is_last_fragment=true
            publish_frame_info(fragment_opcode_, payload_len, frame_total_len, parse_cycle,
                              true, true);

            // Reset fragment state
            reset_fragment_state();
        }
    }

    void flush_pending_pong() {
        if (!has_pending_ping_) return;

        int64_t pong_seq = pongs_prod_->try_claim();
        if (pong_seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: PONGS full\n");
            std::abort();
        }

        auto& pong = (*pongs_prod_)[pong_seq];
        pong.clear();

        // Build PONG frame now
        const uint8_t* ping_payload = msg_inbox_->data_at(pending_ping_.payload_offset);
        // Use non-zero mask key per RFC 6455 (some servers reject all-zero mask)
        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};

        size_t safe_payload_len = pending_ping_.payload_len;
        if (safe_payload_len > 119) {
            safe_payload_len = 119;
        }

        pong.data_len = static_cast<uint8_t>(websocket::http::build_pong_frame(
            ping_payload, safe_payload_len, pong.data, mask_key));

        pongs_prod_->publish(pong_seq);
        has_pending_ping_ = false;
    }

    void handle_ping(uint64_t payload_len, uint32_t frame_total_len, uint64_t parse_cycle) {
        // Publish WSFrameInfo for PING
        int64_t ws_seq = ws_frame_info_prod_->try_claim();
        if (ws_seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
            std::abort();
        }

        auto& info = (*ws_frame_info_prod_)[ws_seq];
        info.clear();

        info.msg_inbox_offset = current_payload_offset_;
        info.payload_len = static_cast<uint32_t>(payload_len);
        info.frame_total_len = frame_total_len;
        info.opcode = static_cast<uint8_t>(websocket::http::WebSocketOpcode::PING);
        info.is_fin = true;
        info.is_fragmented = false;
        info.is_last_fragment = false;

        populate_timestamps(info);
        info.ws_parse_cycle = parse_cycle;

        ws_frame_info_prod_->publish(ws_seq);

        // If we already have a pending PING, flush it first (new PING arrived)
        if (has_pending_ping_) {
            flush_pending_pong();
        }

        // Store pending PING (don't build PONG yet - deferred to idle)
        pending_ping_.payload_offset = current_payload_offset_;
        pending_ping_.payload_len = static_cast<uint16_t>(payload_len);
        has_pending_ping_ = true;
    }

    void handle_close(uint64_t payload_len) {
        // Signal CLOSE to Transport via MSG_OUTBOX
        int64_t seq = msg_outbox_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: MSG_OUTBOX full for CLOSE\n");
            std::abort();
        }

        auto& event = (*msg_outbox_prod_)[seq];
        event.msg_type = MSG_TYPE_WS_CLOSE;
        event.data_len = 2;

        if (payload_len >= 2) {
            const uint8_t* payload = msg_inbox_->data_at(current_payload_offset_);
            event.data[0] = payload[0];
            event.data[1] = payload[1];
        } else {
            // Default to 1000 (Normal Closure)
            event.data[0] = 0x03;  // 1000 >> 8
            event.data[1] = 0xE8;  // 1000 & 0xFF
        }

        msg_outbox_prod_->publish(seq);

        // Signal shutdown
        conn_state_->shutdown_all();
    }

    void publish_frame_info(uint8_t opcode, uint64_t payload_len, uint32_t frame_total_len,
                           uint64_t parse_cycle, bool is_fragmented, bool is_last_fragment) {
        int64_t seq = ws_frame_info_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
            std::abort();
        }

        auto& info = (*ws_frame_info_prod_)[seq];
        info.clear();

        info.msg_inbox_offset = current_payload_offset_;
        info.payload_len = static_cast<uint32_t>(payload_len);
        info.frame_total_len = frame_total_len;
        info.opcode = opcode;
        info.is_fin = !is_fragmented || is_last_fragment;
        info.is_fragmented = is_fragmented;
        info.is_last_fragment = is_last_fragment;

        populate_timestamps(info);
        info.ws_parse_cycle = parse_cycle;

        ws_frame_info_prod_->publish(seq);

        // Reset accumulator for next message
        reset_accumulator();
    }

    // ========================================================================
    // Timestamp Helpers
    // ========================================================================

    void populate_timestamps(WSFrameInfo& info) {
        if (accumulated_metadata_count_ > 0) {
            const auto& first_meta = accumulated_metadata_[0];
            info.first_byte_ts = first_meta.first_nic_timestamp_ns;
            info.first_nic_frame_poll_cycle = first_meta.first_nic_frame_poll_cycle;
            info.first_ssl_read_cycle = first_meta.ssl_read_cycle;
        }

        info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
        info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
        info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
        info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
        info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);

        // Sum packet counts from all accumulated metadata
        info.nic_packet_ct = 0;
        for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
            info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
        }
    }

    // ========================================================================
    // State Management
    // ========================================================================

    void reset_accumulator() {
        accumulated_metadata_count_ = 0;
    }

    void reset_fragment_state() {
        accumulating_fragments_ = false;
        fragment_opcode_ = 0;
        fragment_start_offset_ = 0;
        fragment_total_len_ = 0;
        fragment_total_frame_len_ = 0;
    }

    // ========================================================================
    // Member Variables
    // ========================================================================

    // Ring buffer interfaces
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataCons* msg_metadata_cons_ = nullptr;
    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    PongsProd* pongs_prod_ = nullptr;
    MsgOutboxProd* msg_outbox_prod_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // Partial frame parsing state
    PartialWebSocketFrame pending_frame_;
    bool has_pending_frame_ = false;
    uint32_t current_payload_offset_ = 0;

    // Wrap-around buffer for WS headers spanning MSG_INBOX wrap point
    uint8_t ws_header_wrap_buffer_[64];

    // Partial frame accumulation
    uint32_t data_start_offset_ = 0;
    uint32_t data_accumulated_ = 0;
    uint32_t parse_offset_ = 0;

    // Timestamp accumulation
    std::array<MsgMetadata, MAX_ACCUMULATED_METADATA> accumulated_metadata_;
    size_t accumulated_metadata_count_ = 0;
    MsgMetadata first_packet_metadata_;
    MsgMetadata current_metadata_;

    // Fragment state (for fragmented WebSocket messages)
    bool accumulating_fragments_ = false;
    uint8_t fragment_opcode_ = 0;
    uint32_t fragment_start_offset_ = 0;
    uint32_t fragment_total_len_ = 0;
    uint32_t fragment_total_frame_len_ = 0;
    MsgMetadata fragment_first_metadata_;

    // Pending PING info (PONG built later when flushing, not on hot path)
    struct PendingPing {
        uint32_t payload_offset;   // MSG_INBOX offset of PING payload
        uint16_t payload_len;      // PING payload length
    };
    PendingPing pending_ping_;
    bool has_pending_ping_ = false;
};

}  // namespace websocket::pipeline
