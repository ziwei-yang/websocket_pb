// pipeline/20_ws_process.hpp
// WebSocket Process - HTTP+WS handshake and frame parsing
// Performs HTTP upgrade handshake after TLS ready, then parses WS frames
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <array>

// pipeline_data.hpp must be included BEFORE pipeline_config.hpp
// to avoid CACHE_LINE_SIZE macro conflict with disruptor
#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"
#include "../core/http.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// WebSocket Frame Header (RFC 6455)
//
// Byte 0: [FIN:1][RSV:3][OPCODE:4]
// Byte 1: [MASK:1][PAYLOAD_LEN:7]
// If PAYLOAD_LEN == 126: Bytes 2-3 = 16-bit length
// If PAYLOAD_LEN == 127: Bytes 2-9 = 64-bit length
// If MASK == 1: 4 bytes masking key follows (client->server only)
//
// Server-to-client frames are NOT masked per RFC 6455
// ============================================================================

// ============================================================================
// PartialWebSocketFrame - State for parsing frames across SSL_reads
// ============================================================================

struct PartialWebSocketFrame {
    // Header parsing state
    uint8_t  header_buf[14];          // Max header: 2 + 8 (extended len) + 4 (mask)
    uint8_t  header_bytes_received;   // Bytes of header received so far
    uint8_t  expected_header_len;     // Total expected header length (2-14)
    bool     header_complete;         // Header fully parsed

    // Parsed header values
    uint8_t  opcode;                  // Frame opcode
    bool     fin;                     // FIN bit
    bool     masked;                  // MASK bit (should be false for server frames)
    uint64_t payload_len;             // Payload length (from header)
    uint8_t  mask_key[4];             // Masking key (if masked)

    // Payload state
    uint64_t payload_bytes_received;  // Bytes of payload received so far

    void clear() {
        header_bytes_received = 0;
        expected_header_len = 2;  // Minimum header size
        header_complete = false;
        opcode = 0;
        fin = false;
        masked = false;
        payload_len = 0;
        payload_bytes_received = 0;
    }

    bool is_complete() const {
        return header_complete && payload_bytes_received >= payload_len;
    }

    uint64_t payload_remaining() const {
        return payload_len - payload_bytes_received;
    }
};

// ============================================================================
// WebSocket Parser Functions
// ============================================================================

// Calculate expected header length from first 2 bytes
inline uint8_t calculate_header_len(uint8_t byte0, uint8_t byte1) {
    uint8_t len = 2;  // Base header

    // Check payload length field
    uint8_t payload_len_field = byte1 & 0x7F;
    if (payload_len_field == 126) {
        len += 2;  // 16-bit extended length
    } else if (payload_len_field == 127) {
        len += 8;  // 64-bit extended length
    }

    // Check mask bit
    if (byte1 & 0x80) {
        len += 4;  // Masking key
    }

    return len;
}

// Parse completed header buffer
// Call after header_complete == true
inline void parse_completed_header(PartialWebSocketFrame& frame) {
    const uint8_t* h = frame.header_buf;

    // Byte 0: FIN + opcode
    frame.fin = (h[0] & 0x80) != 0;
    frame.opcode = h[0] & 0x0F;

    // Byte 1: MASK + payload length
    frame.masked = (h[1] & 0x80) != 0;
    uint8_t len_field = h[1] & 0x7F;

    // Parse payload length
    size_t offset = 2;
    if (len_field < 126) {
        frame.payload_len = len_field;
    } else if (len_field == 126) {
        frame.payload_len = (static_cast<uint64_t>(h[2]) << 8) |
                            static_cast<uint64_t>(h[3]);
        offset = 4;
    } else {  // len_field == 127
        frame.payload_len = (static_cast<uint64_t>(h[2]) << 56) |
                            (static_cast<uint64_t>(h[3]) << 48) |
                            (static_cast<uint64_t>(h[4]) << 40) |
                            (static_cast<uint64_t>(h[5]) << 32) |
                            (static_cast<uint64_t>(h[6]) << 24) |
                            (static_cast<uint64_t>(h[7]) << 16) |
                            (static_cast<uint64_t>(h[8]) << 8) |
                            static_cast<uint64_t>(h[9]);
        offset = 10;
    }

    // Parse masking key if present
    if (frame.masked) {
        std::memcpy(frame.mask_key, h + offset, 4);
    }
}

// Start parsing a new frame
// Returns bytes consumed from data
// Sets frame.header_complete if header is fully received
inline size_t start_parse_frame(PartialWebSocketFrame& frame,
                                const uint8_t* data, size_t len) {
    frame.clear();

    if (len == 0) return 0;

    size_t consumed = 0;

    // Read first byte
    frame.header_buf[0] = data[0];
    frame.header_bytes_received = 1;
    consumed = 1;

    if (len < 2) {
        // Need more data for second byte
        return consumed;
    }

    // Read second byte and calculate header length
    frame.header_buf[1] = data[1];
    frame.header_bytes_received = 2;
    frame.expected_header_len = calculate_header_len(data[0], data[1]);
    consumed = 2;

    // Try to complete header
    size_t header_remaining = frame.expected_header_len - 2;
    size_t available = len - 2;
    size_t to_copy = (available < header_remaining) ? available : header_remaining;

    if (to_copy > 0) {
        std::memcpy(frame.header_buf + 2, data + 2, to_copy);
        frame.header_bytes_received += to_copy;
        consumed += to_copy;
    }

    if (frame.header_bytes_received >= frame.expected_header_len) {
        frame.header_complete = true;
        parse_completed_header(frame);
    }

    return consumed;
}

// Continue parsing partial frame (header or payload)
// Returns bytes consumed from data
inline size_t continue_partial_frame(PartialWebSocketFrame& frame,
                                     const uint8_t* data, size_t len) {
    if (len == 0) return 0;

    size_t consumed = 0;

    // Complete header if needed
    if (!frame.header_complete) {
        // Need second byte to know header length
        if (frame.header_bytes_received == 1) {
            frame.header_buf[1] = data[0];
            frame.header_bytes_received = 2;
            frame.expected_header_len = calculate_header_len(frame.header_buf[0],
                                                             frame.header_buf[1]);
            consumed = 1;
        }

        // Read remaining header bytes
        size_t header_remaining = frame.expected_header_len - frame.header_bytes_received;
        size_t available = len - consumed;
        size_t to_copy = (available < header_remaining) ? available : header_remaining;

        if (to_copy > 0) {
            std::memcpy(frame.header_buf + frame.header_bytes_received,
                        data + consumed, to_copy);
            frame.header_bytes_received += to_copy;
            consumed += to_copy;
        }

        if (frame.header_bytes_received >= frame.expected_header_len) {
            frame.header_complete = true;
            parse_completed_header(frame);
        }
    }

    // Note: Payload tracking is done externally by WebSocketProcess
    // since payload is written directly to MSG_INBOX

    return consumed;
}

// Unmask payload in place (if masked)
// For client->server masking only; server->client is not masked
inline void unmask_payload(uint8_t* payload, size_t len, const uint8_t* mask_key) {
    // Optimize for common case of 4-byte aligned data
    size_t i = 0;

    // Process 4 bytes at a time if possible
    if (len >= 4) {
        uint32_t mask32;
        std::memcpy(&mask32, mask_key, 4);

        for (; i + 4 <= len; i += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(payload + i);
            *p ^= mask32;
        }
    }

    // Handle remaining bytes
    for (; i < len; i++) {
        payload[i] ^= mask_key[i & 3];
    }
}

// Build WebSocket frame header
// Returns header length (2-14 bytes written to header_buf)
inline size_t build_ws_header(uint8_t* header_buf, uint8_t opcode, size_t payload_len,
                              bool fin = true, bool mask = true,
                              const uint8_t* mask_key = nullptr) {
    size_t offset = 0;

    // Byte 0: FIN + opcode
    header_buf[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
    offset = 1;

    // Byte 1: MASK + payload length
    uint8_t mask_bit = mask ? 0x80 : 0x00;

    if (payload_len < 126) {
        header_buf[1] = mask_bit | static_cast<uint8_t>(payload_len);
        offset = 2;
    } else if (payload_len <= 65535) {
        header_buf[1] = mask_bit | 126;
        header_buf[2] = static_cast<uint8_t>(payload_len >> 8);
        header_buf[3] = static_cast<uint8_t>(payload_len & 0xFF);
        offset = 4;
    } else {
        header_buf[1] = mask_bit | 127;
        header_buf[2] = static_cast<uint8_t>(payload_len >> 56);
        header_buf[3] = static_cast<uint8_t>(payload_len >> 48);
        header_buf[4] = static_cast<uint8_t>(payload_len >> 40);
        header_buf[5] = static_cast<uint8_t>(payload_len >> 32);
        header_buf[6] = static_cast<uint8_t>(payload_len >> 24);
        header_buf[7] = static_cast<uint8_t>(payload_len >> 16);
        header_buf[8] = static_cast<uint8_t>(payload_len >> 8);
        header_buf[9] = static_cast<uint8_t>(payload_len & 0xFF);
        offset = 10;
    }

    // Masking key (client->server only)
    if (mask && mask_key) {
        std::memcpy(header_buf + offset, mask_key, 4);
        offset += 4;
    }

    return offset;
}

// Generate random mask key
inline void generate_mask_key(uint8_t* mask_key) {
    // Simple PRNG for masking (doesn't need to be cryptographic)
    static uint32_t seed = 0x12345678;
    seed = seed * 1103515245 + 12345;
    std::memcpy(mask_key, &seed, 4);
}

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
                maybe_send_client_ping();
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

        { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
          fprintf(stderr, "[%ld.%06ld] [WS-EVENT] seq=%ld len=%u\n",
                  _ts.tv_sec, _ts.tv_nsec / 1000, sequence, meta.decrypted_len); }

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

        // Pre-count complete frames for M/N batch display
        batch_total_frames_ = count_complete_frames_in_buffer();
        batch_frame_index_ = 0;

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
                handle_pong(payload_len);
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
            msg_count_++;
            batch_frame_index_++;
            const char* opcode_str = (opcode == static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT))
                                     ? "TEXT" : "BINARY";

            // Format message preview (truncate to 120 chars for logging)
            const uint8_t* msg_data = msg_inbox_->data_at(current_payload_offset_);
            char msg_preview[256] = {0};
            size_t preview_len = std::min(payload_len, uint64_t(120));
            if (opcode == static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT)) {
                // TEXT: copy as string, escape non-printable
                size_t j = 0;
                for (size_t i = 0; i < preview_len && j < 240; i++) {
                    uint8_t c = msg_data[i];
                    if (c >= 32 && c < 127) {
                        msg_preview[j++] = static_cast<char>(c);
                    } else if (c == '\n') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 'n';
                    } else if (c == '\r') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 'r';
                    } else if (c == '\t') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 't';
                    } else {
                        j += snprintf(msg_preview + j, 5, "\\x%02x", c);
                    }
                }
                msg_preview[j] = '\0';
            } else {
                // BINARY: hex format
                for (size_t i = 0; i < std::min(preview_len, size_t(40)); i++) {
                    snprintf(msg_preview + i * 2, 3, "%02x", msg_data[i]);
                }
            }
            if (payload_len > 120) {
                strncat(msg_preview, "...", 4);
            }

            // Get current Unix time in milliseconds
            auto now = std::chrono::system_clock::now();
            int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

            { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
              fprintf(stderr, "[%ld.%06ld] [WS-MSG] #%lu %zu/%zu received: opcode=%s payload_len=%lu nic_ts=%lu ns unix_ts=%ld ms text=[%s]\n",
                      _ts.tv_sec, _ts.tv_nsec / 1000, msg_count_, batch_frame_index_, batch_total_frames_, opcode_str, payload_len, current_metadata_.latest_nic_timestamp_ns, unix_ms, msg_preview); }
            print_ssl_read_timeline();

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
            // Final fragment - log complete fragmented message
            msg_count_++;
            batch_frame_index_++;
            const char* opcode_str = (fragment_opcode_ == static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT))
                                     ? "TEXT" : "BINARY";

            // Format message preview from first fragment (truncate to 120 chars)
            const uint8_t* msg_data = msg_inbox_->data_at(fragment_start_offset_);
            char msg_preview[256] = {0};
            size_t preview_len = std::min(static_cast<size_t>(fragment_total_len_), size_t(120));
            if (fragment_opcode_ == static_cast<uint8_t>(websocket::http::WebSocketOpcode::TEXT)) {
                size_t j = 0;
                for (size_t i = 0; i < preview_len && j < 240; i++) {
                    uint8_t c = msg_data[i];
                    if (c >= 32 && c < 127) {
                        msg_preview[j++] = static_cast<char>(c);
                    } else if (c == '\n') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 'n';
                    } else if (c == '\r') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 'r';
                    } else if (c == '\t') {
                        msg_preview[j++] = '\\';
                        msg_preview[j++] = 't';
                    } else {
                        j += snprintf(msg_preview + j, 5, "\\x%02x", c);
                    }
                }
                msg_preview[j] = '\0';
            } else {
                for (size_t i = 0; i < std::min(preview_len, size_t(40)); i++) {
                    snprintf(msg_preview + i * 2, 3, "%02x", msg_data[i]);
                }
            }
            if (fragment_total_len_ > 120) {
                strncat(msg_preview, "...", 4);
            }

            // Get current Unix time in milliseconds
            auto now = std::chrono::system_clock::now();
            int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

            { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
              fprintf(stderr, "[%ld.%06ld] [WS-MSG] #%lu %zu/%zu received: opcode=%s payload_len=%u nic_ts=%lu ns unix_ts=%ld ms text=[%s] (fragmented)\n",
                      _ts.tv_sec, _ts.tv_nsec / 1000, msg_count_, batch_frame_index_, batch_total_frames_, opcode_str, fragment_total_len_, current_metadata_.latest_nic_timestamp_ns, unix_ms, msg_preview); }
            print_ssl_read_timeline();

            // Final fragment - publish with is_last_fragment=true
            publish_frame_info(fragment_opcode_, payload_len, frame_total_len, parse_cycle,
                              true, true);

            // Reset fragment state
            reset_fragment_state();
        }
    }

    void flush_pending_pong() {
        if (!has_pending_ping_) return;

        uint64_t flush_cycle = rdtscp();
        uint64_t queue_latency_cycles = flush_cycle - pending_ping_.recv_cycle;
        // Convert to nanoseconds (assuming ~2.5GHz TSC)
        uint64_t queue_latency_ns = queue_latency_cycles * 1000 / (conn_state_->tsc_freq_hz / 1000000);

        pong_count_++;

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

        // Format payload as ASCII string for logging
        char pong_payload_ascii[32] = {0};
        size_t ascii_len = std::min(safe_payload_len, size_t(31));
        for (size_t i = 0; i < ascii_len; i++) {
            pong_payload_ascii[i] = static_cast<char>(ping_payload[i]);
        }

        { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
          fprintf(stderr, "[%ld.%06ld] [WS-PONG] #%lu queued: payload_len=%u queue_latency=%lu ns payload=[%s]\n",
                  _ts.tv_sec, _ts.tv_nsec / 1000, pong_count_, pending_ping_.payload_len, queue_latency_ns, pong_payload_ascii);
        }

        has_pending_ping_ = false;
    }

    void handle_ping(uint64_t payload_len, uint32_t frame_total_len, uint64_t parse_cycle) {
        ping_count_++;
        uint64_t recv_cycle = rdtscp();
        uint64_t recv_nic_ts_ns = current_metadata_.latest_nic_timestamp_ns;

        // Get current Unix time in milliseconds
        auto now = std::chrono::system_clock::now();
        int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        // Get payload pointer
        const uint8_t* ping_payload = msg_inbox_->data_at(current_payload_offset_);

        // Parse payload as ASCII string (Binance sends timestamp as ASCII digits)
        char payload_ascii[32] = {0};
        size_t ascii_len = std::min(payload_len, uint64_t(31));
        for (size_t i = 0; i < ascii_len; i++) {
            payload_ascii[i] = static_cast<char>(ping_payload[i]);
        }

        // Parse as timestamp if 13 digits (millisecond Unix timestamp)
        int64_t payload_ms = 0;
        int64_t diff_ms = 0;
        if (payload_len == 13) {
            payload_ms = std::strtoll(payload_ascii, nullptr, 10);
            diff_ms = unix_ms - payload_ms;
        }

        { struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
          if (payload_ms > 0) {
              fprintf(stderr, "[%ld.%06ld] [WS-PING] #%lu received: payload_len=%lu payload=[%s] diff_ms=%ld\n",
                      _ts.tv_sec, _ts.tv_nsec / 1000, ping_count_, payload_len, payload_ascii, diff_ms);
          } else {
              fprintf(stderr, "[%ld.%06ld] [WS-PING] #%lu received: payload_len=%lu payload=[%s]\n",
                      _ts.tv_sec, _ts.tv_nsec / 1000, ping_count_, payload_len, payload_ascii);
          }
        }

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
            fprintf(stderr, "[WS-PING] WARNING: New PING arrived before previous PONG sent, flushing old PONG\n");
            flush_pending_pong();
        }

        // Store pending PING (don't build PONG yet - deferred to idle)
        pending_ping_.payload_offset = current_payload_offset_;
        pending_ping_.payload_len = static_cast<uint16_t>(payload_len);
        pending_ping_.recv_cycle = recv_cycle;
        pending_ping_.recv_nic_ts_ns = recv_nic_ts_ns;
        has_pending_ping_ = true;
    }

    void handle_close(uint64_t payload_len) {
        // Extract and log CLOSE frame details
        uint16_t close_code = 1005;  // RFC 6455: "No Status Rcvd" if no status code present
        const uint8_t* payload = nullptr;

        if (payload_len >= 2) {
            payload = msg_inbox_->data_at(current_payload_offset_);
            close_code = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
        }

        // Log close code with meaning
        const char* close_meaning = "";
        switch (close_code) {
            case 1000: close_meaning = "Normal Closure"; break;
            case 1001: close_meaning = "Going Away"; break;
            case 1002: close_meaning = "Protocol Error"; break;
            case 1003: close_meaning = "Unsupported Data"; break;
            case 1005: close_meaning = "No Status Rcvd"; break;
            case 1006: close_meaning = "Abnormal Closure"; break;
            case 1007: close_meaning = "Invalid Payload Data"; break;
            case 1008: close_meaning = "Policy Violation"; break;
            case 1009: close_meaning = "Message Too Big"; break;
            case 1010: close_meaning = "Mandatory Extension"; break;
            case 1011: close_meaning = "Internal Server Error"; break;
            case 1012: close_meaning = "Service Restart"; break;
            case 1013: close_meaning = "Try Again Later"; break;
            case 1014: close_meaning = "Bad Gateway"; break;
            case 1015: close_meaning = "TLS Handshake"; break;
            default:
                if (close_code >= 3000 && close_code < 4000) close_meaning = "Registered (IANA)";
                else if (close_code >= 4000 && close_code < 5000) close_meaning = "Private Use";
                else close_meaning = "Unknown";
                break;
        }

        // Extract reason text if present
        char close_reason[128] = {0};
        if (payload_len > 2 && payload != nullptr) {
            size_t reason_len = std::min(payload_len - 2, static_cast<uint64_t>(sizeof(close_reason) - 1));
            std::memcpy(close_reason, payload + 2, reason_len);
            close_reason[reason_len] = '\0';
        }

        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  [WS-CLOSE] CLOSE FRAME RECEIVED                                 ║\n");
        fprintf(stderr, "╠══════════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Code:   %u (%s)%*s║\n",
                close_code, close_meaning, (int)(47 - strlen(close_meaning)), "");
        if (close_reason[0] != '\0') {
            fprintf(stderr, "║  Reason: %-55s║\n", close_reason);
        }
        fprintf(stderr, "║  Payload length: %-48lu║\n", payload_len);
        fprintf(stderr, "╚══════════════════════════════════════════════════════════════════╝\n");

        // Signal shutdown to all processes - Transport will call on_finished()
        conn_state_->shutdown_all();

        // Signal shutdown
        conn_state_->shutdown_all();
    }

    void handle_pong(uint64_t payload_len) {
        // Get current time immediately
        auto now = std::chrono::system_clock::now();
        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        // Read payload
        const uint8_t* payload = msg_inbox_->data_at(current_payload_offset_);
        char payload_ascii[32] = {0};
        size_t ascii_len = std::min(payload_len, uint64_t(31));
        for (size_t i = 0; i < ascii_len; i++)
            payload_ascii[i] = static_cast<char>(payload[i]);

        // Parse as timestamp and compute RTT
        int64_t payload_ms = std::strtoll(payload_ascii, nullptr, 10);
        int64_t rtt_ms = now_ms - payload_ms;

        // Clear watchdog — PONG received
        awaiting_client_pong_ = false;

        // Log
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-CLIENT-PONG] received: payload=[%s] rtt_ms=%ld\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, payload_ascii, rtt_ms);
    }

    void maybe_send_client_ping() {
        uint64_t now_cycle = rdtscp();
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;

        // First call: initialize and skip (don't PING during handshake warmup)
        if (last_client_ping_cycle_ == 0) {
            last_client_ping_cycle_ = now_cycle;
            return;
        }

        // Check if 1 second has elapsed since last PING
        uint64_t elapsed_ns = cycles_to_ns(now_cycle - last_client_ping_cycle_, tsc_freq);
        if (elapsed_ns < 1000000000ULL) return;

        // If awaiting PONG from previous PING
        if (awaiting_client_pong_) {
            uint64_t since_ping_ns = cycles_to_ns(now_cycle - last_client_ping_cycle_, tsc_freq);
            uint64_t since_ping_s = since_ping_ns / 1000000000ULL;

            // Log warning every 1s (throttled)
            uint64_t since_warning_ns = cycles_to_ns(now_cycle - last_pong_warning_cycle_, tsc_freq);
            if (since_warning_ns >= 1000000000ULL) {
                struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                fprintf(stderr, "[%ld.%06ld] [WS-CLIENT-PING] WARNING: no PONG for %lus\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000, (unsigned long)since_ping_s);
                last_pong_warning_cycle_ = now_cycle;
            }

            // Abort after 10s with no PONG
            if (since_ping_s >= 10) {
                struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                fprintf(stderr, "[%ld.%06ld] [WS-CLIENT-PING] FATAL: no PONG for 10s, aborting\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000);
                std::abort();
            }

            return;  // Don't send new PING while awaiting PONG
        }

        // Build payload: current system_clock -> Unix-ms -> ASCII string
        auto now = std::chrono::system_clock::now();
        int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        char payload_ascii[16];
        int payload_len = snprintf(payload_ascii, sizeof(payload_ascii), "%ld", unix_ms);

        // Build PING frame into PongFrameAligned (reuse same ring for control frames)
        int64_t seq = pongs_prod_->try_claim();
        if (seq < 0) {
            // Ring full — skip this PING, will retry next second
            return;
        }

        auto& frame = (*pongs_prod_)[seq];
        frame.clear();

        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};
        frame.data_len = static_cast<uint8_t>(websocket::http::build_ping_frame(
            reinterpret_cast<const uint8_t*>(payload_ascii),
            static_cast<size_t>(payload_len),
            frame.data, mask_key));

        pongs_prod_->publish(seq);

        // Update state
        client_ping_count_++;
        last_client_ping_cycle_ = now_cycle;
        last_client_ping_ms_ = unix_ms;
        awaiting_client_pong_ = true;
        last_pong_warning_cycle_ = now_cycle;

        // Log
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [WS-CLIENT-PING] #%lu sent: payload=[%s]\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, client_ping_count_, payload_ascii);
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
            info.first_bpf_entry_ns = first_meta.first_bpf_entry_ns;
            info.first_poll_cycle = first_meta.first_nic_frame_poll_cycle;
            info.first_ssl_read_cycle = first_meta.ssl_read_cycle;
            info.first_ssl_read_id = first_meta.ssl_read_id;
        }

        info.latest_ssl_read_id = current_metadata_.ssl_read_id;
        info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
        info.latest_bpf_entry_ns = current_metadata_.latest_bpf_entry_ns;
        info.latest_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
        info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
        info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);

        // Sum packet counts from all accumulated metadata
        info.nic_packet_ct = 0;
        for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
            info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
        }
    }

    // ========================================================================
    // Per-SSL_read Timeline Debug Print
    // ========================================================================

    void print_ssl_read_timeline() {
        if (accumulated_metadata_count_ == 0) return;

        struct timespec ts_mono;
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        uint64_t mono_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;
        uint64_t now_cycle = rdtscp();
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;

        for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
            const auto& m = accumulated_metadata_[i];

            // BPF timestamps (CLOCK_MONOTONIC ns -> "us ago")
            double first_bpf_ago_us = (m.first_bpf_entry_ns > 0)
                ? (double)(mono_now_ns - m.first_bpf_entry_ns) / 1000.0 : 0;
            double latest_bpf_ago_us = (m.latest_bpf_entry_ns > 0)
                ? (double)(mono_now_ns - m.latest_bpf_entry_ns) / 1000.0 : 0;

            // Poll cycles (TSC -> "us ago")
            double first_poll_ago_us = (m.first_nic_frame_poll_cycle > 0 && tsc_freq > 0)
                ? cycles_to_ns(now_cycle - m.first_nic_frame_poll_cycle, tsc_freq) / 1000.0 : 0;
            double latest_poll_ago_us = (m.latest_nic_frame_poll_cycle > 0 && tsc_freq > 0)
                ? cycles_to_ns(now_cycle - m.latest_nic_frame_poll_cycle, tsc_freq) / 1000.0 : 0;

            // Format BPF field
            char bpf_str[64];
            if (m.first_bpf_entry_ns == 0) {
                snprintf(bpf_str, sizeof(bpf_str), "N/A");
            } else if (m.nic_packet_ct <= 1 || m.first_bpf_entry_ns == m.latest_bpf_entry_ns) {
                snprintf(bpf_str, sizeof(bpf_str), "%.1fus ago", latest_bpf_ago_us);
            } else {
                snprintf(bpf_str, sizeof(bpf_str), "%.1f ~ %.1fus ago",
                         first_bpf_ago_us, latest_bpf_ago_us);
            }

            // Format poll field
            char poll_str[64];
            if (m.first_nic_frame_poll_cycle == 0) {
                snprintf(poll_str, sizeof(poll_str), "N/A");
            } else if (m.nic_packet_ct <= 1 || m.first_nic_frame_poll_cycle == m.latest_nic_frame_poll_cycle) {
                snprintf(poll_str, sizeof(poll_str), "%.1fus ago", latest_poll_ago_us);
            } else {
                snprintf(poll_str, sizeof(poll_str), "%.1f ~ %.1fus ago",
                         first_poll_ago_us, latest_poll_ago_us);
            }

            fprintf(stderr, "  | ssl_read %lu | packets %u | NIC ~ | BPF %s | poll %s |\n",
                    m.ssl_read_id, m.nic_packet_ct, bpf_str, poll_str);
        }
    }

    // ========================================================================
    // Batch Frame Counting
    // ========================================================================

    size_t count_complete_frames_in_buffer() {
        size_t count = 0;
        uint32_t scan = parse_offset_;

        // If continuing a partial frame, that's the first "frame"
        if (has_pending_frame_ && pending_frame_.header_complete) {
            uint64_t remaining = pending_frame_.payload_len - pending_frame_.payload_bytes_received;
            if (remaining <= (data_accumulated_ - scan)) {
                count++;
                scan += remaining;
            } else {
                return 0;  // Partial frame can't complete
            }
        }

        // Count remaining complete frames
        while (scan < data_accumulated_) {
            uint32_t offset = (data_start_offset_ + scan) % MSG_INBOX_SIZE;
            const uint8_t* data = msg_inbox_->data_at(offset);
            size_t avail = data_accumulated_ - scan;

            if (avail < 2) break;

            uint8_t hdr_len = calculate_header_len(data[0], data[1]);
            if (avail < hdr_len) break;

            uint8_t len_field = data[1] & 0x7F;
            uint64_t payload_len;
            if (len_field < 126) {
                payload_len = len_field;
            } else if (len_field == 126) {
                payload_len = (uint64_t(data[2]) << 8) | data[3];
            } else {
                payload_len = 0;
                for (int k = 2; k < 10; k++)
                    payload_len = (payload_len << 8) | data[k];
            }

            if (avail < hdr_len + payload_len) break;
            count++;
            scan += hdr_len + payload_len;
        }

        return count;
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
        uint64_t recv_cycle;       // TSC when PING was received
        uint64_t recv_nic_ts_ns;   // NIC timestamp when PING arrived
    };
    PendingPing pending_ping_;
    bool has_pending_ping_ = false;
    uint64_t ping_count_ = 0;      // Total PINGs received
    uint64_t pong_count_ = 0;      // Total PONGs sent
    uint64_t msg_count_ = 0;       // Total TEXT/BINARY messages received

    // Client-initiated PING state (for RTT measurement)
    uint64_t client_ping_count_ = 0;
    uint64_t last_client_ping_cycle_ = 0;   // TSC of last client PING sent
    int64_t  last_client_ping_ms_ = 0;      // Unix-ms payload of last client PING
    bool     awaiting_client_pong_ = false;  // true after PING sent, cleared on PONG receipt
    uint64_t last_pong_warning_cycle_ = 0;  // TSC of last "no PONG" warning (for 1s throttle)

    // Batch frame counting (M/N format in [WS-MSG] output)
    size_t batch_total_frames_ = 0;    // Total frames in current on_event batch
    size_t batch_frame_index_ = 0;     // Current frame position (1-based)
};

}  // namespace websocket::pipeline
