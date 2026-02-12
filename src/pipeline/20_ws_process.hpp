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
#include <concepts>

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
// Non-blocking state machine:
//   DISCONNECTED  → waiting for TLS_CONNECTED event from Transport
//   WS_UPGRADE_SENT → HTTP upgrade sent, accumulating 101 response
//   ACTIVE         → normal WS frame parsing
//
// When AutoReconnect:
//   Both initial connect and reconnect use the same state machine.
//   WS starts in DISCONNECTED, Transport publishes TLS_CONNECTED when ready.
//
// When !AutoReconnect:
//   perform_handshake() blocks waiting for tls_ready, then does blocking
//   HTTP upgrade. Then run() enters main loop with all connections ACTIVE.
//
// Responsibilities:
// 1. Consume MsgMetadata from MSG_METADATA ring via on_event()
// 2. Dispatch on event_type and ws_phase (state machine)
// 3. Parse WebSocket frames from MSG_INBOX data
// 4. Handle control frames: PING -> PONGS + WSFrameInfo, CLOSE -> reconnect
// 5. Publish WSFrameInfo for TEXT/BINARY to AppClient
// 6. Track partial frames across SSL_read boundaries
// ============================================================================

// ============================================================================
// AppHandler Concept + NullAppHandler
//
// AppHandler is an inline callback invoked by WebSocketProcess for each
// complete TEXT/BINARY frame. When AppHandler::enabled is true, the
// WSFrameInfo ring is skipped entirely — the handler replaces it.
// ============================================================================

template<typename T>
concept AppHandlerConcept = requires(T handler,
                                     uint8_t connection_id,
                                     uint8_t opcode,
                                     const uint8_t* payload,
                                     uint32_t payload_len,
                                     const WSFrameInfo& info) {
    { T::enabled } -> std::convertible_to<bool>;
    { handler.on_ws_frame(connection_id, opcode, payload, payload_len, info) };
};

// Default: no-op handler that compiles away entirely
struct NullAppHandler {
    static constexpr bool enabled = false;
    void on_ws_frame(uint8_t, uint8_t, const uint8_t*, uint32_t, const WSFrameInfo&) {}
};

static_assert(AppHandlerConcept<NullAppHandler>);

// ============================================================================
// UpgradeCustomizer Concept + NullUpgradeCustomizer
//
// UpgradeCustomizer allows test binaries to inject custom HTTP headers
// into the WebSocket upgrade request (e.g., X-MBX-APIKEY for Binance SBE).
// Default NullUpgradeCustomizer is a no-op — zero behavioral change.
// ============================================================================

struct NullUpgradeCustomizer {
    static void customize(const ConnStateShm*,
        std::vector<std::pair<std::string, std::string>>&) {}
};

template<typename T>
concept UpgradeCustomizerConcept = requires(
    const ConnStateShm* cs,
    std::vector<std::pair<std::string, std::string>>& headers) {
    { T::customize(cs, headers) };
};

static_assert(UpgradeCustomizerConcept<NullUpgradeCustomizer>);

// Maximum metadata entries to accumulate before forced commit
constexpr size_t MAX_ACCUMULATED_METADATA = 64;

// Handshake timeout in milliseconds (for non-AutoReconnect blocking path)
constexpr uint64_t HANDSHAKE_TIMEOUT_MS = 10000;

// Partial HTTP response accumulation for handshake
struct PartialHttpResponse {
    uint8_t buffer[4096];
    size_t accumulated = 0;
    bool headers_complete = false;
    size_t headers_end = 0;  // Position after \r\n\r\n (first WS byte)

    void clear() {
        accumulated = 0;
        headers_complete = false;
        headers_end = 0;
    }

    // Check if we have complete HTTP headers (ends with \r\n\r\n)
    bool try_complete() {
        if (accumulated < 4) return false;
        for (size_t i = 0; i <= accumulated - 4; ++i) {
            if (buffer[i] == '\r' && buffer[i+1] == '\n' &&
                buffer[i+2] == '\r' && buffer[i+3] == '\n') {
                headers_complete = true;
                headers_end = i + 4;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// WsConnPhase - Per-connection state for WebSocket process
// ============================================================================

enum class WsConnPhase : uint8_t {
    ACTIVE = 0,          // Normal WS frame parsing
    DISCONNECTED,        // Waiting for TLS_CONNECTED event from Transport
    WS_UPGRADE_SENT,     // HTTP upgrade sent, accumulating 101 response
};

// Template parameters for each ring type used by WebSocketProcess
template<typename MsgMetadataCons,     // IPCRingConsumer<MsgMetadata>
         typename WSFrameInfoProd,     // IPCRingProducer<WSFrameInfo>
         typename PongsProd,           // IPCRingProducer<PongFrameAligned>
         typename MsgOutboxProd,       // IPCRingProducer<MsgOutboxEvent>
         bool EnableAB = false,
         bool AutoReconnect = false,
         bool Profiling = false,
         AppHandlerConcept AppHandler = NullAppHandler,
         UpgradeCustomizerConcept UpgradeCustomizer = NullUpgradeCustomizer>
struct WebSocketProcess {
public:
    static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;
    static constexpr bool HasAppHandler = AppHandler::enabled;

    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(MsgInbox* msg_inbox,
              MsgMetadataCons* msg_metadata_cons,
              WSFrameInfoProd* ws_frame_info_prod,
              PongsProd* pongs_prod,
              MsgOutboxProd* msg_outbox_prod,
              ConnStateShm* conn_state,
              MsgInbox* msg_inbox_b = nullptr,
              MsgMetadataCons* msg_metadata_cons_b = nullptr) {

        msg_inbox_[0] = msg_inbox;
        msg_metadata_cons_[0] = msg_metadata_cons;
        if constexpr (!HasAppHandler) {
            ws_frame_info_prod_ = ws_frame_info_prod;
        }
        pongs_prod_ = pongs_prod;
        msg_outbox_prod_ = msg_outbox_prod;
        conn_state_ = conn_state;

        if constexpr (EnableAB) {
            msg_inbox_[1] = msg_inbox_b;
            msg_metadata_cons_[1] = msg_metadata_cons_b;
        }

        for (size_t i = 0; i < NUM_CONN; i++) {
            pending_frame_[i].clear();
            has_pending_frame_[i] = false;
            reset_accumulator(i);
            reset_fragment_state(i);
            has_pending_ping_[i] = false;

            if constexpr (AutoReconnect) {
                // AutoReconnect: start DISCONNECTED, wait for TLS_CONNECTED
                ws_phase_[i] = WsConnPhase::DISCONNECTED;
                http_response_[i].clear();
            } else {
                // Non-AutoReconnect: will be set ACTIVE after perform_handshake()
                ws_phase_[i] = WsConnPhase::ACTIVE;
            }
        }

        printf("[WS-PROCESS] Initialized%s%s\n",
               EnableAB ? " (Dual A/B)" : "",
               AutoReconnect ? " (AutoReconnect)" : "");
        return true;
    }

    // ========================================================================
    // Phase 1: Blocking Handshake (non-AutoReconnect only)
    // ========================================================================

    bool perform_handshake() {
        static_assert(!AutoReconnect,
            "perform_handshake() should not be called with AutoReconnect");

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

        // Connection A: HTTP upgrade + subscription
        send_http_upgrade_request(0);
        if (!recv_http_upgrade_response_blocking(0)) {
            fprintf(stderr, "[WS-PROCESS] HTTP upgrade failed (conn A)\n");
            return false;
        }
        printf("[WS-PROCESS] HTTP 101 received (conn A), sending subscription\n");
        send_subscription_message(0);

        if constexpr (EnableAB) {
            // Connection B: HTTP upgrade + subscription
            send_http_upgrade_request(1);
            if (!recv_http_upgrade_response_blocking(1)) {
                fprintf(stderr, "[WS-PROCESS] HTTP upgrade failed (conn B)\n");
                return false;
            }
            printf("[WS-PROCESS] HTTP 101 received (conn B), sending subscription\n");
            send_subscription_message(1);
        }

        // Signal ws_ready
        conn_state_->set_handshake_ws_ready();
        printf("[WS-PROCESS] Handshake complete%s, ws_ready signaled\n",
               EnableAB ? " (both A/B)" : "");

        // All connections start ACTIVE
        for (size_t i = 0; i < NUM_CONN; i++) {
            ws_phase_[i] = WsConnPhase::ACTIVE;
        }

        return true;
    }

    // ========================================================================
    // Phase 2: Main Loop (event_processor pattern)
    // ========================================================================

    void run() {
        printf("[WS-PROCESS] Running main loop%s%s\n",
               EnableAB ? " (Dual A/B)" : "",
               AutoReconnect ? " (AutoReconnect)" : "");
        conn_state_->set_ready(PROC_WEBSOCKET);

        while (conn_state_->is_running(PROC_WEBSOCKET)) {
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                slot = profiling_data_->next_slot();
            }

            // ── Consume metadata for ALL connections — ALWAYS ──
            // Never let ring back up, even for DISCONNECTED connections.
            // The on_event() dispatcher handles state-based routing.

            // Op 0: metadata consume + commit (connection A / single)
            int32_t processed = 0;
            processed = profile_op<Profiling>([this]() -> int32_t {
                [[maybe_unused]] bool first_meta = true;
                size_t p = msg_metadata_cons_[0]->process_manually(
                    [this, &first_meta](MsgMetadata& meta, int64_t seq, bool end_of_batch) {
                        if constexpr (Profiling) {
                            if (first_meta) {
                                first_consumed_poll_cycle_ = meta.first_nic_frame_poll_cycle;
                                first_meta = false;
                            }
                        }
                        on_event(0, meta, seq, end_of_batch);
                        return true;
                    }, MAX_ACCUMULATED_METADATA);
                if (p > 0) {
                    msg_metadata_cons_[0]->commit_manually();
                    last_op_cycle_ = rdtscp();
                }
                return static_cast<int32_t>(p);
            }, slot, 0);

            // Op 1: ping/pong (idle only)
            bool idle = (processed == 0);

            if constexpr (EnableAB) {
                // Op 2: metadata consume + commit (connection B)
                int32_t processed_b = 0;
                processed_b = profile_op<Profiling>([this]() -> int32_t {
                    size_t p = msg_metadata_cons_[1]->process_manually(
                        [this](MsgMetadata& meta, int64_t seq, bool end_of_batch) {
                            on_event(1, meta, seq, end_of_batch);
                            return true;
                        }, MAX_ACCUMULATED_METADATA);
                    if (p > 0) {
                        msg_metadata_cons_[1]->commit_manually();
                        last_op_cycle_ = rdtscp();
                    }
                    return static_cast<int32_t>(p);
                }, slot, 2);

                idle = idle && (processed_b == 0);
            }

            // Ping/pong for all connections (idle only)
            profile_op<Profiling>([this]() -> int32_t {
                int32_t count = 0;
                for (size_t ci = 0; ci < NUM_CONN; ci++) {
                    if (has_pending_ping_[ci]) {
                        flush_pending_pong(static_cast<uint8_t>(ci));
                        count++;
                    }
                }
                // Watchdog for all active connections
                for (size_t ci = 0; ci < NUM_CONN; ci++) {
                    if (ws_phase_[ci] == WsConnPhase::ACTIVE) {
                        maybe_send_client_ping(static_cast<uint8_t>(ci));
                    }
                }
                // Fast dual-dead detection (fires at ~3s vs ~20s per-conn watchdog)
                check_dual_dead();
                if (count > 0) last_op_cycle_ = rdtscp();
                return count;
            }, slot, 1, idle);

            if (idle) __builtin_ia32_pause();

            if constexpr (Profiling) {
                slot->nic_poll_cycle = (processed > 0) ? first_consumed_poll_cycle_ : 0;
                slot->transport_poll_cycle = 0;
                slot->packet_nic_ns = 0;
                profiling_data_->commit();
            }
        }
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            flush_pending_pong(static_cast<uint8_t>(ci));
        }
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
        if constexpr (!AutoReconnect) {
            if (!perform_handshake()) {
                fprintf(stderr, "[WS-PROCESS] Handshake failed, exiting\n");
                return;
            }
        }
        run();
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

        // Publish to MSG_OUTBOX with connection_id
        int64_t seq = msg_outbox_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: MSG_OUTBOX full during handshake\n");
            std::abort();
        }

        auto& event = (*msg_outbox_prod_)[seq];
        std::memcpy(event.data, request_buf, request_len);
        event.data_len = static_cast<uint16_t>(request_len);
        event.msg_type = MSG_TYPE_DATA;
        event.connection_id = ci;

        msg_outbox_prod_->publish(seq);
    }

    /**
     * Blocking HTTP upgrade response receive (non-AutoReconnect path only).
     * Polls msg_metadata until HTTP 101 headers are complete.
     */
    bool recv_http_upgrade_response_blocking(uint8_t ci) {
        PartialHttpResponse response;
        response.clear();

        uint64_t start_cycle = rdtscp();
        uint64_t timeout_cycles = HANDSHAKE_TIMEOUT_MS * (conn_state_->tsc_freq_hz / 1000);

        while (!response.headers_complete) {
            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                return false;
            }
            if (rdtscp() - start_cycle > timeout_cycles) {
                fprintf(stderr, "[WS-PROCESS] Timeout waiting for HTTP response (conn %u)\n", ci);
                return false;
            }

            // Poll for metadata events from this connection
            MsgMetadata meta;
            if (msg_metadata_cons_[ci]->try_consume(meta)) {
                if (meta.decrypted_len > 0) {
                    const uint8_t* data = msg_inbox_[ci]->data_at(meta.msg_inbox_offset);
                    size_t to_copy = std::min(static_cast<size_t>(meta.decrypted_len),
                                              sizeof(response.buffer) - response.accumulated);
                    std::memcpy(response.buffer + response.accumulated, data, to_copy);
                    response.accumulated += to_copy;
                    response.try_complete();
                }
            } else {
                // When EnableAB, drain other connection's metadata during the wait
                // to avoid ring buffer backup (initial handshake phase only)
                if constexpr (EnableAB) {
                    uint8_t other = ci ^ 1;
                    MsgMetadata other_meta;
                    while (msg_metadata_cons_[other]->try_consume(other_meta)) {
                        // Drain but don't process (initial handshake phase)
                    }
                }
                __builtin_ia32_pause();
            }
        }

        // Validate HTTP 101 response
        return websocket::http::validate_http_upgrade_response(response.buffer, response.accumulated);
    }

    void send_subscription_message(uint8_t ci) {
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
        event.connection_id = ci;

        msg_outbox_prod_->publish(seq);
        printf("[WS-PROCESS] Subscription sent (conn %u, %zu bytes)\n", ci, json_len);
    }

    // ========================================================================
    // Event Handler (satisfies disruptor::event_handler_concept)
    // ========================================================================

    void on_event(uint8_t ci, MsgMetadata& meta, int64_t sequence, bool end_of_batch) {
        (void)sequence;
        (void)end_of_batch;

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

        // Send HTTP upgrade request via MSG_OUTBOX
        send_http_upgrade_request(ci);
        ws_phase_[ci] = WsConnPhase::WS_UPGRADE_SENT;
        http_response_[ci].clear();
    }

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
            return;  // Need more data
        }

        // HTTP headers complete — validate 101
        bool upgrade_ok = websocket::http::validate_http_upgrade_response(
            resp.buffer, resp.accumulated);

        if (!upgrade_ok) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [WS-RECONNECT] HTTP upgrade failed for conn %u, requesting reconnect\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            // Request full reconnect cycle
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

        // Reset dual-dead baseline: 0 means "no data yet" so check_dual_dead()
        // won't fire until real WS data arrives on this connection
        last_data_cycle_[ci] = 0;

        // Reset + resume watchdog for this connection
        reset_watchdog_state(ci);

        // Signal ws_ready on first successful handshake (for startup)
        if (!ws_ready_signaled_) {
            // Check if all connections are ACTIVE before signaling
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

        // Forward leftover WS bytes: if the SSL_read that completed the HTTP
        // headers also contained WS frame data after \r\n\r\n, those bytes are
        // in MSG_INBOX but were consumed as "HTTP". Forward them to the WS parser.
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

        // Prefetch MSG_INBOX data that we'll parse shortly
        __builtin_prefetch(inbox->data_at(meta.msg_inbox_offset), 0, 3);
        __builtin_prefetch(inbox->data_at(meta.msg_inbox_offset) + 64, 0, 3);

        // Accumulate metadata for timestamp recovery
        if (!has_pending_frame_[ci]) {
            // Starting fresh - record start offset and reset accumulators
            ps.data_start_offset = meta.msg_inbox_offset;
            ps.data_accumulated = 0;
            ps.parse_offset = 0;
            ps.accumulated_metadata_count = 0;
            ps.batch_frame_num = 0;
        }

        // Accumulate this SSL_read's data
        ps.data_accumulated += meta.decrypted_len;

        // Add metadata to array (if space available)
        if (ps.accumulated_metadata_count < MAX_ACCUMULATED_METADATA) {
            ps.accumulated_metadata[ps.accumulated_metadata_count++] = meta;
        }

        // Store current metadata for latest timestamps
        ps.current_metadata = meta;

        // Parse WebSocket frames from accumulated data
        while (ps.parse_offset < ps.data_accumulated) {
            uint32_t offset = (ps.data_start_offset + ps.parse_offset) % MSG_INBOX_SIZE;
            const uint8_t* data = inbox->data_at(offset);
            size_t available = ps.data_accumulated - ps.parse_offset;

            // Handle MSG_INBOX wrap-around (linear available bytes)
            size_t linear_avail = std::min(available, static_cast<size_t>(MSG_INBOX_SIZE - offset));

            // Handle header spanning wrap point - copy to contiguous buffer
            if (linear_avail < available && linear_avail < sizeof(ps.ws_header_wrap_buffer)) {
                size_t first_part = MSG_INBOX_SIZE - offset;
                size_t second_part = std::min(available - first_part,
                                              sizeof(ps.ws_header_wrap_buffer) - first_part);
                std::memcpy(ps.ws_header_wrap_buffer, data, first_part);
                std::memcpy(ps.ws_header_wrap_buffer + first_part, inbox->data_at(0), second_part);
                data = ps.ws_header_wrap_buffer;
                linear_avail = first_part + second_part;
            }

            // Parse frame
            size_t consumed = 0;
            bool frame_complete = false;

            if (has_pending_frame_[ci]) {
                // Continue parsing partial frame
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
                // Start parsing new frame
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
                ps.current_payload_offset = (ps.data_start_offset + ps.parse_offset +
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
                if (ps.parse_offset < ps.data_accumulated) {
                    ps.accumulated_metadata[ps.accumulated_metadata_count++] = ps.current_metadata;
                }
            }
        }

        // All data consumed - reset for next batch
        ps.data_accumulated = 0;
        ps.parse_offset = 0;
    }

    // ========================================================================
    // Partial Frame WSFrameInfo (header complete, payload incomplete)
    // ========================================================================

    void publish_partial_frame_info(uint8_t ci) {
        // Partial frames are never delivered to AppHandler — skip entirely
        if constexpr (HasAppHandler) return;

        auto& ps = parse_state_[ci];

        int64_t seq = ws_frame_info_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
            std::abort();
        }

        auto& info = (*ws_frame_info_prod_)[seq];
        info.clear();

        info.msg_inbox_offset = (ps.data_start_offset + pending_frame_[ci].expected_header_len) % MSG_INBOX_SIZE;
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
                fprintf(stderr, "[WS-PROCESS] Unknown opcode: 0x%02X (conn %u)\n", opcode, ci);
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
            fprintf(stderr, "[WS-PROCESS] Unexpected continuation frame (conn %u)\n", ci);
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

        // Skip PONGs for connections that are not ACTIVE
        if constexpr (AutoReconnect) {
            if (ws_phase_[ci] != WsConnPhase::ACTIVE) {
                has_pending_ping_[ci] = false;  // Discard — connection is dead
                return;
            }
        }

        int64_t pong_seq = pongs_prod_->try_claim();
        if (pong_seq < 0) {
            fprintf(stderr, "[WS-PROCESS] FATAL: PONGS full\n");
            std::abort();
        }

        auto& pong = (*pongs_prod_)[pong_seq];
        pong.clear();

        // Build PONG frame now
        const uint8_t* ping_payload = msg_inbox_[ci]->data_at(pending_ping_[ci].payload_offset);
        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};

        size_t safe_payload_len = pending_ping_[ci].payload_len;
        if (safe_payload_len > 119) {
            safe_payload_len = 119;
        }

        pong.data_len = static_cast<uint8_t>(websocket::http::build_pong_frame(
            ping_payload, safe_payload_len, pong.data, mask_key));
        pong.connection_id = ci;

        pongs_prod_->publish(pong_seq);

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

        // Server PING interval learning (per-connection)
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

        // Publish WSFrameInfo for PING (skip when AppHandler is active)
        if constexpr (!HasAppHandler) {
            int64_t ws_seq = ws_frame_info_prod_->try_claim();
            if (ws_seq < 0) {
                fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
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

        // If we already have a pending PING for this conn, flush it first
        if (has_pending_ping_[ci]) {
            flush_pending_pong(ci);
        }

        // Store pending PING (deferred to idle)
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

        // RFC 6455: valid close codes are 1000-4999. Anything outside this
        // range indicates a parse desync (random data misread as CLOSE frame).
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

        // Per-connection watchdog state update
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

        // First call: init baseline and skip (handshake warmup)
        if (w.last_client_ping_cycle == 0) {
            w.last_client_ping_cycle = now_cycle;
            w.last_pong_recv_cycle = now_cycle;  // Start timer from now
            return;
        }

        // Rate limit: 1 PING per second
        if ((now_cycle - w.last_client_ping_cycle) < tsc_freq) return;

        // ── Compute effective timeout (cycles) ──
        bool interval_learned = (w.server_ping_count >= 2 && w.learned_interval_cycles > 0);
        uint64_t pong_timeout_cycles = interval_learned
            ? w.learned_interval_cycles
            : (DEFAULT_PONG_TIMEOUT_MS * tsc_freq) / 1000;

        // ── PONG timeout (time-based) ──
        uint64_t since_last_pong = now_cycle - w.last_pong_recv_cycle;
        bool server_pong_missing = (since_last_pong > pong_timeout_cycles);

        // ── Server PING timeout (1.5x interval) ──
        bool server_ping_missing = false;
        if (interval_learned && w.last_server_ping_cycle > 0) {
            uint64_t since_last_ping = now_cycle - w.last_server_ping_cycle;
            uint64_t threshold = w.learned_interval_cycles + (w.learned_interval_cycles / 2);
            server_ping_missing = (since_last_ping > threshold);
        }

        // ── Reconnect decision ──
        bool should_reconnect = interval_learned
            ? (server_pong_missing && server_ping_missing)   // Post-learning: dual condition
            : server_pong_missing;                            // Pre-learning: PONG timeout only

        if (should_reconnect) {
            trigger_watchdog_reconnect(ci, now_cycle, tsc_freq);
            ws_phase_[ci] = WsConnPhase::DISCONNECTED;
            return;
        }

        // ── Send client PING ──
        auto now = std::chrono::system_clock::now();
        int64_t unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        char payload_ascii[16];
        int payload_len = snprintf(payload_ascii, sizeof(payload_ascii), "%ld", unix_ms);

        int64_t seq = pongs_prod_->try_claim();
        if (seq < 0) return;  // Ring full, retry next second

        auto& frame = (*pongs_prod_)[seq];
        frame.clear();
        uint8_t mask_key[4] = {0x12, 0x34, 0x56, 0x78};
        frame.data_len = static_cast<uint8_t>(websocket::http::build_ping_frame(
            reinterpret_cast<const uint8_t*>(payload_ascii),
            static_cast<size_t>(payload_len), frame.data, mask_key));
        frame.connection_id = ci;
        pongs_prod_->publish(seq);

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
            // AppHandler replaces WSFrameInfo ring — build info on stack, call handler
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

            // Call handler for complete TEXT/BINARY messages
            if (opcode == 0x01 || opcode == 0x02) {
                if (!is_fragmented || is_last_fragment) {
                    const uint8_t* payload = msg_inbox_[ci]->data_at(info.msg_inbox_offset);
                    app_handler_.on_ws_frame(ci, opcode, payload,
                                             static_cast<uint32_t>(payload_len), info);
                }
            }
        } else {
            // Original path: publish to WSFrameInfo ring for parent consumer
            int64_t seq = ws_frame_info_prod_->try_claim();
            if (seq < 0) {
                fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
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

        // Cross-connection diagnostic: check the other connection's health
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
            // Soft reset: preserve learned_interval, reset baselines
            w.server_ping_count = 0;
            w.last_server_ping_cycle = now_cycle;
            w.last_client_ping_cycle = 0;   // Skip first PING (warmup)
            w.last_pong_recv_cycle = now_cycle;
        } else {
            conn_state_->set_disconnect(DisconnectReason::WS_PONG_TIMEOUT);
            conn_state_->shutdown_all();
        }
    }

    void reset_watchdog_state(uint8_t ci) {
        wd_[ci] = WatchdogState{};
    }

    /// Fast dual-dead detection: if both connections are silent beyond threshold,
    /// trigger reconnect for both immediately (3s vs 20s normal per-conn watchdog).
    void check_dual_dead() {
        if constexpr (!EnableAB || !AutoReconnect) return;

        // Both connections must be ACTIVE and have received data
        if (ws_phase_[0] != WsConnPhase::ACTIVE || ws_phase_[1] != WsConnPhase::ACTIVE) return;
        if (last_data_cycle_[0] == 0 || last_data_cycle_[1] == 0) return;

        uint64_t now = rdtscp();
        uint64_t freq = conn_state_->tsc_freq_hz;
        uint64_t threshold_ms = conn_state_->dual_dead_threshold_ms;
        if (threshold_ms == 0 || freq == 0) return;  // Disabled

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

            // Immediately mark DISCONNECTED to prevent repeated firing
            // while waiting for TCP_DISCONNECTED from Transport process.
            // Stale data will be correctly drained by on_event().
            ws_phase_[0] = WsConnPhase::DISCONNECTED;
            ws_phase_[1] = WsConnPhase::DISCONNECTED;
        }
    }

    // ========================================================================
    // Timestamp Helpers
    // ========================================================================

    // Forward declaration for PerConnParseState (defined below)
    struct PerConnParseState;

    void populate_timestamps(WSFrameInfo& info, PerConnParseState& ps) {
        if (ps.accumulated_metadata_count > 0) {
            const auto& first_meta = ps.accumulated_metadata[0];
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

        uint32_t total_nic_packets = 0;
        for (size_t i = 0; i < ps.accumulated_metadata_count; ++i) {
            total_nic_packets += ps.accumulated_metadata[i].nic_packet_ct;
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
        uint32_t payload_offset;   // MSG_INBOX offset of PING payload
        uint16_t payload_len;      // PING payload length
    };

    struct PerConnParseState {
        // Partial frame accumulation
        uint32_t data_start_offset = 0;
        uint32_t data_accumulated = 0;
        uint32_t parse_offset = 0;

        // Timestamp accumulation
        std::array<MsgMetadata, MAX_ACCUMULATED_METADATA> accumulated_metadata;
        size_t accumulated_metadata_count = 0;
        MsgMetadata first_packet_metadata;
        MsgMetadata current_metadata;

        // Payload offset for current frame
        uint32_t current_payload_offset = 0;
        bool pending_tls_record_end = false;

        // Wrap-around buffer for WS headers spanning MSG_INBOX wrap point
        uint8_t ws_header_wrap_buffer[64];

        // Frame counter within batch
        uint32_t batch_frame_num = 0;

        // Fragment state (for fragmented WebSocket messages)
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

    // Per-connection state
    MsgInbox* msg_inbox_[NUM_CONN]{};
    MsgMetadataCons* msg_metadata_cons_[NUM_CONN]{};
    PerConnParseState parse_state_[NUM_CONN]{};
    PartialWebSocketFrame pending_frame_[NUM_CONN]{};
    bool has_pending_frame_[NUM_CONN]{};
    PendingPing pending_ping_[NUM_CONN]{};
    bool has_pending_ping_[NUM_CONN]{};

    // Per-connection WS state machine (AutoReconnect)
    WsConnPhase ws_phase_[NUM_CONN]{};
    PartialHttpResponse http_response_[NUM_CONN]{};

    // Shared ring buffer interfaces (ws_frame_info_prod_ unused when HasAppHandler)
    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    PongsProd* pongs_prod_ = nullptr;
    MsgOutboxProd* msg_outbox_prod_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // AppHandler (inline callback, replaces WSFrameInfo ring when enabled)
    [[no_unique_address]] AppHandler app_handler_{};

    // AutoReconnect startup signal
    bool ws_ready_signaled_ = false;

    // Profiling (compile-time gated via Profiling template param)
    CycleSampleBuffer* profiling_data_ = nullptr;
    uint64_t first_consumed_poll_cycle_ = 0;
    uint64_t last_op_cycle_ = 0;
public:
    void set_profiling_data(CycleSampleBuffer* data) { profiling_data_ = data; }
    AppHandler& app_handler() { return app_handler_; }
private:

    // Per-connection watchdog state
    struct WatchdogState {
        uint64_t last_client_ping_cycle = 0;   // TSC of last client PING sent
        uint64_t last_pong_recv_cycle = 0;     // TSC of last PONG received

        static constexpr uint32_t PING_LEARN_SAMPLES = 5;
        uint64_t server_ping_cycles[PING_LEARN_SAMPLES]{};
        uint32_t server_ping_count = 0;
        uint64_t learned_interval_cycles = 0;
        uint64_t learned_interval_ms = 0;

        uint64_t last_server_ping_cycle = 0;
    };
    WatchdogState wd_[NUM_CONN]{};
    uint64_t last_data_cycle_[NUM_CONN]{};  // TSC of last DATA event per connection

    static constexpr uint64_t DEFAULT_PONG_TIMEOUT_MS = 5000;  // 5s pre-learning default
};

}  // namespace websocket::pipeline
