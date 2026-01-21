# Pipeline Process 2: WebSocket (Core 6)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [Transport Process (Core 4)](pipeline_1_trans.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

---

## Overview

WebSocket Process handles **HTTP+WS handshake** and **WebSocket frame parsing/dispatching**. After Transport signals `tls_ready`, it performs the HTTP upgrade handshake, then consumes decrypted TLS data from MSG_INBOX and produces WSFrameInfo events for AppClient.

**Key Responsibilities**:
1. Perform HTTP+WS handshake after Transport signals `tls_ready`
   - Build and send HTTP upgrade request via MSG_OUTBOX
   - Validate HTTP 101 response from MSG_INBOX
   - Send subscription message(s) via MSG_OUTBOX
   - Signal `ws_ready` when handshake complete
2. Consume MSG_METADATA_INBOX events via `event_processor.run()` (auto-consumer)
3. Read decrypted data from MSG_INBOX at offsets specified in metadata
4. Parse WebSocket frames using `parse_websocket_frame()` from core/http.hpp
5. Handle control frames (PING → defer PONG to idle, CLOSE → signal Transport)
6. Publish WSFrameInfo with full timestamp chain for data frames

---

## Code Reuse

```cpp
// Standard library
#include <array>              // std::array for fixed-size metadata accumulation

// Disruptor IPC (from 01_shared_headers/disruptor/)
#include <disruptor/disruptor.hpp>  // ring_buffer, sequencer, event_processor, sequence_barrier

// Pipeline data structures
#include <pipeline/pipeline_data.hpp>  // MsgMetadata, WSFrameInfo, PongFrameAligned, MsgOutboxEvent
#include <pipeline/msg_inbox.hpp>      // MsgInbox
#include <pipeline/ws_parser.hpp>      // PartialWebSocketFrame, continue_partial_frame()

// WebSocket & Timing
#include <core/http.hpp>      // parse_websocket_frame(), WebSocketFrame, WebSocketOpcode
                              // build_websocket_upgrade_request(), validate_http_upgrade_response()
                              // build_pong_frame(), build_websocket_header_zerocopy()
#include <core/timing.hpp>    // rdtscp()

// Namespace aliases for cleaner code
using websocket::http::parse_websocket_frame;
using websocket::http::WebSocketFrame;
using websocket::http::WebSocketOpcode;
using websocket::http::build_websocket_upgrade_request;
using websocket::http::validate_http_upgrade_response;
using websocket::http::build_pong_frame;
using websocket::http::build_websocket_header_zerocopy;
```

---

## Handshake Phase

After Transport Process completes TCP/TLS handshake and signals `tls_ready`, WebSocket Process performs the HTTP+WS level handshake before entering the main event loop.

**Two-Phase Operation**:
- **Phase 1 (Handshake)**: Manual polling on MSG_METADATA_INBOX, blocking until HTTP 101 received
- **Phase 2 (Main Loop)**: `event_processor.run()` auto-consumer for WebSocket frames

### Handshake Steps

```
1. Wait for `tls_ready` flag from Transport (busy-poll)
2. Build HTTP upgrade request with Sec-WebSocket-Key
3. Publish to MSG_OUTBOX (Transport encrypts and sends)
4. Poll MSG_METADATA_INBOX for HTTP response
5. Read response from MSG_INBOX, validate "101 Switching Protocols"
6. Build subscription message as WS TEXT frame
7. Publish to MSG_OUTBOX
8. Signal `ws_ready` flag for AppClient
9. Enter main event loop (event_processor.run())
```

### Handshake Data Flow

```
Transport signals tls_ready
         │
         ▼
WebSocket builds HTTP upgrade request
         │
         ▼ MSG_OUTBOX (raw HTTP bytes in data field)
Transport (encrypts + sends via RAW_OUTBOX)
         │
         ▼
Server receives HTTP upgrade, sends HTTP 101 response
         │
         ▼
Transport (receives + decrypts via MSG_INBOX)
         │
         ▼ MSG_METADATA_INBOX + MSG_INBOX
WebSocket polls and validates HTTP 101
         │
         ▼
WebSocket builds subscription as WS TEXT frame
         │
         ▼ MSG_OUTBOX (complete WS frame: header + JSON payload)
Transport (encrypts + sends)
         │
         ▼
WebSocket signals ws_ready
         │
         ▼
Enter event_processor.run() for main loop
```

### HTTP Upgrade Request Building

```cpp
void WebSocketProcess::send_http_upgrade_request(const char* host, const char* path,
                                                   const std::vector<std::pair<std::string, std::string>>& custom_headers) {
    // Build HTTP upgrade request using core/http.hpp
    char request_buf[4096];
    size_t request_len = build_websocket_upgrade_request(host, path, custom_headers,
                                                          request_buf, sizeof(request_buf));

    // Publish to MSG_OUTBOX (Transport treats as raw bytes)
    int64_t seq = msg_outbox_producer_.try_claim();
    if (seq < 0) std::abort();  // MSG_OUTBOX full - should not happen during handshake

    auto& event = msg_outbox_producer_[seq];
    // Copy request into data field (raw HTTP, no WS framing)
    memcpy(event.data, request_buf, request_len);
    event.data_len = static_cast<uint16_t>(request_len);
    event.msg_type = MSG_TYPE_DATA;  // Transport just encrypts and sends raw bytes
    event.opcode = 0;  // Not used for raw HTTP

    msg_outbox_producer_.publish(seq);
}
```

### HTTP Response Validation

```cpp
// State for partial HTTP response accumulation (similar to PartialWebSocketFrame)
struct PartialHttpResponse {
    uint8_t buffer[4096];
    size_t accumulated = 0;
    bool headers_complete = false;

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

bool WebSocketProcess::recv_http_upgrade_response() {
    PartialHttpResponse response;

    // Manual polling loop - process_manually on MSG_METADATA_INBOX
    while (!response.headers_complete) {
        // Poll for new metadata events
        msg_metadata_consumer_.process_manually([&](MsgMetadata& meta, int64_t seq) {
            // Read decrypted data from MSG_INBOX
            const uint8_t* data = msg_inbox_.data_at(meta.msg_inbox_offset);
            size_t to_copy = std::min(meta.decrypted_len,
                                       sizeof(response.buffer) - response.accumulated);
            memcpy(response.buffer + response.accumulated, data, to_copy);
            response.accumulated += to_copy;
            response.try_complete();
        });
        msg_metadata_consumer_.commit_manually();

        // Timeout check (prevent infinite loop)
        // ... timeout handling omitted for clarity
    }

    // Validate response contains "101"
    return validate_http_upgrade_response(response.buffer, response.accumulated);
}
```

**Note**: `commit_manually()` is called inside the loop, committing after each poll
iteration. This is acceptable for the blocking handshake phase. If an error occurs
mid-response, partial consumption cannot be rolled back, but handshake failure
triggers process abort anyway.

### Subscription Message Sending

```cpp
void WebSocketProcess::send_subscription_messages() {
    // subscription_json_ is pre-configured in HandshakeConfig (shared memory)
    const char* json = handshake_config_->subscription_json;
    size_t json_len = strlen(json);

    // Build complete WS TEXT frame (header + payload)
    int64_t seq = msg_outbox_producer_.try_claim();
    if (seq < 0) std::abort();

    auto& event = msg_outbox_producer_[seq];

    // Build WS header in header_room (right-aligned)
    // Header is 6 bytes for payload < 126: [0x81, 0x80|len, mask[4]]
    size_t header_len = build_websocket_header_zerocopy(
        event.header_room + 14 - 6,  // Right-align 6-byte header
        json_len, 0x01);             // opcode 0x01 = TEXT

    // Copy payload
    memcpy(event.data, json, json_len);
    event.data_len = static_cast<uint16_t>(json_len);
    event.opcode = 0x01;  // TEXT
    event.msg_type = MSG_TYPE_DATA;

    msg_outbox_producer_.publish(seq);
}
```

### Handshake Configuration

WebSocket Process receives handshake parameters from shared memory (set by parent before fork):

```cpp
// In ConnStateShm or separate HandshakeConfig structure
struct HandshakeConfig {
    char target_host[256];              // e.g., "stream.binance.com"
    char target_path[512];              // e.g., "/ws"
    char custom_headers[2048];          // Pre-formatted additional headers
    char subscription_json[4096];       // e.g., {"method":"SUBSCRIBE","params":["btcusdt@aggTrade"],"id":1}
};
```

---

## Type Definitions

```cpp
// From pipeline_data.hpp - wraps disruptor::ipc::shared_region
// DESIGN DECISION: Always use try_claim(), abort on full buffer (indicates misconfiguration)
template<typename T>
struct IPCRingProducer {
    disruptor::ipc::shared_region& region_;
    size_t element_count_;
    size_t element_mask_;

    explicit IPCRingProducer(disruptor::ipc::shared_region& r);

    int64_t try_claim();
    T& operator[](int64_t seq);
    void publish(int64_t seq);
};

// NOTE: Callers must check try_claim() return value and abort if < 0:
//   int64_t seq = producer.try_claim();
//   if (seq < 0) std::abort();  // Buffer full = consumer too slow or buffer misconfigured

// Concrete producer types used by WebSocketProcess
using WSFrameInfoProducer = IPCRingProducer<WSFrameInfo>;
using PongsProducer = IPCRingProducer<PongFrameAligned>;
using MsgOutboxProducer = IPCRingProducer<MsgOutboxEvent>;

// WSFrameInfo structure (from pipeline_data.hpp, 128 bytes cache-aligned)
//
// NOTE: Each WS fragment generates a separate WSFrameInfo event immediately.
// This allows AppClient to process fragments incrementally for lower latency.
//
// Fragment/partial handling:
//   - is_fragmented=false: Complete single-frame message
//   - is_fragmented=true, is_last_fragment=false: Partial frame or intermediate fragment
//   - is_fragmented=true, is_last_fragment=true: Final fragment (message complete)
//
// Partial frame behavior:
//   - If WS header is complete but payload is incomplete, WSFrameInfo is published immediately
//   - is_fragmented=true indicates partial data, is_last_fragment=false indicates more coming
//   - If WS header is incomplete (< 14 bytes), DEFER until header is complete
//
// All fields are valid per-fragment (msg_inbox_offset points to THIS fragment's payload).
struct WSFrameInfo {
    uint32_t msg_inbox_offset;        // Payload offset in MSG_INBOX (valid for this fragment)
    uint32_t payload_len;             // This fragment's payload length
    uint8_t  opcode;                  // WS opcode (TEXT=1, BINARY=2, PING=9, etc.)
    bool     is_fin;                  // FIN bit from WS header
    bool     is_fragmented;           // True if partial frame OR fragmented WS message
    bool     is_last_fragment;        // True if this is the final fragment/part
    uint32_t frame_total_len;         // Total WS frame length(s) including headers

    // Full timestamp chain
    uint64_t first_byte_ts;           // NIC timestamp when first byte arrived
    uint64_t first_nic_frame_poll_cycle;
    uint64_t last_byte_ts;            // NIC timestamp when frame completed
    uint64_t latest_nic_frame_poll_cycle;
    uint64_t latest_raw_frame_poll_cycle;

    // SSL_read timing (replaces single ssl_read_cycle)
    uint64_t first_ssl_read_cycle;    // TSC cycle of first SSL_read for this frame
    uint64_t last_ssl_read_cycle;     // TSC cycle of last SSL_read for this frame
    uint32_t ssl_read_ct;             // Number of SSL_read calls for this frame

    // Packet counting
    uint32_t nic_packet_ct;           // Number of NIC packets for this frame

    uint64_t ws_parse_cycle;          // WS frame parse completion cycle
};
```

---

## Class Definition

```cpp
// Satisfies disruptor::event_handler_concept<WebSocketProcess, MsgMetadata>
// Can be used with disruptor::event_processor for automatic event consumption
class WebSocketProcess {
private:
    MsgInbox& msg_inbox_;
    WSFrameInfoProducer& ws_frame_producer_;
    PongsProducer& pongs_producer_;
    MsgOutboxProducer& msg_outbox_producer_;
    std::atomic<bool>* running_;

    // === HANDSHAKE STATE ===
    // WebSocket Process performs HTTP+WS handshake after Transport signals tls_ready
    std::atomic<bool>* tls_ready_;          // Input: Transport signals TLS handshake complete
    std::atomic<bool>* ws_ready_;           // Output: Signal to AppClient that WS is ready
    HandshakeConfig* handshake_config_;     // Shared memory: host, path, subscription JSON
    bool handshake_complete_ = false;
    bool subscription_sent_ = false;

    // HTTP response accumulation during handshake (before event_processor.run())
    PartialHttpResponse http_response_;

    // Ring buffer and barrier (from 01_shared_headers/disruptor/, IPC mode with external storage)
    disruptor::ring_buffer<MsgMetadata, MSG_METADATA_SIZE,
                           disruptor::storage_policies::external_storage>& msg_metadata_ring_buffer_;
    disruptor::sequence_barrier<>& sequence_barrier_;

    // WS parser state (uses PartialWebSocketFrame from pipeline/ws_parser.hpp)
    PartialWebSocketFrame pending_frame_;
    bool has_pending_frame_ = false;

    // Wrap-around buffer for WS headers spanning MSG_INBOX wrap point
    // Max WS header = 14 bytes (2 base + 8 extended length + 4 mask)
    // 64 bytes provides margin for safety
    uint8_t ws_header_wrap_buffer_[64];

    // Current message metadata (from MSG_METADATA_INBOX)
    MsgMetadata current_metadata_;

    // === PARTIAL FRAME ACCUMULATION MODE ===
    // When a WS frame spans multiple SSL_reads, we accumulate data until the frame
    // is complete (same pattern as src/websocket.hpp lines 585-1312).
    //
    // Key insight: MSG_INBOX already contains the accumulated data from all SSL_reads.
    // Ring buffer consumption happens immediately via event_processor; only WS frame
    // parsing state is preserved across events. We track:
    //   1. Where the current partial frame starts (data_start_offset_)
    //   2. How much data we've accumulated (data_accumulated_)
    //   3. Timestamps from the FIRST packet (accumulated_metadata_)
    //
    // On each on_event():
    //   - If partial frame: data_accumulated_ += meta.decrypted_len, continue parsing
    //   - If frame complete: publish WSFrameInfo, reset state
    //   - If still partial: preserve parser state, wait for next event
    //
    uint32_t data_start_offset_ = 0;           // MSG_INBOX offset where current batch starts
    uint32_t data_accumulated_ = 0;            // Total bytes accumulated for current partial frame
    uint32_t parse_offset_ = 0;                // How far we've parsed within accumulated data

    // Partial frame timestamp recovery state
    // When a WS frame spans multiple SSL_reads, we need to recover timestamps from
    // the FIRST packet in the frame, not the latest SSL_read.
    // We accumulate ALL metadata events until the frame is complete, then recover true timestamps.
    //
    // DESIGN: Use fixed-size array instead of std::vector to avoid dynamic allocation
    // in hot path. 64 entries is generous - typical WS frame spans 1-4 SSL_reads.
    // If a WS frame requires more than 64 SSL_reads (>1MB at 16KB TLS records),
    // we fall back to using only the first metadata's timestamps.
    //
    // Value 64 is a practical optimization (reduced from 256):
    //   - Reduces cache footprint by 12 KB (MsgMetadata is 64 bytes each)
    //   - Still handles any realistic WebSocket frame (64 SSL_reads per frame is extreme)
    //   - Better cache locality = lower latency variance
    static constexpr size_t MAX_ACCUMULATED_METADATA = 64;
    int64_t partial_frame_start_seq_ = -1;     // Sequence of first metadata for this frame
    std::array<MsgMetadata, MAX_ACCUMULATED_METADATA> accumulated_metadata_;  // Fixed-size, no allocation
    size_t accumulated_metadata_count_ = 0;    // Current count in accumulated_metadata_
    MsgMetadata first_packet_metadata_;         // Recovered true first packet metadata

    // Fragment accumulation state (for fragmented WebSocket messages using CONTINUATION)
    // RFC 6455: A fragmented message is a single message split into multiple frames.
    // First frame has opcode=TEXT/BINARY with FIN=0, continuation frames have opcode=0,
    // final frame has opcode=0 with FIN=1.
    // NOTE: This HFT library does NOT support SENDING fragmented messages, but must handle
    // receiving them from servers.
    bool accumulating_fragments_ = false;      // Currently accumulating fragments
    uint8_t fragment_opcode_ = 0;              // Opcode from first fragment (TEXT=1, BINARY=2)
    uint32_t fragment_start_offset_ = 0;       // MSG_INBOX offset of first fragment's payload
    uint32_t fragment_total_len_ = 0;          // Accumulated payload length
    uint32_t fragment_total_frame_len_ = 0;    // Accumulated total frame length (headers + payloads)

    // Fragment timestamp tracking (separate from partial frame timestamps)
    // accumulated_metadata_ tracks timestamps within a single WS frame that spans SSL_reads.
    // fragment_first_metadata_ tracks timestamps across multiple WS frames (fragmentation).
    //
    // Fragmented WS Frame Timestamp Semantics:
    //   - first_* timestamps: From the MsgMetadata of the FIRST TLS record containing frame start
    //   - latest_* timestamps: From the MsgMetadata of the LAST TLS record containing frame end
    //   - This matches how we track partial frames spanning multiple SSL_reads
    MsgMetadata fragment_first_metadata_;       // Timestamps from first fragment (TEXT/BINARY with FIN=0)

    // === DEFERRED PONG STATE ===
    // PONG frame building is deferred to idle time to reduce hot-path work.
    // When PING is received, we store the payload info; PONG is built when idle.
    struct PendingPing {
        uint32_t payload_offset;   // MSG_INBOX offset of PING payload
        uint16_t payload_len;      // PING payload length
    };
    PendingPing pending_ping_;
    bool has_pending_ping_ = false;

    // Constructor receives shared memory pointers from parent process (set before fork)
    WebSocketProcess(
        MsgInbox& msg_inbox,                    // Shared memory: decrypted TLS data
        WSFrameInfoProducer& ws_frame_producer,
        PongsProducer& pongs_producer,
        MsgOutboxProducer& msg_outbox_producer,
        // ... ring buffer references
        HandshakeConfig* handshake_config,      // Shared memory: handshake parameters
        std::atomic<bool>* tls_ready,           // Input signal from Transport
        std::atomic<bool>* ws_ready,            // Output signal to AppClient
        std::atomic<bool>* running              // Shutdown flag
    );

public:
    // === HANDSHAKE METHODS (Phase 1: called before run()) ===
    bool init_with_handshake();  // Main entry: performs full HTTP+WS handshake
    void shutdown();             // Signal halt to event_processor

    // === MAIN LOOP (Phase 2: blocking event_processor.run()) ===
    // event_processor.run() calls this for each MsgMetadata event
    void on_event(MsgMetadata& meta, int64_t sequence, bool end_of_batch) override;
    void run();

private:
    // Handshake helpers
    void send_http_upgrade_request();
    bool recv_http_upgrade_response();
    void send_subscription_messages();

    // Frame handling
    void handle_complete_frame(const uint8_t* frame_start, const WebSocketFrame& frame, size_t consumed);
    void publish_ws_frame_info(const uint8_t* frame_start, const WebSocketFrame& frame,
                               size_t consumed, uint64_t ws_parse_cycle);

    // Deferred PONG helpers
    void flush_pending_pong();  // Build and send PONG for pending PING (called on idle/shutdown)
};
```

---

## Event Handler

```cpp
// WEBSOCKET PROCESS: Consumes MSG_METADATA_INBOX via event_processor.run() (auto-consumer)
// Then reads from MSG_INBOX at offsets from consumed MsgMetadata events

void WebSocketProcess::on_event(MsgMetadata& meta, int64_t sequence, bool end_of_batch) {
    current_metadata_ = meta;

    // === PARTIAL FRAME ACCUMULATION MODE (same pattern as src/websocket.hpp) ===
    // Accumulate data across SSL_reads until WS frame is complete.
    // Ring buffer consumption happens immediately; only WS frame parsing state is preserved.
    //
    // Key insight: MSG_INBOX already contains contiguous data from Transport.
    // Each on_event() adds more data; we parse from where we left off.

    // Accumulate metadata for timestamp recovery
    if (!has_pending_frame_) {
        // Starting fresh - record start offset and reset accumulators
        data_start_offset_ = meta.msg_inbox_offset;
        data_accumulated_ = 0;
        parse_offset_ = 0;
        partial_frame_start_seq_ = sequence;
        accumulated_metadata_count_ = 0;
    }

    // Accumulate this SSL_read's data
    data_accumulated_ += meta.decrypted_len;
    // Add metadata to fixed-size array (if space available)
    if (accumulated_metadata_count_ < MAX_ACCUMULATED_METADATA) {
        accumulated_metadata_[accumulated_metadata_count_++] = meta;
    }
    // If array full, first_packet_metadata_ will still be correct from index 0

    // Parse WebSocket frames from accumulated data
    // data_start_offset_ + parse_offset_ = where to resume parsing
    // data_accumulated_ - parse_offset_ = bytes available to parse
    while (parse_offset_ < data_accumulated_) {
        uint32_t offset = (data_start_offset_ + parse_offset_) % MSG_INBOX_SIZE;
        const uint8_t* data = msg_inbox_.data_at(offset);
        size_t available = data_accumulated_ - parse_offset_;

        // Handle MSG_INBOX wrap-around (linear available bytes)
        size_t linear_avail = std::min(available, (size_t)(MSG_INBOX_SIZE - offset));

        // Handle header spanning wrap point - copy to contiguous buffer
        if (linear_avail < available && linear_avail < sizeof(ws_header_wrap_buffer_)) {
            // Header may span wrap point - copy to contiguous buffer
            size_t first_part = MSG_INBOX_SIZE - offset;
            size_t second_part = std::min(available - first_part, sizeof(ws_header_wrap_buffer_) - first_part);
            memcpy(ws_header_wrap_buffer_, data, first_part);
            memcpy(ws_header_wrap_buffer_ + first_part, msg_inbox_.data_at(0), second_part);
            data = ws_header_wrap_buffer_;
            linear_avail = first_part + second_part;
        }

        // Resume parsing with pending frame state if we have one
        PartialWebSocketFrame& pframe = pending_frame_;
        if (has_pending_frame_) {
            // Continue parsing with previously saved state
            if (!continue_partial_frame(data, linear_avail, pframe)) {
                // Still incomplete - check if header is complete for partial WSFrameInfo
                if (!pframe.header_complete) {
                    // Header incomplete - DEFER, don't publish WSFrameInfo
                    // has_pending_frame_ stays true, data_accumulated_ preserved
                    return;
                }

                // Header complete but payload incomplete - publish partial WSFrameInfo
                int64_t seq = ws_frame_producer_.try_claim();
                if (seq < 0) std::abort();

                auto& info = ws_frame_producer_[seq];
                // Calculate payload offset (frame start + header length)
                info.msg_inbox_offset = (data_start_offset_ + pframe.header_len) % MSG_INBOX_SIZE;
                info.payload_len = data_accumulated_ - pframe.header_len;  // Payload bytes so far
                info.frame_total_len = data_accumulated_;
                info.opcode = pframe.opcode;  // Header is complete, opcode is known
                info.is_fin = pframe.fin;
                info.is_fragmented = true;      // Partial frame (payload incomplete)
                info.is_last_fragment = false;  // More data needed

                // Timestamps from accumulated metadata
                info.first_byte_ts = accumulated_metadata_[0].first_nic_timestamp_ns;
                info.first_nic_frame_poll_cycle = accumulated_metadata_[0].first_nic_frame_poll_cycle;
                info.last_byte_ts = meta.latest_nic_timestamp_ns;
                info.latest_nic_frame_poll_cycle = meta.latest_nic_frame_poll_cycle;
                info.latest_raw_frame_poll_cycle = meta.latest_raw_frame_poll_cycle;
                info.first_ssl_read_cycle = accumulated_metadata_[0].ssl_read_cycle;
                info.last_ssl_read_cycle = meta.ssl_read_cycle;
                info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
                // Sum packet counts from all accumulated metadata
                info.nic_packet_ct = 0;
                for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
                    info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
                }
                info.ws_parse_cycle = rdtscp();

                ws_frame_producer_.publish(seq);

                // Still preserve state for continuation
                has_pending_frame_ = true;
                return;
            }
        } else {
            // Start parsing new frame
            pframe.reset();
            if (!start_parse_frame(data, linear_avail, pframe)) {
                // Partial frame - check if header is complete
                if (!pframe.header_complete) {
                    // Header incomplete - DEFER, don't publish WSFrameInfo
                    has_pending_frame_ = true;
                    return;
                }

                // Header complete but payload incomplete - publish partial WSFrameInfo
                int64_t seq = ws_frame_producer_.try_claim();
                if (seq < 0) std::abort();

                auto& info = ws_frame_producer_[seq];
                // Calculate payload offset (frame start + header length)
                info.msg_inbox_offset = (data_start_offset_ + pframe.header_len) % MSG_INBOX_SIZE;
                info.payload_len = data_accumulated_ - pframe.header_len;  // Payload bytes so far
                info.frame_total_len = data_accumulated_;
                info.opcode = pframe.opcode;
                info.is_fin = pframe.fin;
                info.is_fragmented = true;
                info.is_last_fragment = false;

                // Timestamps from accumulated metadata
                info.first_byte_ts = accumulated_metadata_[0].first_nic_timestamp_ns;
                info.first_nic_frame_poll_cycle = accumulated_metadata_[0].first_nic_frame_poll_cycle;
                info.last_byte_ts = meta.latest_nic_timestamp_ns;
                info.latest_nic_frame_poll_cycle = meta.latest_nic_frame_poll_cycle;
                info.latest_raw_frame_poll_cycle = meta.latest_raw_frame_poll_cycle;
                info.first_ssl_read_cycle = accumulated_metadata_[0].ssl_read_cycle;
                info.last_ssl_read_cycle = meta.ssl_read_cycle;
                info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
                info.nic_packet_ct = 0;
                for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
                    info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
                }
                info.ws_parse_cycle = rdtscp();

                ws_frame_producer_.publish(seq);

                has_pending_frame_ = true;
                return;
            }
        }

        // Frame complete - convert to WebSocketFrame
        WebSocketFrame frame;
        frame.opcode = pframe.opcode;
        frame.fin = pframe.fin;
        frame.payload_len = pframe.payload_len;
        frame.payload = pframe.payload;  // Points into MSG_INBOX
        frame.header_len = pframe.header_len;

        // Recover true timestamps from FIRST metadata in accumulated array
        if (accumulated_metadata_count_ > 0) {
            first_packet_metadata_ = accumulated_metadata_[0];
        }

        // Handle the complete frame
        // NOTE: Pass the MSG_INBOX offset where this frame starts, NOT the parse_offset_
        // data_start_offset_ + parse_offset_ gives the correct MSG_INBOX position
        handle_complete_frame(data, frame, data_start_offset_ + parse_offset_);

        // Advance parse position
        parse_offset_ += frame.header_len + frame.payload_len;
        has_pending_frame_ = false;

        // Reset timestamp accumulator for next frame (within same batch)
        // Note: Keep data_start_offset_ and data_accumulated_ - more frames may follow
        accumulated_metadata_count_ = 0;
        accumulated_metadata_[accumulated_metadata_count_++] = meta;  // Current meta is start of next frame
    }

    // All data consumed - reset state for next batch
    // This is the "commit" - we processed all accumulated data
    data_accumulated_ = 0;
    parse_offset_ = 0;
    partial_frame_start_seq_ = -1;
}
```

---

## Main Loop

```cpp
// Event processor as member for halt() access
using ProcessorType = disruptor::event_processor<MsgMetadata,
    disruptor::policy_bundles::single_producer_lowest_latency>;
std::unique_ptr<ProcessorType> processor_;

void WebSocketProcess::run() {
    using namespace disruptor;

    // Create event processor for MSG_METADATA_INBOX
    processor_ = std::make_unique<ProcessorType>(
        msg_metadata_ring_buffer_,
        sequence_barrier_,
        *this  // this class is the event handler
    );

    // Blocking call - runs until halt() is called
    processor_->run();
}

// Shutdown: call from signal handler or other process
void WebSocketProcess::shutdown() {
    if (processor_) {
        processor_->halt();
    }
}
```

---

## Deferred PONG Response

To reduce hot-path work, PONG frame building is deferred to idle time rather than being done immediately when a PING is received.

### Design Rationale

1. **Hot path optimization**: PONG frame building (header construction, mask application) is moved out of the frame parsing path
2. **Simple state**: Single pending PING tracked with boolean flag
3. **Immediate on new PING**: If server sends another PING while one is pending, the old PONG is flushed immediately

### Data Structures

```cpp
// Pending PING info (PONG built later when flushing, not on hot path)
struct PendingPing {
    uint32_t payload_offset;   // MSG_INBOX offset of PING payload
    uint16_t payload_len;      // PING payload length
};

// Member variables
PendingPing pending_ping_;
bool has_pending_ping_ = false;
```

### Flow

```
on_event(MsgMetadata):
    parse frames...
    if PING found:
        publish WSFrameInfo (unchanged)
        if has_pending_ping_:
            flush_pending_pong()     // New PING while pending → flush old first
        store pending_ping_          // Don't build PONG yet
        has_pending_ping_ = true

run() main loop:
    processed = process_manually(...)
    commit if processed > 0

    if has_pending_ping_ && processed == 0:   // IDLE
        flush_pending_pong()

    pause if idle

shutdown:
    flush_pending_pong()             // Flush any remaining PONG
```

### Implementation

```cpp
void flush_pending_pong() {
    if (!has_pending_ping_) return;

    int64_t pong_seq = pongs_prod_->try_claim();
    if (pong_seq < 0) {
        fprintf(stderr, "[WS-PROCESS] FATAL: PONGS full\n");
        std::abort();
    }

    auto& pong = (*pongs_prod_)[pong_seq];
    pong.clear();

    // Build PONG frame now (deferred from PING receipt)
    const uint8_t* ping_payload = msg_inbox_->data_at(pending_ping_.payload_offset);
    uint8_t mask_key[4] = {0, 0, 0, 0};

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
    // Publish WSFrameInfo for PING (unchanged - allows client to see PING timing)
    // ... WSFrameInfo publishing code ...

    // If we already have a pending PING, flush it first (new PING arrived)
    if (has_pending_ping_) {
        flush_pending_pong();
    }

    // Store pending PING (don't build PONG yet - deferred to idle)
    pending_ping_.payload_offset = current_payload_offset_;
    pending_ping_.payload_len = static_cast<uint16_t>(payload_len);
    has_pending_ping_ = true;
}
```

### Main Loop with Deferred PONG

```cpp
void run() {
    conn_state_->set_ready(PROC_WEBSOCKET);

    while (conn_state_->is_running(PROC_WEBSOCKET)) {
        size_t processed = msg_metadata_cons_->process_manually(
            [this](MsgMetadata& meta, int64_t seq, bool end_of_batch) {
                on_event(meta, seq, end_of_batch);
                return true;
            },
            MAX_ACCUMULATED_METADATA
        );

        if (processed > 0) {
            msg_metadata_cons_->commit_manually();
        }

        // Flush PONG on IDLE (no frames processed this round)
        if (has_pending_ping_ && processed == 0) {
            flush_pending_pong();
        }

        if (processed == 0) {
            __builtin_ia32_pause();
        }
    }

    // Flush any remaining PONG on shutdown
    flush_pending_pong();
}
```

### Benefits

| Aspect | Before | After |
|--------|--------|-------|
| PING handling | Build PONG immediately in hot path | Store offset/len only |
| PONG building | During frame parsing | Deferred to idle |
| New PING while pending | N/A (immediate send) | Flush old, store new |
| Shutdown | N/A | Flush pending PONG |

---

## Frame Handler

```cpp
void WebSocketProcess::handle_complete_frame(const uint8_t* frame_start,
                                              const WebSocketFrame& frame,
                                              size_t consumed) {
    uint64_t ws_parse_cycle = rdtscp();  // From core/timing.hpp

    // WebSocketOpcode enum from core/http.hpp
    if (frame.opcode == static_cast<uint8_t>(WebSocketOpcode::PING)) {
        // Publish WSFrameInfo for PING (allows client to see PING timing)
        int64_t ws_seq = ws_frame_producer_.try_claim();
        if (ws_seq < 0) std::abort();

        auto& info = ws_frame_producer_[ws_seq];
        size_t payload_offset_in_data = frame.payload - frame_start;
        info.msg_inbox_offset = (consumed + payload_offset_in_data) % MSG_INBOX_SIZE;
        info.payload_len = static_cast<uint32_t>(frame.payload_len);
        info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
        info.opcode = 0x09;  // PING opcode
        info.is_fin = true;
        info.is_fragmented = false;
        info.is_last_fragment = false;

        // Timestamps from accumulated metadata
        info.first_byte_ts = first_packet_metadata_.first_nic_timestamp_ns;
        info.first_nic_frame_poll_cycle = first_packet_metadata_.first_nic_frame_poll_cycle;
        info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
        info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
        info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
        info.first_ssl_read_cycle = first_packet_metadata_.ssl_read_cycle;
        info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
        info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
        // Sum packet counts from all accumulated metadata
        info.nic_packet_ct = 0;
        for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
            info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
        }
        info.ws_parse_cycle = ws_parse_cycle;

        ws_frame_producer_.publish(ws_seq);

        // DEFERRED PONG: Store pending PING info, don't build PONG on hot path
        // If we already have a pending PING, flush it first (new PING arrived)
        if (has_pending_ping_) {
            flush_pending_pong();
        }

        // Store pending PING (PONG built later on idle)
        pending_ping_.payload_offset = (consumed + payload_offset_in_data) % MSG_INBOX_SIZE;
        pending_ping_.payload_len = static_cast<uint16_t>(frame.payload_len);
        has_pending_ping_ = true;

    } else if (frame.opcode == static_cast<uint8_t>(WebSocketOpcode::CLOSE)) {
        // Signal close to Transport - FATAL if ring full
        int64_t seq = msg_outbox_producer_.try_claim();
        if (seq < 0) std::abort();  // MSG_OUTBOX ring full

        auto& event = msg_outbox_producer_[seq];
        event.msg_type = MSG_TYPE_WS_CLOSE;
        event.data_len = 2;
        if (frame.payload_len >= 2) {
            // Use close code from peer
            event.data[0] = frame.payload[0];
            event.data[1] = frame.payload[1];
        } else {
            // No close code provided - default to 1000 (Normal Closure)
            event.data[0] = 0x03;  // 1000 >> 8 = 0x03
            event.data[1] = 0xE8;  // 1000 & 0xFF = 0xE8
        }
        msg_outbox_producer_.publish(seq);

    } else if (frame.opcode == static_cast<uint8_t>(WebSocketOpcode::TEXT) ||
               frame.opcode == static_cast<uint8_t>(WebSocketOpcode::BINARY)) {
        // Handle fragmented messages (FIN=0 means more fragments to come)
        if (!frame.fin) {
            // First fragment: start accumulation and save timestamps
            accumulating_fragments_ = true;
            fragment_opcode_ = frame.opcode;
            // NOTE: 'consumed' is already the MSG_INBOX offset (see on_event line 241)
            size_t payload_offset_in_data = frame.payload - frame_start;
            fragment_start_offset_ = (consumed + payload_offset_in_data) % MSG_INBOX_SIZE;
            fragment_total_len_ = static_cast<uint32_t>(frame.payload_len);
            fragment_total_frame_len_ = static_cast<uint32_t>(frame.header_len + frame.payload_len);
            // Save timestamps from first fragment
            // NOTE: first_packet_metadata_ contains timestamps from the FIRST SSL_read that
            // contributed to this WS frame (recovered from accumulated_metadata_.front()).
            // If the first TEXT/BINARY frame spans multiple SSL_reads, first_packet_metadata_
            // correctly reflects the true first packet of the entire fragmented message.
            fragment_first_metadata_ = first_packet_metadata_;

            // Publish WSFrameInfo for first fragment immediately (allows client to start processing)
            int64_t seq = ws_frame_producer_.try_claim();
            if (seq < 0) std::abort();  // WS_FRAME_INFO ring full

            auto& info = ws_frame_producer_[seq];
            info.msg_inbox_offset = fragment_start_offset_;  // Valid for this fragment only
            info.payload_len = static_cast<uint32_t>(frame.payload_len);  // This fragment's payload
            info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
            info.opcode = frame.opcode;  // TEXT or BINARY
            info.is_fin = false;
            info.is_fragmented = true;        // Part of fragmented message
            info.is_last_fragment = false;    // More fragments to come

            info.first_byte_ts = first_packet_metadata_.first_nic_timestamp_ns;
            info.first_nic_frame_poll_cycle = first_packet_metadata_.first_nic_frame_poll_cycle;
            info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
            info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
            info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
            info.first_ssl_read_cycle = first_packet_metadata_.ssl_read_cycle;
            info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
            info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
            // Sum packet counts from all accumulated metadata
            info.nic_packet_ct = 0;
            for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
                info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
            }
            info.ws_parse_cycle = ws_parse_cycle;

            ws_frame_producer_.publish(seq);
            return;  // Wait for continuation frames
        }

        // Complete single-frame message - publish WSFrameInfo
        publish_ws_frame_info(frame_start, frame, consumed, ws_parse_cycle);

    } else if (frame.opcode == 0x00) {  // CONTINUATION frame (opcode 0)
        // RFC 6455: CONTINUATION frames carry subsequent fragments of a fragmented message.
        // The first frame has opcode TEXT/BINARY with FIN=0, followed by CONTINUATION frames
        // with opcode=0. The final frame has opcode=0 with FIN=1.
        //
        // NOTE: This is a separate case from TEXT/BINARY handling above. The control flow is:
        //   1. TEXT/BINARY with FIN=0 → starts accumulating_fragments_, saves timestamps
        //   2. CONTINUATION frames → accumulate payload until FIN=1
        //   3. CONTINUATION with FIN=1 → publish complete message with is_fragmented=true
        //
        if (!accumulating_fragments_) {
            // Unexpected continuation without first fragment - protocol error, ignore
            return;
        }

        // Accumulate fragment payload and frame lengths
        fragment_total_len_ += static_cast<uint32_t>(frame.payload_len);
        fragment_total_frame_len_ += static_cast<uint32_t>(frame.header_len + frame.payload_len);

        // Calculate this fragment's payload offset in MSG_INBOX
        size_t payload_offset_in_data = frame.payload - frame_start;
        uint32_t this_fragment_offset = (consumed + payload_offset_in_data) % MSG_INBOX_SIZE;

        if (!frame.fin) {
            // Intermediate CONTINUATION fragment - publish immediately for faster client processing
            int64_t seq = ws_frame_producer_.try_claim();
            if (seq < 0) std::abort();  // WS_FRAME_INFO ring full

            auto& info = ws_frame_producer_[seq];
            info.msg_inbox_offset = this_fragment_offset;  // Valid for this fragment only
            info.payload_len = static_cast<uint32_t>(frame.payload_len);  // This fragment's payload
            info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
            info.opcode = fragment_opcode_;  // Original opcode (TEXT or BINARY)
            info.is_fin = false;
            info.is_fragmented = true;        // Part of fragmented message
            info.is_last_fragment = false;    // More fragments to come

            // Timestamps for this fragment
            info.first_byte_ts = first_packet_metadata_.first_nic_timestamp_ns;
            info.first_nic_frame_poll_cycle = first_packet_metadata_.first_nic_frame_poll_cycle;
            info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
            info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
            info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
            info.first_ssl_read_cycle = first_packet_metadata_.ssl_read_cycle;
            info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
            info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
            info.nic_packet_ct = 0;
            for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
                info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
            }
            info.ws_parse_cycle = ws_parse_cycle;

            ws_frame_producer_.publish(seq);
            return;  // Continue accumulating
        }

        // Final fragment (FIN=1) - publish with is_last_fragment=true
            // Final fragment - publish and signal message complete
            //
            // WSFrameInfo publishing strategy for fragmented messages:
            //   - Each fragment (first, intermediate, final) is published immediately
            //   - AppClient receives fragments in order and can process incrementally
            //   - is_last_fragment=true signals the complete message boundary
            //
            // Fragment field semantics:
            //   - msg_inbox_offset: Valid for THIS fragment's payload location
            //   - payload_len: THIS fragment's payload length (not total)
            //   - is_fragmented=true: Part of a multi-frame message
            //   - is_last_fragment: false=more coming, true=message complete
            //
            // AppClient must accumulate fragments if it needs the complete message,
            // or can process each fragment incrementally for lower latency.
            //
            int64_t seq = ws_frame_producer_.try_claim();
            if (seq < 0) std::abort();  // WS_FRAME_INFO ring full

            auto& info = ws_frame_producer_[seq];
            info.msg_inbox_offset = this_fragment_offset;  // Valid for this fragment
            info.payload_len = static_cast<uint32_t>(frame.payload_len);  // This fragment's payload
            info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
            info.opcode = fragment_opcode_;  // Original opcode (TEXT or BINARY)
            info.is_fin = true;
            info.is_fragmented = true;        // Part of fragmented message
            info.is_last_fragment = true;     // This is the final fragment

            // Timestamps for this final fragment
            info.first_byte_ts = first_packet_metadata_.first_nic_timestamp_ns;
            info.first_nic_frame_poll_cycle = first_packet_metadata_.first_nic_frame_poll_cycle;
            info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
            info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
            info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
            info.first_ssl_read_cycle = first_packet_metadata_.ssl_read_cycle;
            info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
            info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
            info.nic_packet_ct = 0;
            for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
                info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
            }
            info.ws_parse_cycle = ws_parse_cycle;

            ws_frame_producer_.publish(seq);

            // Reset fragment state
            accumulating_fragments_ = false;
            fragment_opcode_ = 0;
            fragment_total_len_ = 0;
            fragment_total_frame_len_ = 0;

    } else if (frame.opcode == 0x0A) {  // PONG frame (opcode 10)
        // Ignore incoming PONG frames gracefully
        // RFC 6455: "A Pong frame MAY be sent unsolicited. This serves as a unidirectional heartbeat."
        // We don't track outgoing PINGs, so we just ignore PONGs from server.
        return;
    }
}

// Helper to publish WSFrameInfo for complete single-frame messages
void WebSocketProcess::publish_ws_frame_info(const uint8_t* frame_start,
                                              const WebSocketFrame& frame,
                                              size_t consumed,
                                              uint64_t ws_parse_cycle) {
    int64_t seq = ws_frame_producer_.try_claim();
    if (seq < 0) std::abort();  // WS_FRAME_INFO ring full

    auto& info = ws_frame_producer_[seq];

    // Message location with wrap-around handling
    // NOTE: 'consumed' is the MSG_INBOX offset where this WS frame starts (passed from handle_complete_frame)
    //       It already represents data_start_offset_ + parse_offset_ (see on_event line 241)
    //       payload_offset_in_data is the WS header length (offset from frame_start to payload)
    // Result: MSG_INBOX offset where payload data begins
    size_t payload_offset_in_data = frame.payload - frame_start;
    info.msg_inbox_offset = (consumed + payload_offset_in_data) % MSG_INBOX_SIZE;
    info.payload_len = static_cast<uint32_t>(frame.payload_len);
    info.frame_total_len = static_cast<uint32_t>(frame.header_len + frame.payload_len);
    info.opcode = frame.opcode;
    info.is_fin = frame.fin;
    info.is_fragmented = false;       // Single-frame message, not fragmented
    info.is_last_fragment = false;    // Not applicable for non-fragmented messages

    // Full timestamp chain
    info.first_byte_ts = first_packet_metadata_.first_nic_timestamp_ns;
    info.first_nic_frame_poll_cycle = first_packet_metadata_.first_nic_frame_poll_cycle;
    info.last_byte_ts = current_metadata_.latest_nic_timestamp_ns;
    info.latest_nic_frame_poll_cycle = current_metadata_.latest_nic_frame_poll_cycle;
    info.latest_raw_frame_poll_cycle = current_metadata_.latest_raw_frame_poll_cycle;
    info.first_ssl_read_cycle = first_packet_metadata_.ssl_read_cycle;
    info.last_ssl_read_cycle = current_metadata_.ssl_read_cycle;
    info.ssl_read_ct = static_cast<uint32_t>(accumulated_metadata_count_);
    // Sum packet counts from all accumulated metadata
    info.nic_packet_ct = 0;
    for (size_t i = 0; i < accumulated_metadata_count_; ++i) {
        info.nic_packet_ct += accumulated_metadata_[i].nic_packet_ct;
    }
    info.ws_parse_cycle = ws_parse_cycle;

    ws_frame_producer_.publish(seq);
}
```

---

## Partial Frame Handling and Timestamp Recovery

### Partial Frame Accumulation Mode

WebSocket Process uses **partial frame accumulation mode** (same pattern as `src/websocket.hpp` lines 585-1312) to handle WS frames that span multiple SSL_reads:

1. **Accumulate data**: Each `on_event()` adds `meta.decrypted_len` to `data_accumulated_`
2. **Parse incrementally**: Resume parsing from `parse_offset_` within accumulated data
3. **Preserve on partial**: If frame incomplete, return early (preserve parser state)
4. **Reset on complete**: When all frames parsed, reset accumulators

**Note**: Ring buffer consumption happens immediately via `event_processor`; only the WS frame parsing state is preserved across events. This is distinct from deferring ring buffer consumption.

**Why This Works**:
- MSG_INBOX already contains all accumulated data from Transport
- Each TLS record is contiguous in MSG_INBOX (Transport guarantees this by checking linear space before SSL_read)
- WS frames spanning multiple TLS records may be non-contiguous if wrap occurs between records
- We track offsets, not copy data - true zero-copy parsing

---

### MSG_INBOX TLS Record Contiguity Guarantee

Transport Process guarantees **each TLS record is contiguous** by checking `linear_space >= TLS_RECORD_MAX_SIZE` (16640 bytes) before each SSL_read. If insufficient linear space exists before the wrap point, Transport resets to head first. This means:

1. **Each TLS record is contiguous** - a single TLS record never spans the MSG_INBOX wrap point
2. **WS frames within a single TLS record are contiguous** - they're contained within that record
3. **WS frames spanning multiple TLS records may be non-contiguous** - if the wrap point falls between TLS records, the WS frame payload is split. WebSocket Process handles this via `on_message_wrapped()` callback.
4. **Partial WS frames across SSL_reads**: Each TLS record's data is contiguous; we track offset/length to access all parts

**NOTE**: A WebSocket frame can span multiple TLS records. If a wrap occurs between these records, the WS frame payload becomes non-contiguous in MSG_INBOX. AppClient receives such payloads via `on_message_wrapped(seg1, seg1_len, seg2, seg2_len, opcode)` and must handle the two segments appropriately.

See `pipeline_1_trans.md` `ssl_read_to_msg_inbox()` for the linear space check logic.

---

### Key State Variables

| Variable | Purpose |
|----------|---------|
| `data_start_offset_` | MSG_INBOX offset where current batch starts |
| `data_accumulated_` | Total bytes accumulated for current partial frame |
| `parse_offset_` | How far we've parsed within accumulated data |
| `has_pending_frame_` | True if we're in the middle of parsing a frame |
| `pending_frame_` | Saved parser state (header bytes, expected lengths) |
| `accumulated_metadata_` | Array of ALL MsgMetadata events for timestamp/packet count recovery |
| `accumulated_metadata_count_` | Number of MsgMetadata events accumulated |
| `first_packet_metadata_` | Recovered timestamps from first SSL_read |
| `pending_ping_` | Stores pending PING info (offset, len) for deferred PONG |
| `has_pending_ping_` | Whether we have a pending PING awaiting PONG response |

**MsgMetadata fields used**:
- `first_nic_timestamp_ns`, `first_nic_frame_poll_cycle` - timestamps from first packet
- `ssl_read_cycle` - used for `first_ssl_read_cycle` and `last_ssl_read_cycle`
- `nic_packet_ct` - summed across all accumulated metadata for WSFrameInfo.nic_packet_ct

---

### Timestamp Flow for Multi-SSL_read Frames

```
SSL_read #1 (start of WS frame):
  ├── on_event(): data_start_offset_ = meta.msg_inbox_offset
  ├──              data_accumulated_ = 500, parse_offset_ = 0
  ├──              accumulated_metadata_.push(meta1)
  ├── Parsing: start_parse_frame() → frame needs 2000 bytes, only 500 available
  └── DEFER: has_pending_frame_ = true, return early

SSL_read #2 (continuation):
  ├── on_event(): data_accumulated_ += 600 → now 1100 bytes
  ├──              accumulated_metadata_.push(meta2)
  ├── Parsing: continue_partial_frame() → still need 900 more bytes
  └── DEFER: return early, wait for more data

SSL_read #3 (frame completes):
  ├── on_event(): data_accumulated_ += 1000 → now 2100 bytes
  ├──              accumulated_metadata_.push(meta3)
  ├── Parsing: continue_partial_frame() → SUCCESS! Frame complete
  ├── first_packet_metadata_ = accumulated_metadata_.front()  ← meta1
  ├── handle_complete_frame() with correct timestamps
  ├── parse_offset_ += 2000, check for more frames
  └── COMMIT: All data consumed, reset accumulators

WSFrameInfo timestamps:
  first_nic_timestamp_ns = meta1.first_nic_timestamp_ns       ← From SSL_read #1
  first_nic_frame_poll_cycle = meta1.first_nic_frame_poll_cycle
  first_ssl_read_cycle = meta1.ssl_read_cycle                 ← From SSL_read #1
  latest_nic_timestamp_ns = meta3.latest_nic_timestamp_ns     ← From SSL_read #3
  last_ssl_read_cycle = meta3.ssl_read_cycle                  ← From SSL_read #3
  ssl_read_ct = 3                                             ← Number of SSL_reads
  nic_packet_ct = meta1.nic_packet_ct + meta2.nic_packet_ct + meta3.nic_packet_ct
```

This ensures accurate latency measurement even for large WebSocket frames spanning multiple SSL_reads.

---

### WSFrameInfo Generation Table

| Condition | `opcode` | `is_fragmented` | `is_last_fragment` | `is_fin` |
|-----------|----------|-----------------|---------------------|----------|
| Single-frame complete | TEXT/BINARY | `false` | `false` | `true` |
| Partial frame (header complete, payload incomplete) | from header | `true` | `false` | from header |
| WS fragment first | TEXT/BINARY | `true` | `false` | `false` |
| WS fragment middle | TEXT/BINARY | `true` | `false` | `false` |
| WS fragment final | TEXT/BINARY | `true` | `true` | `true` |
| PING | 0x09 | `false` | `false` | `true` |
| Header incomplete | — | NO WSFrameInfo generated (DEFER) | — | — |

### Partial Frame Flow Diagram

```
on_event(MsgMetadata)
        │
        ▼
   Accumulate data + metadata
        │
        ▼
   Parse WS frame header
        │
   ┌────┴─────────────────┐
   │                      │
HEADER INCOMPLETE      HEADER COMPLETE
   │                      │
   ▼                      ▼
 DEFER              Check payload
(no publish)              │
                    ┌─────┴─────┐
                    │           │
              PAYLOAD       PAYLOAD
              INCOMPLETE    COMPLETE
                    │           │
                    ▼           ▼
              WSFrameInfo   WSFrameInfo
              is_frag=true  is_frag=false
              (partial)     (complete)
                    │           │
                    └─────┬─────┘
                          ▼
                    Continue loop
```

---

### Timestamp Granularity Limitation

When multiple WebSocket frames exist within a single TLS record (SSL_read), all frames
share the same `first_byte_ts` from that TLS record. Per-frame timestamps within a
single TLS record are not available because:
1. TLS decryption operates on entire records
2. NIC timestamps are captured at packet level, not application frame level

For HFT applications where sub-TLS-record timing matters, prefer servers that send
one WebSocket frame per TLS record.

---

## Helper: build_ws_header()

Build WebSocket frame header only (payload passed separately for zero-copy TX):

```cpp
// RFC 6455 client frames must be masked, but we use [0,0,0,0] mask (XOR is no-op)
// Returns header length (6-14 bytes)
size_t build_ws_header(uint8_t* header, uint8_t opcode, size_t payload_len) {
    size_t pos = 0;

    // Byte 0: FIN=1, opcode
    header[pos++] = 0x80 | (opcode & 0x0F);

    // Byte 1: MASK=1 (client frames must be masked), payload length
    if (payload_len < 126) {
        header[pos++] = 0x80 | static_cast<uint8_t>(payload_len);
    } else if (payload_len <= 0xFFFF) {
        header[pos++] = 0x80 | 126;
        header[pos++] = (payload_len >> 8) & 0xFF;
        header[pos++] = payload_len & 0xFF;
    } else {
        header[pos++] = 0x80 | 127;
        // 8-byte extended length (big-endian)
        for (int i = 7; i >= 0; --i) {
            header[pos++] = (payload_len >> (i * 8)) & 0xFF;
        }
    }

    // 4-byte mask key: [0,0,0,0] - XOR with zeros is no-op, avoids masking payload
    header[pos++] = 0;
    header[pos++] = 0;
    header[pos++] = 0;
    header[pos++] = 0;

    return pos;
}
```

---

## Ring Buffer Interactions

| Ring | Role | API |
|------|------|-----|
| MSG_METADATA_INBOX | Consumer | `event_processor.run()` with `on_event()` handler; manual polling during handshake |
| MSG_INBOX | Reader | `data_at(offset)` - read-only access |
| WS_FRAME_INFO_RING | Producer | `try_claim()` + `publish()` |
| PONGS | Producer | `try_claim()` + `publish()` (complete WS PONG frame, not just payload) |
| MSG_OUTBOX | Producer | `try_claim()` + `publish()` (handshake: HTTP upgrade, subscription; main loop: CLOSE) |

---

## Critical Error Handling

| Condition | Action |
|-----------|--------|
| WS_FRAME_INFO ring full | `std::abort()` - AppClient is not keeping up |
| PONGS ring full | `std::abort()` - Transport is not processing PONGs |
| MSG_OUTBOX ring full | `std::abort()` - Transport is not processing outbound messages |
| Partial frame | Save state, continue on next event |

---

## Performance Considerations

1. **Auto-consumer**: Uses `event_processor.run()` - no manual polling needed
2. **Zero-copy reads**: Reads directly from MSG_INBOX via pointer
3. **Batch processing**: Multiple WS frames per SSL_read batch processed together
4. **Inline timestamp**: `ws_parse_cycle` captured via `rdtscp()` at parse completion
5. **Reusable parser**: Uses `parse_websocket_frame()` from core/http.hpp

---

## Data Flow

```
MSG_METADATA_INBOX ──event_processor.run()──► on_event()
                                                   │
MSG_INBOX ◄──────────data_at(offset)───────────────┤
                                                   │
                                                   ▼
                                          parse_websocket_frame()
                                                   │
                    ┌──────────────────────────────┼────────────────────────────┐
                    │                              │                            │
                    ▼                              ▼                            ▼
              PING frame                     TEXT/BINARY                   CLOSE frame
                    │                              │                            │
                    ▼                              ▼                            ▼
              PONGS ring                   WS_FRAME_INFO_RING             MSG_OUTBOX
                    │                              │                            │
                    ▼                              ▼                            ▼
             Transport                        AppClient                    Transport
         (builds PONG TCP)              (processes messages)          (sends WS CLOSE)
```

---

## ws_parser.hpp Contents

**File**: `src/pipeline/ws_parser.hpp`

This file provides a stateful WebSocket parser with partial frame tracking. It extends the basic `parse_websocket_frame()` from `core/http.hpp` to handle frames that span multiple SSL_read batches.

### PartialWebSocketFrame Struct

```cpp
#pragma once
#include <core/http.hpp>
#include <cstdint>
#include <cstring>

namespace pipeline {

// Extended WebSocketFrame with partial parsing state
// Used when a WS frame spans multiple MSG_METADATA_INBOX events
struct PartialWebSocketFrame {
    // Core frame data (same as core/http.hpp WebSocketFrame)
    uint8_t opcode;
    bool fin;
    uint64_t payload_len;
    const uint8_t* payload;     // Points into MSG_INBOX when complete
    size_t header_len;

    // Partial parsing state
    bool header_complete = false;
    size_t expected_header_len = 2;   // Minimum header size, grows as we parse
    size_t parsed_header_len = 0;     // How much header we've accumulated
    uint8_t header_buf[14];           // Max WS header size (2 + 8 + 4 mask)

    void reset() {
        header_complete = false;
        expected_header_len = 2;
        parsed_header_len = 0;
        payload = nullptr;
        payload_len = 0;
    }
};
```

### parse_completed_header()

```cpp
// Parse a complete WS header from header_buf
// Called after header_complete = true to extract frame fields
inline void parse_completed_header(PartialWebSocketFrame& frame) {
    const uint8_t* h = frame.header_buf;

    frame.fin = (h[0] & 0x80) != 0;
    frame.opcode = h[0] & 0x0F;

    bool masked = (h[1] & 0x80) != 0;
    uint8_t len_byte = h[1] & 0x7F;

    // RFC 6455 Section 5.1: Server-to-client frames MUST NOT be masked
    // A client MUST close connection if it receives a masked frame from server
    // For HFT, we abort immediately on protocol violation
    if (masked) {
        std::abort();  // FATAL: Server sent masked frame - RFC 6455 violation
    }

    size_t offset = 2;
    if (len_byte < 126) {
        frame.payload_len = len_byte;
    } else if (len_byte == 126) {
        frame.payload_len = (static_cast<uint64_t>(h[2]) << 8) | h[3];
        offset = 4;
    } else {  // len_byte == 127
        frame.payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            frame.payload_len = (frame.payload_len << 8) | h[2 + i];
        }
        offset = 10;
    }

    // No mask key for server frames (verified above)
    frame.header_len = offset;
}
```

### start_parse_frame()

```cpp
// Start parsing a new WebSocket frame
// Returns true if frame is complete, false if partial
// If partial, frame state is populated for later continuation via continue_partial_frame()
inline bool start_parse_frame(const uint8_t* data, size_t len, PartialWebSocketFrame& frame) {
    frame.reset();

    if (len < 2) {
        // Not enough data for minimum header
        size_t to_copy = len;
        memcpy(frame.header_buf, data, to_copy);
        frame.parsed_header_len = to_copy;
        return false;
    }

    // Parse first 2 bytes to determine header length
    uint8_t len_byte = data[1] & 0x7F;
    bool masked = (data[1] & 0x80) != 0;

    if (len_byte < 126) {
        frame.expected_header_len = 2 + (masked ? 4 : 0);
    } else if (len_byte == 126) {
        frame.expected_header_len = 4 + (masked ? 4 : 0);
    } else {  // len_byte == 127
        frame.expected_header_len = 10 + (masked ? 4 : 0);
    }

    if (len < frame.expected_header_len) {
        // Partial header
        memcpy(frame.header_buf, data, len);
        frame.parsed_header_len = len;
        return false;
    }

    // Complete header - parse it
    memcpy(frame.header_buf, data, frame.expected_header_len);
    frame.header_complete = true;
    frame.header_len = frame.expected_header_len;
    parse_completed_header(frame);

    // Check if we have complete payload
    size_t total_frame_len = frame.header_len + frame.payload_len;
    if (len < total_frame_len) {
        // Have header but not full payload
        frame.parsed_header_len = len;  // Track how much data we've seen
        return false;
    }

    // Frame complete
    frame.payload = data + frame.header_len;
    return true;
}
```

### continue_partial_frame()

```cpp
// Continue parsing a partial frame with new data
// Returns true if frame is now complete, false if still incomplete
// On return, frame.payload points to payload start in current data buffer
inline bool continue_partial_frame(const uint8_t* data, size_t len, PartialWebSocketFrame& frame) {
    // If we don't have the full header yet, try to complete it
    if (!frame.header_complete) {
        size_t needed = frame.expected_header_len - frame.parsed_header_len;

        // Do we have enough to determine actual header length?
        if (frame.parsed_header_len < 2) {
            size_t to_copy = std::min(len, 2 - frame.parsed_header_len);
            memcpy(frame.header_buf + frame.parsed_header_len, data, to_copy);
            frame.parsed_header_len += to_copy;

            if (frame.parsed_header_len >= 2) {
                // Now we can determine expected header length
                uint8_t len_byte = frame.header_buf[1] & 0x7F;
                bool masked = (frame.header_buf[1] & 0x80) != 0;

                if (len_byte < 126) {
                    frame.expected_header_len = 2 + (masked ? 4 : 0);
                } else if (len_byte == 126) {
                    frame.expected_header_len = 4 + (masked ? 4 : 0);
                } else {
                    frame.expected_header_len = 10 + (masked ? 4 : 0);
                }

                needed = frame.expected_header_len - frame.parsed_header_len;
                data += to_copy;
                len -= to_copy;
            } else {
                return false;  // Still need more header bytes
            }
        }

        if (len < needed) {
            // Still not enough for header
            memcpy(frame.header_buf + frame.parsed_header_len, data, len);
            frame.parsed_header_len += len;
            return false;
        }

        // Complete the header
        memcpy(frame.header_buf + frame.parsed_header_len, data, needed);
        frame.header_complete = true;
        frame.header_len = frame.expected_header_len;
        parse_completed_header(frame);

        data += needed;
        len -= needed;
        frame.parsed_header_len = frame.header_len;
    }

    // Check if we have enough data for remaining payload
    size_t payload_already_seen = frame.parsed_header_len - frame.header_len;
    size_t payload_still_need = frame.payload_len - payload_already_seen;

    if (len < payload_still_need) {
        // Still incomplete
        frame.parsed_header_len += len;  // Track total bytes seen
        return false;
    }

    // Frame complete - set payload pointer
    //
    // IMPORTANT: Payload spanning multiple buffers
    // When payload_already_seen > 0, the payload started in a previous buffer and
    // continues into this one. The caller (WebSocketProcess) uses MSG_INBOX offsets
    // to access the full payload:
    //   - data_start_offset_ points to where this frame's data begins in MSG_INBOX
    //   - The full payload is contiguous in MSG_INBOX (Transport guarantees this)
    //   - frame.payload here points into the *current* data buffer for parsing,
    //     but on_event() uses MSG_INBOX offsets for the actual WSFrameInfo
    //
    // The caller must NOT use frame.payload directly when payload spans buffers.
    // Instead, calculate: msg_inbox_.data_at(data_start_offset_ + header_len)
    //
    if (payload_already_seen == 0) {
        frame.payload = data;  // Entire payload is in this buffer
    } else {
        // Payload spans buffers - set to current buffer position for header-only parsing
        // Caller MUST use MSG_INBOX offsets for actual payload access
        frame.payload = data;
    }
    return true;
}

} // namespace pipeline
```

### Usage Notes

1. **Single-buffer frames**: Use `start_parse_frame()` first. If it returns `true`, the frame is complete and `frame.payload` points directly to the payload in the provided buffer.

2. **Multi-buffer frames**: If `start_parse_frame()` returns `false`, save the `PartialWebSocketFrame` state. On the next data arrival, call `continue_partial_frame()`.

3. **Payload spanning buffers**: When payload spans multiple data buffers (SSL_reads), `frame.payload` is only valid for single-buffer cases. For multi-buffer payloads:
   - The caller (WebSocketProcess) tracks `data_start_offset_` and `data_accumulated_` in MSG_INBOX
   - MSG_INBOX contains the complete, contiguous payload (Transport guarantees contiguity)
   - Use `msg_inbox_.data_at(offset + header_len)` to get the actual payload pointer
   - `frame.header_len` and `frame.payload_len` are always correct for size calculations

4. **MSG_INBOX wrap points**: When payload spans the MSG_INBOX wrap point, AppClient receives two segments via `on_message_wrapped()`. The payload is still logically contiguous but physically wraps around buffer end.

5. **Thread safety**: Each `WebSocketProcess` instance has its own `pending_frame_` state, so no synchronization is needed.
