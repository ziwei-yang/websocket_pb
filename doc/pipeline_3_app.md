# Pipeline Process 3: AppClient (Core 8)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [Transport Process (Core 4)](pipeline_1_trans.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)

---

## Library Usage Overview

The AppClient process is the **user's main process**. This library is designed so that the user's application code runs in the AppClient process while the library spawns and manages the three worker processes (XDP Poll, Transport, WebSocket).

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           USER APPLICATION WORKFLOW                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │  STEP 1: User defines handler (compile-time CRTP)                        │   │
│   │                                                                          │   │
│   │  class MyHandler : public AppClientHandler<MyHandler> {                  │   │
│   │      // RX callbacks                                                     │   │
│   │      void on_message(const uint8_t* data, uint32_t len, uint8_t op);     │   │
│   │      void on_message_wrapped(...);                                       │   │
│   │      void on_fragmented_message(...);                                    │   │
│   │                                                                          │   │
│   │      // TX methods (inherited from AppClientHandler)                     │   │
│   │      // bool send_message(const char* data, size_t len);                 │   │
│   │      // bool send_binary(const uint8_t* data, size_t len);               │   │
│   │  };                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                          │
│                                       ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │  STEP 2: Create pipeline and configure                                   │   │
│   │                                                                          │   │
│   │  WebSocketClientPipeline<MyHandler> pipeline(                            │   │
│   │      "wss://stream.binance.com/ws",                                      │   │
│   │      WebSocketConfig{...}                                                │   │
│   │  );                                                                      │   │
│   │  pipeline.setup();   // Init shm, TCP/TLS/WS handshake                   │   │
│   │  pipeline.subscribe(R"({"method":"SUBSCRIBE",...})");                    │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                          │
│                                       ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │  STEP 3: Start pipeline                                                  │   │
│   │                                                                          │   │
│   │  pipeline.start();   // Forks 3 child processes, runs AppClient inline   │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                       │                                          │
│                                       ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                                                                          │   │
│   │                          PROCESS SPAWN                                   │   │
│   │                                                                          │   │
│   │   ┌──────────────────┐                                                   │   │
│   │   │ fork() ──────────┼────► Child 1: XDP Poll Process (Core 2)           │   │
│   │   │                  │                  │                                │   │
│   │   │ fork() ──────────┼────► Child 2: Transport Process (Core 4)          │   │
│   │   │                  │                  │                                │   │
│   │   │ fork() ──────────┼────► Child 3: WebSocket Process (Core 6)          │   │
│   │   │                  │                  │                                │   │
│   │   │ (main continues) │                  │                                │   │
│   │   │       │          │                  │                                │   │
│   │   │       ▼          │                  │                                │   │
│   │   │  AppClient.run() │ ◄────────────────┘                                │   │
│   │   │  (Core 8)        │      IPC via shared memory                        │   │
│   │   │       │          │                                                   │   │
│   │   │       ▼          │                                                   │   │
│   │   │  on_message()    │   RX: receive messages                            │   │
│   │   │  called for each │                                                   │   │
│   │   │  WS message      │                                                   │   │
│   │   │       │          │                                                   │   │
│   │   │       ▼          │                                                   │   │
│   │   │  send_message()  │   TX: send messages                               │   │
│   │   │  send_binary()   │                                                   │   │
│   │   └──────────────────┘                                                   │   │
│   │                                                                          │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

```
                              SHARED MEMORY (IPC)
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                                                                               │
   │   NIC Hardware                                                                │
   │        │▲                                                                     │
   │        ││ (AF_XDP zero-copy)                                                  │
   │        ▼│                                                                     │
   │   ┌─────────────────┐     RAW_INBOX      ┌─────────────────┐                  │
   │   │  XDP Poll       │ ─────────────────► │  Transport      │◄─── MSG_OUTBOX ─┐│
   │   │  Process        │ ◄───────────────── │  Process        │                 ││
   │   │  (Core 2)       │     RAW_OUTBOX     │  (Core 4)       │                 ││
   │   └─────────────────┘                    └─────────────────┘                 ││
   │                                                 │                            ││
   │                                                 │ MSG_METADATA_INBOX         ││
   │                                                 │ MSG_INBOX (decrypted TLS)  ││
   │                                                 ▼                            ││
   │                                          ┌─────────────────┐                 ││
   │                                          │  WebSocket      │                 ││
   │                                          │  Process        │                 ││
   │                                          │  (Core 6)       │                 ││
   │                                          └─────────────────┘                 ││
   │                                                 │                            ││
   │                                                 │ WS_FRAME_INFO_RING         ││
   │                                                 ▼                            ││
   │   ┌─────────────────────────────────────────────────────────────────────┐   ││
   │   │                     AppClient Process (Core 8)                       │   ││
   │   │                     ═══════════════════════════                      │   ││
   │   │                     THIS IS YOUR APPLICATION                         │   ││
   │   │                                                                      │   ││
   │   │    ┌──────────────────┐                                              │   ││
   │   │    │ event_processor  │──► on_message(payload, len, opcode)          │   ││
   │   │    │     .run()       │         │                                    │   ││
   │   │    └──────────────────┘         ▼                                    │   ││
   │   │                           User's callback code                       │   ││
   │   │                           (JSON parsing, trading logic, etc.)        │   ││
   │   │                                  │                                   │   ││
   │   │                                  ▼                                   │   ││
   │   │                           send_message() / send_binary()  ───────────┼───┘│
   │   │                                                                      │    │
   │   └─────────────────────────────────────────────────────────────────────┘    │
   │                                                                               │
   └──────────────────────────────────────────────────────────────────────────────┘
```

### Minimal Client Code Example

```cpp
#include <websocket_pb/pipeline.hpp>
#include <cstdio>

// STEP 1: Define your message handler
class MyHandler : public websocket_pb::AppClientHandler<MyHandler> {
public:
    using AppClientHandler::AppClientHandler;

    // Called for each contiguous WebSocket message (RX)
    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        // Simply print the message
        printf("[MSG] opcode=%u len=%u: %.*s\n", opcode, len, len, payload);

        // Example: Echo message back to server (TX)
        // send_message(reinterpret_cast<const char*>(payload), len);
    }

    // Called when payload wraps around MSG_INBOX boundary (rare)
    void on_message_wrapped(const uint8_t* seg1, uint32_t seg1_len,
                            const uint8_t* seg2, uint32_t seg2_len,
                            uint8_t opcode) {
        // For simplicity, concatenate and print
        printf("[MSG-WRAPPED] opcode=%u total_len=%u\n", opcode, seg1_len + seg2_len);
        printf("  seg1: %.*s\n", seg1_len, seg1);
        printf("  seg2: %.*s\n", seg2_len, seg2);
    }

    // Called for fragmented messages (is_fragmented=true)
    void on_fragmented_message(const websocket_pb::WSFrameInfo& info) {
        // Fragmented messages not supported in this example
        printf("[WARN] Fragmented message received, skipping (len=%u)\n", info.payload_len);
    }

    // User-defined method for sending messages (TX)
    void send_order(const char* order_json) {
        if (!send_message(order_json, strlen(order_json))) {
            printf("[WARN] MSG_OUTBOX full, order not sent\n");
        }
    }
};

int main(int argc, char* argv[]) {
    // STEP 2: Configure and create pipeline
    websocket_pb::WebSocketConfig config;
    config.interface = "enp108s0";           // XDP interface
    config.url = "wss://stream.binance.com/ws/btcusdt@trade";
    config.cpu_cores = {2, 4, 6, 8};         // XDP, Transport, WebSocket, AppClient

    websocket_pb::WebSocketClientPipeline<MyHandler> pipeline(config);

    // Initialize: creates shared memory, performs TCP/TLS/WS handshake
    if (!pipeline.setup()) {
        fprintf(stderr, "Pipeline setup failed\n");
        return 1;
    }

    // Optional: send subscription messages before starting
    pipeline.subscribe(R"({"method":"SUBSCRIBE","params":["btcusdt@trade"],"id":1})");

    // STEP 3: Start pipeline
    // This call:
    //   1. Forks 3 child processes (XDP Poll, Transport, WebSocket)
    //   2. Runs AppClient.run() in THIS process (blocking)
    //   3. Your on_message() is called for each WebSocket message (RX)
    //   4. You can call send_message()/send_binary() to send messages (TX)
    //
    // Returns when:
    //   - Connection closes (server FIN)
    //   - SIGINT/SIGTERM received
    //   - Error occurs
    pipeline.start();

    printf("Pipeline stopped\n");
    return 0;
}
```

### Build & Run

```bash
# Build (requires sudo for XDP)
make my_client USE_WOLFSSL=1 PATH_MTU=1500

# Run with CPU pinning
sudo ./build/my_client
```

### Key Points

1. **User code is the main process**: Your `main()` function calls `pipeline.start()`, which forks worker processes and then runs AppClient inline.

2. **Callbacks are compile-time**: `on_message()`, `on_message_wrapped()`, and `on_fragmented_message()` are resolved at compile time via CRTP (no virtual function overhead).

3. **Zero-copy payloads (RX)**: The `payload` pointer in `on_message()` points directly into shared memory (MSG_INBOX). Do NOT store this pointer - copy data if you need it after returning.

4. **Sending messages (TX)**: Call `send_message()` or `send_binary()` from your handler to send WebSocket messages to the server. Returns `false` if MSG_OUTBOX is full (backpressure).

5. **Worker processes are internal**: XDP Poll, Transport, and WebSocket processes are implementation details. They communicate with AppClient via shared memory rings.

6. **Subscription before start**: Call `pipeline.subscribe()` after `setup()` but before `start()` to queue subscription messages.

---

## Overview (Internal Details)

AppClient Process is the **user-facing message handler**. It consumes WSFrameInfo events from the WS_FRAME_INFO_RING and provides parsed WebSocket payloads to user code via a CRTP callback pattern. It also provides TX methods for sending messages to the server.

**Key Responsibilities**:
1. **RX**: Consume WS_FRAME_INFO_RING events via `event_processor.run()` (auto-consumer)
2. **RX**: Read payload data from MSG_INBOX at offsets specified in WSFrameInfo
3. **RX**: Call user's `on_message()` callback with payload pointer and metadata
4. **RX**: Track consumed position in MSG_INBOX for Transport to reclaim space
5. **TX**: Provide `send_message()` and `send_binary()` methods to write to MSG_OUTBOX
6. **TX**: Handle backpressure when MSG_OUTBOX is full (return false, don't block)

---

## Code Reuse

```cpp
#include <core/http.hpp>      // WebSocketOpcode enum
#include <core/timing.hpp>    // rdtscp() for latency measurement
#include <disruptor/event_processor.hpp>
```

---

## Handler Template (CRTP Pattern)

The `AppClientHandler` template provides:
- **RX**: Consume WSFrameInfo events and dispatch to user callbacks
- **TX**: `send_message()` and `send_binary()` methods to send WebSocket messages

**Note**: The full handler template with TX support is documented in the [Sending Messages (TX Path)](#sending-messages-tx-path) section below. Here we show the RX-only version for clarity:

```cpp
// Event Handler for WS_FRAME_INFO events (CRTP pattern for user customization)
// NOTE: See "Sending Messages (TX Path)" section for full template with TX support
template<typename Derived>
class AppClientHandler : public disruptor::event_handler<WSFrameInfo> {
public:
    AppClientHandler(MsgInbox& msg_inbox) : msg_inbox_(msg_inbox) {}

    void on_event(WSFrameInfo& info, int64_t sequence, bool end_of_batch) override {
        current_info_ = &info;  // Store for on_message() access (latency calculation)

        // CRITICAL: Check is_fragmented BEFORE using msg_inbox_offset!
        // When is_fragmented=true, msg_inbox_offset is set to 0 as a SENTINEL VALUE.
        // This sentinel value is INVALID and MUST NOT be used to read payload data.
        // Fragment payloads are scattered throughout MSG_INBOX with headers between them.
        // See "Fragmented Messages" section below for handling options.
        if (info.is_fragmented) {
            // Fragmented message - msg_inbox_offset is INVALID (sentinel value 0)
            // Call derived class handler for fragmented messages
            // NOTE: Derived class MUST implement on_fragmented_message().
            static_cast<Derived*>(this)->on_fragmented_message(info);

            // IMPORTANT: For fragmented messages, we advance consumption by frame_total_len
            // even though the payloads are non-contiguous. This is a CONSERVATIVE estimate
            // that ensures Transport knows we've "consumed" the data region.
            //
            // Fragmented message layout in MSG_INBOX:
            //   [WS Header 1][Payload 1][WS Header 2][Payload 2]...[WS Header N][Payload N]
            //
            // frame_total_len = sum of all (header + payload) lengths, which represents
            // the total bytes written to MSG_INBOX for this fragmented message.
            //
            // We advance current_pos_ by frame_total_len from its current position.
            // This may over-consume slightly if there are gaps, but:
            //   1. It prevents current_pos_ from staying at 0 (initial value)
            //   2. It signals to Transport that AppClient is making progress
            //   3. It's better to over-consume than under-consume (risk dirty_flag)
            //
            // For HFT: prefer servers that send single-frame messages (no fragmentation)
            //
            current_pos_ = (current_pos_ + info.frame_total_len) % MSG_INBOX_SIZE;

            if (end_of_batch) {
                msg_inbox_.set_app_consumed(current_pos_);
            }
            return;
        }

        // DEBUG VALIDATION: Verify msg_inbox_offset is within bounds
        // This should never fail if WebSocket process is working correctly.
        // If it fails, it indicates a bug in WebSocket frame parsing or MSG_INBOX handling.
#ifdef PIPELINE_DEBUG
        if (info.msg_inbox_offset >= MSG_INBOX_SIZE) {
            fprintf(stderr, "[FATAL] Invalid msg_inbox_offset: %u >= %u (MSG_INBOX_SIZE)\n",
                    info.msg_inbox_offset, static_cast<uint32_t>(MSG_INBOX_SIZE));
            std::abort();
        }
        if (info.payload_len > MSG_INBOX_SIZE) {
            fprintf(stderr, "[FATAL] Invalid payload_len: %u > %u (MSG_INBOX_SIZE)\n",
                    info.payload_len, static_cast<uint32_t>(MSG_INBOX_SIZE));
            std::abort();
        }
#endif

        // Check if payload wraps around MSG_INBOX boundary
        uint32_t end_offset = (info.msg_inbox_offset + info.payload_len) % MSG_INBOX_SIZE;
        bool payload_wraps = (end_offset < info.msg_inbox_offset) && (info.payload_len > 0);

        if (payload_wraps) {
            // Payload wraps: provide two segments to on_message_wrapped()
            // Segment 1: from msg_inbox_offset to end of buffer
            const uint8_t* seg1 = msg_inbox_.data_at(info.msg_inbox_offset);
            uint32_t seg1_len = MSG_INBOX_SIZE - info.msg_inbox_offset;
            // Segment 2: from start of buffer to end_offset
            const uint8_t* seg2 = msg_inbox_.data_at(0);
            uint32_t seg2_len = end_offset;

            // Call wrapped handler (derived class must implement)
            static_cast<Derived*>(this)->on_message_wrapped(
                seg1, seg1_len, seg2, seg2_len, info.opcode);
        } else {
            // Contiguous payload - use simple handler
            const uint8_t* payload = msg_inbox_.data_at(info.msg_inbox_offset);
            static_cast<Derived*>(this)->on_message(payload, info.payload_len, info.opcode);
        }

        // Update consumption position to end of WS frame (header + payload)
        //
        // MSG_INBOX Layout: The decrypted TLS record contains the complete WS frame:
        //   [WS Header (2-14 bytes)] [WS Payload (variable)]
        //
        // WSFrameInfo fields:
        //   - msg_inbox_offset: Points to WS PAYLOAD start (after header)
        //   - payload_len: Length of WS payload
        //   - frame_total_len: Header length + payload length
        //
        // To find frame start: msg_inbox_offset - header_len
        // To find next frame: frame_start + frame_total_len
        //
        uint32_t header_len = info.frame_total_len - info.payload_len;
        uint32_t frame_start = (info.msg_inbox_offset - header_len + MSG_INBOX_SIZE) % MSG_INBOX_SIZE;
        current_pos_ = (frame_start + info.frame_total_len) % MSG_INBOX_SIZE;

        // Batch update: only signal consumed position at end of batch
        if (end_of_batch) {
            msg_inbox_.set_app_consumed(current_pos_);
        }
    }

    // TX Methods - available when constructed with MSG_OUTBOX sequencer/buffer
    // See "Sending Messages (TX Path)" section for full documentation
    bool send_message(const char* data, size_t len);      // Send TEXT message
    bool send_message(const std::string& msg);            // Send TEXT message (string)
    bool send_binary(const uint8_t* data, size_t len);    // Send BINARY message
    bool send_close(uint16_t status_code = 1000, const char* reason = nullptr);  // Send CLOSE frame

protected:
    MsgInbox& msg_inbox_;
    WSFrameInfo* current_info_ = nullptr;  // Available in on_message() for latency calc
    uint32_t current_pos_ = 0;
};
```

---

## Example: Binance AppClient

```cpp
// Example concrete AppClient implementation with RX and TX support
class BinanceAppClient : public AppClientHandler<BinanceAppClient> {
public:
    using AppClientHandler::AppClientHandler;

    // Called for fragmented messages (is_fragmented=true)
    // NOTE: For fragmented messages, msg_inbox_offset is NOT usable.
    // Use FragmentAssemblingClient pattern for proper handling (see below).
    void on_fragmented_message(const WSFrameInfo& info) {
        // Default: Log warning and skip fragmented messages
        // Override this or use FragmentAssemblingClient for proper handling
        fprintf(stderr, "[WARN] Fragmented message received (opcode=%u, len=%u). "
                        "Use FragmentAssemblingClient for proper handling.\n",
                info.opcode, info.payload_len);
    }

    // Called for contiguous payloads (common case) - RX
    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        if (opcode == static_cast<uint8_t>(WebSocketOpcode::TEXT)) {
            // Parse JSON, update order book, etc.
            // payload is zero-copy pointer into MSG_INBOX
            process_json(payload, len);
        } else if (opcode == static_cast<uint8_t>(WebSocketOpcode::BINARY)) {
            process_binary(payload, len);
        }
    }

    // Called when payload wraps around MSG_INBOX boundary (rare for small messages)
    // NOTE: For zero-copy, process segments in order. For convenience, copy to temp buffer.
    void on_message_wrapped(const uint8_t* seg1, uint32_t seg1_len,
                            const uint8_t* seg2, uint32_t seg2_len,
                            uint8_t opcode) {
        // Option 1: Copy to temporary buffer (simple but requires allocation)
        std::vector<uint8_t> temp(seg1_len + seg2_len);
        memcpy(temp.data(), seg1, seg1_len);
        memcpy(temp.data() + seg1_len, seg2, seg2_len);
        on_message(temp.data(), temp.size(), opcode);

        // Option 2: Process segments in-place (zero-copy, but more complex)
        // process_json_segment(seg1, seg1_len);
        // process_json_segment(seg2, seg2_len);
    }

    // =========================================================================
    // TX Methods - User-defined methods that use send_message()/send_binary()
    // =========================================================================

    // Send a subscription request to Binance
    bool subscribe(const char* stream) {
        char buf[256];
        int len = snprintf(buf, sizeof(buf),
            R"({"method":"SUBSCRIBE","params":["%s"],"id":%d})",
            stream, ++request_id_);
        return send_message(buf, len);
    }

    // Send an order (example - actual format depends on exchange API)
    bool place_order(const char* symbol, const char* side, double price, double qty) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf),
            R"({"method":"ORDER","symbol":"%s","side":"%s","price":"%.8f","qty":"%.8f","id":%d})",
            symbol, side, price, qty, ++request_id_);
        return send_message(buf, len);
    }

private:
    int request_id_ = 0;

    void process_json(const uint8_t* data, uint32_t len) {
        // Application-specific JSON parsing
        // e.g., simdjson, rapidjson, etc.
        // May trigger order placement via place_order()
    }

    void process_binary(const uint8_t* data, uint32_t len) {
        // Application-specific binary parsing
    }
};
```

---

## Process Entry Point

```cpp
class AppClientProcess {
    MsgInbox& msg_inbox_;

    // TX support: MSG_OUTBOX sequencer and ring buffer
    disruptor::sequencer<>& msg_outbox_sequencer_;
    disruptor::ring_buffer<MsgOutboxEvent>& msg_outbox_buffer_;

    // RX: WS_FRAME_INFO_RING for incoming messages
    disruptor::ring_buffer<WSFrameInfo>& ws_frame_ring_buffer_;
    disruptor::sequence_barrier& sequence_barrier_;

    std::atomic<bool>* running_;

    // Event processor (member for halt() access)
    using ProcessorType = disruptor::event_processor<WSFrameInfo,
        disruptor::policy_bundles::single_producer_lowest_latency>;
    std::unique_ptr<ProcessorType> processor_;

public:
    // AppClient Process entry point - uses event_processor.run()
    void run() {
        using namespace disruptor;

        // Create handler with TX support (sequencer + ring buffer)
        BinanceAppClient handler(msg_inbox_, msg_outbox_sequencer_, msg_outbox_buffer_);

        // Create event processor for WS_FRAME_INFO_RING
        processor_ = std::make_unique<ProcessorType>(
            ws_frame_ring_buffer_,
            sequence_barrier_,
            handler
        );

        // Blocking call - runs until halt() is called
        // Handler can call send_message()/send_binary() during on_message() callbacks
        processor_->run();
    }

    // Shutdown: call from signal handler or other process
    // Uses event_processor.halt() which:
    //   1. Sets running_ = false
    //   2. Sets alerted_ = true
    //   3. Calls barrier_.alert() to wake from wait_for()
    void shutdown() {
        if (processor_) {
            processor_->halt();
        }
    }
};
```

---

## MSG_INBOX Consumption Tracking

AppClient tracks how far it has consumed in MSG_INBOX. This position is used by Transport to know when it's safe to overwrite old data.

**MsgInbox Structure**: See [pipeline_architecture.md Section 3.5](pipeline_architecture.md#35-msginbox-shared-memory-byte-stream-buffer) for the complete `MsgInbox` struct definition with all methods.

**Key methods used by AppClient**:
- `data_at(offset)` - Get pointer to data at offset (read-only)
- `set_app_consumed(pos)` - Update consumption position (called at end of batch)
- `get_app_consumed()` - Read current consumption position

---

## WSFrameInfo Access

Each WSFrameInfo event contains:

| Field | Description |
|-------|-------------|
| `msg_inbox_offset` | Start offset of payload in MSG_INBOX. **CRITICAL: Check `is_fragmented` first!** |
| `payload_len` | Length of payload data |
| `frame_total_len` | Total frame length (header + payload) |
| `opcode` | WebSocket opcode (TEXT=1, BINARY=2, etc.) |
| `is_final` | FIN bit - true if final fragment |
| `is_fragmented` | True if message was fragmented (payloads non-contiguous in MSG_INBOX) |
| `first_byte_ts` | NIC timestamp when first byte arrived |
| `first_nic_frame_poll_cycle` | XDP poll cycle of first packet |
| `first_raw_frame_poll_cycle` | Transport poll cycle of first packet |
| `last_byte_ts` | NIC timestamp when frame completed |
| `latest_nic_frame_poll_cycle` | XDP poll cycle of latest packet |
| `latest_raw_frame_poll_cycle` | Transport poll cycle of latest packet |
| `ssl_read_cycle` | SSL_read completion cycle |
| `ws_parse_cycle` | WebSocket parse completion cycle |

**CRITICAL - Fragmented Message Handling**:
- **Always check `is_fragmented` BEFORE using `msg_inbox_offset`**
- When `is_fragmented == true`, `msg_inbox_offset` is set to **0 as a sentinel value** and is INVALID
- Fragment payloads are scattered throughout MSG_INBOX with WS headers between them
- Use `FragmentAssemblingClient` pattern (see below) to handle fragmented messages
- For HFT: prefer servers that send single-frame messages (no fragmentation)

---

## Latency Calculation

AppClient can calculate end-to-end latency using timestamps from WSFrameInfo. The `current_info_` pointer is set by `on_event()` before calling `on_message()`, making it available for latency calculation:

```cpp
// In your derived handler class
class LatencyAwareClient : public AppClientHandler<LatencyAwareClient> {
public:
    using AppClientHandler::AppClientHandler;

    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        uint64_t app_recv_cycle = rdtscp();

        // Access timestamps via current_info_ (set by on_event before calling on_message)
        // End-to-end latency from NIC to AppClient (in cycles)
        uint64_t total_cycles = app_recv_cycle - current_info_->first_nic_frame_poll_cycle;

        // Convert to nanoseconds using pre-calibrated TSC frequency
        double latency_ns = (double)total_cycles / tsc_freq_ghz_;

        // Stage-by-stage latency breakdown:
        // 1. NIC → XDP Poll: first_nic_frame_poll_cycle - (derived from nic_timestamp)
        // 2. XDP → Transport: first_raw_frame_poll_cycle - first_nic_frame_poll_cycle
        // 3. Transport (SSL): ssl_read_cycle - latest_raw_frame_poll_cycle
        // 4. WebSocket parse: ws_parse_cycle - ssl_read_cycle
        // 5. WS → AppClient: app_recv_cycle - ws_parse_cycle

        // ... process payload
    }

    void on_message_wrapped(...) { /* ... */ }
    void on_fragmented_message(const WSFrameInfo& info) { /* ... */ }

private:
    double tsc_freq_ghz_ = 3.0;  // Pre-calibrate this
};
```

**Note**: The `current_info_` pointer is only valid during the `on_message()` / `on_message_wrapped()` callback. Do not store it for later use.

### Latency Helper Class

For convenient latency measurement, use the `LatencyHelper` utility class:

```cpp
// Latency calculation helper - converts TSC cycles to nanoseconds
// and provides stage-by-stage breakdown
class LatencyHelper {
public:
    // Construct with pre-calibrated TSC frequency in GHz
    // Typical values: 2.0-4.0 GHz depending on CPU
    // Calibrate once at startup using core/timing.hpp calibrate_tsc()
    explicit LatencyHelper(double tsc_freq_ghz) : tsc_freq_ghz_(tsc_freq_ghz) {}

    // Convert TSC cycles to nanoseconds
    double cycles_to_ns(uint64_t cycles) const {
        return static_cast<double>(cycles) / tsc_freq_ghz_;
    }

    // Convert TSC cycles to microseconds
    double cycles_to_us(uint64_t cycles) const {
        return cycles_to_ns(cycles) / 1000.0;
    }

    // =========================================================================
    // End-to-End Latency
    // =========================================================================

    // Total latency from NIC hardware timestamp to AppClient receipt
    // This is the most accurate end-to-end measurement
    double total_latency_ns(uint64_t app_recv_cycle, const WSFrameInfo& info) const {
        return cycles_to_ns(app_recv_cycle - info.first_nic_frame_poll_cycle);
    }

    // =========================================================================
    // Stage-by-Stage Breakdown
    // =========================================================================

    // Stage 1: NIC → XDP Poll (hardware to first software touch)
    // Note: first_nic_timestamp_ns is in nanoseconds (from NIC hardware)
    //       first_nic_frame_poll_cycle is in TSC cycles (from rdtscp)
    // This stage requires NIC-to-TSC correlation, which is complex.
    // For simplicity, we measure from XDP poll cycle.

    // Stage 2: XDP Poll → Transport (RAW_INBOX transit)
    double xdp_to_transport_ns(const WSFrameInfo& info) const {
        return cycles_to_ns(info.first_raw_frame_poll_cycle - info.first_nic_frame_poll_cycle);
    }

    // Stage 3: Transport RX processing (TCP parse + SSL decrypt)
    // Uses latest_raw_frame_poll_cycle because SSL_read may span multiple packets
    double transport_processing_ns(const WSFrameInfo& info) const {
        return cycles_to_ns(info.ssl_read_cycle - info.latest_raw_frame_poll_cycle);
    }

    // Stage 4: WebSocket frame parsing
    double ws_parse_ns(const WSFrameInfo& info) const {
        return cycles_to_ns(info.ws_parse_cycle - info.ssl_read_cycle);
    }

    // Stage 5: WebSocket → AppClient (WS_FRAME_INFO_RING transit + dispatch)
    double ws_to_app_ns(uint64_t app_recv_cycle, const WSFrameInfo& info) const {
        return cycles_to_ns(app_recv_cycle - info.ws_parse_cycle);
    }

    // =========================================================================
    // Convenience: Full Breakdown Struct
    // =========================================================================

    struct LatencyBreakdown {
        double total_ns;              // End-to-end
        double xdp_to_transport_ns;   // Stage 2
        double transport_ns;          // Stage 3 (TCP + SSL)
        double ws_parse_ns;           // Stage 4
        double ws_to_app_ns;          // Stage 5
    };

    LatencyBreakdown breakdown(uint64_t app_recv_cycle, const WSFrameInfo& info) const {
        return {
            .total_ns = total_latency_ns(app_recv_cycle, info),
            .xdp_to_transport_ns = xdp_to_transport_ns(info),
            .transport_ns = transport_processing_ns(info),
            .ws_parse_ns = ws_parse_ns(info),
            .ws_to_app_ns = ws_to_app_ns(app_recv_cycle, info)
        };
    }

    // Print breakdown to stderr (for debugging)
    void print_breakdown(uint64_t app_recv_cycle, const WSFrameInfo& info) const {
        auto b = breakdown(app_recv_cycle, info);
        fprintf(stderr, "Latency Breakdown:\n"
                "  Total:         %.2f ns (%.2f us)\n"
                "  XDP→Transport: %.2f ns\n"
                "  Transport:     %.2f ns (TCP+SSL)\n"
                "  WS Parse:      %.2f ns\n"
                "  WS→App:        %.2f ns\n",
                b.total_ns, b.total_ns / 1000.0,
                b.xdp_to_transport_ns,
                b.transport_ns,
                b.ws_parse_ns,
                b.ws_to_app_ns);
    }

private:
    double tsc_freq_ghz_;
};
```

**Usage Example**:

```cpp
class InstrumentedClient : public AppClientHandler<InstrumentedClient> {
public:
    InstrumentedClient(MsgInbox& inbox, /* ... */, double tsc_freq_ghz)
        : AppClientHandler(inbox, /* ... */),
          latency_(tsc_freq_ghz) {}

    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        uint64_t app_recv_cycle = rdtscp();

        // Quick total latency check
        double latency_us = latency_.cycles_to_us(
            app_recv_cycle - current_info_->first_nic_frame_poll_cycle);

        if (latency_us > 100.0) {  // Alert if > 100us
            fprintf(stderr, "[WARN] High latency: %.2f us\n", latency_us);
            latency_.print_breakdown(app_recv_cycle, *current_info_);
        }

        // Update statistics
        latency_sum_ns_ += latency_.total_latency_ns(app_recv_cycle, *current_info_);
        latency_count_++;

        // ... process message
    }

    void on_message_wrapped(/* ... */) { /* ... */ }
    void on_fragmented_message(const WSFrameInfo& info) { /* ... */ }

    double avg_latency_ns() const {
        return latency_count_ > 0 ? latency_sum_ns_ / latency_count_ : 0.0;
    }

private:
    LatencyHelper latency_;
    double latency_sum_ns_ = 0.0;
    uint64_t latency_count_ = 0;
};
```

**TSC Frequency Calibration**: The TSC frequency must be calibrated at startup. Use `calibrate_tsc()` from `core/timing.hpp`:

```cpp
#include <core/timing.hpp>

int main() {
    // Calibrate TSC frequency (takes ~10ms)
    double tsc_freq_ghz = calibrate_tsc_ghz();
    printf("TSC frequency: %.3f GHz\n", tsc_freq_ghz);

    // Pass to client
    InstrumentedClient client(msg_inbox, /* ... */, tsc_freq_ghz);
    // ...
}
```

---

## Sending Messages (TX Path)

AppClient can send WebSocket messages to the server via the MSG_OUTBOX ring buffer. The `AppClientHandler` template provides `send_message()` and `send_binary()` methods for this purpose.

### TX Data Flow

```
AppClient                    MSG_OUTBOX                     Transport
    │                            │                              │
    │── send_message() ────────►│────── process_manually() ───►│
    │   (TEXT opcode)            │                              │
    │                            │                              │
    │── send_binary() ─────────►│      SSL_write() + TCP       │
    │   (BINARY opcode)          │            │                 │
    │                            │            ▼                 │
    │                            │       RAW_OUTBOX ───────────►│ XDP Poll
    │                            │                              │     │
    │                            │                              │     ▼
    │                            │                              │   NIC TX
```

### Handler Template with TX Support

```cpp
// Event Handler for WS_FRAME_INFO events (CRTP pattern for user customization)
// Extended with send_message() and send_binary() for TX path
//
// TX uses the standard disruptor pattern:
//   - sequencer.try_claim() to get a slot
//   - ring_buffer[seq] to access the slot
//   - sequencer.publish(seq) to make it visible to Transport
//
template<typename Derived>
class AppClientHandler : public disruptor::event_handler<WSFrameInfo> {
public:
    // Constructor with MSG_OUTBOX for TX support
    // msg_outbox_sequencer: disruptor sequencer for MSG_OUTBOX ring
    // msg_outbox_buffer: ring buffer containing MsgOutboxEvent elements
    AppClientHandler(MsgInbox& msg_inbox,
                     disruptor::sequencer<>& msg_outbox_sequencer,
                     disruptor::ring_buffer<MsgOutboxEvent>& msg_outbox_buffer)
        : msg_inbox_(msg_inbox),
          msg_outbox_sequencer_(&msg_outbox_sequencer),
          msg_outbox_buffer_(&msg_outbox_buffer) {}

    // Legacy constructor (RX-only, no TX support)
    AppClientHandler(MsgInbox& msg_inbox)
        : msg_inbox_(msg_inbox),
          msg_outbox_sequencer_(nullptr),
          msg_outbox_buffer_(nullptr) {}

    // =========================================================================
    // TX Methods - Send WebSocket messages to server
    // =========================================================================

    // Send a TEXT message (opcode 0x01)
    // Returns true if message was queued successfully, false if MSG_OUTBOX is full
    //
    // DESIGN DECISION: Returns false on full instead of aborting
    // Unlike internal pipeline rings (which abort on full), MSG_OUTBOX allows
    // user code to handle backpressure gracefully. This is because:
    //   1. User code can decide whether to drop, retry, or buffer the message
    //   2. HFT applications may have different backpressure strategies
    //   3. Aborting on user-initiated send is too aggressive
    //
    // NOTE: Maximum message size is 2030 bytes (MsgOutboxEvent::data capacity)
    // Messages larger than 2030 bytes will be truncated with a warning.
    //
    bool send_message(const char* data, size_t len) {
        return send_impl(reinterpret_cast<const uint8_t*>(data), len,
                         static_cast<uint8_t>(WebSocketOpcode::TEXT));
    }

    bool send_message(const uint8_t* data, size_t len) {
        return send_impl(data, len, static_cast<uint8_t>(WebSocketOpcode::TEXT));
    }

    // Convenience overload for std::string
    bool send_message(const std::string& msg) {
        return send_message(msg.data(), msg.size());
    }

    // Send a BINARY message (opcode 0x02)
    // Returns true if message was queued successfully, false if MSG_OUTBOX is full
    //
    // Same backpressure semantics as send_message() - see notes above.
    //
    bool send_binary(const uint8_t* data, size_t len) {
        return send_impl(data, len, static_cast<uint8_t>(WebSocketOpcode::BINARY));
    }

    bool send_binary(const void* data, size_t len) {
        return send_impl(reinterpret_cast<const uint8_t*>(data), len,
                         static_cast<uint8_t>(WebSocketOpcode::BINARY));
    }

    // Send a WebSocket CLOSE frame (opcode 0x08)
    // status_code: WebSocket close status code (e.g., 1000 for normal closure)
    // reason: Optional reason string (max ~123 bytes to fit in 125-byte close payload)
    //
    // Returns true if close frame was queued successfully.
    // After sending CLOSE, you should stop sending data and wait for server's CLOSE response.
    //
    bool send_close(uint16_t status_code = 1000, const char* reason = nullptr) {
        if (!msg_outbox_sequencer_ || !msg_outbox_buffer_) {
            return false;
        }

        int64_t seq = msg_outbox_sequencer_->try_claim();
        if (seq < 0) {
            return false;
        }

        MsgOutboxEvent& event = (*msg_outbox_buffer_)[seq];

        // Close frame payload: 2-byte status code (big-endian) + optional reason
        event.data[0] = static_cast<uint8_t>(status_code >> 8);
        event.data[1] = static_cast<uint8_t>(status_code & 0xFF);

        size_t reason_len = 0;
        if (reason) {
            reason_len = strlen(reason);
            if (reason_len > 123) reason_len = 123;  // Max close payload is 125 bytes
            memcpy(event.data + 2, reason, reason_len);
        }

        event.data_len = static_cast<uint16_t>(2 + reason_len);
        event.opcode = static_cast<uint8_t>(WebSocketOpcode::CLOSE);
        event.msg_type = MSG_TYPE_WS_CLOSE;

        msg_outbox_sequencer_->publish(seq);
        return true;
    }

    // =========================================================================
    // RX Handler (on_event from base class)
    // =========================================================================

    void on_event(WSFrameInfo& info, int64_t sequence, bool end_of_batch) override {
        // ... (existing on_event implementation unchanged)
        current_info_ = &info;

        if (info.is_fragmented) {
            static_cast<Derived*>(this)->on_fragmented_message(info);
            return;
        }

        uint32_t end_offset = (info.msg_inbox_offset + info.payload_len) % MSG_INBOX_SIZE;
        bool payload_wraps = (end_offset < info.msg_inbox_offset) && (info.payload_len > 0);

        if (payload_wraps) {
            const uint8_t* seg1 = msg_inbox_.data_at(info.msg_inbox_offset);
            uint32_t seg1_len = MSG_INBOX_SIZE - info.msg_inbox_offset;
            const uint8_t* seg2 = msg_inbox_.data_at(0);
            uint32_t seg2_len = end_offset;
            static_cast<Derived*>(this)->on_message_wrapped(
                seg1, seg1_len, seg2, seg2_len, info.opcode);
        } else {
            const uint8_t* payload = msg_inbox_.data_at(info.msg_inbox_offset);
            static_cast<Derived*>(this)->on_message(payload, info.payload_len, info.opcode);
        }

        uint32_t header_len = info.frame_total_len - info.payload_len;
        uint32_t frame_start = (info.msg_inbox_offset - header_len + MSG_INBOX_SIZE) % MSG_INBOX_SIZE;
        current_pos_ = (frame_start + info.frame_total_len) % MSG_INBOX_SIZE;

        if (end_of_batch) {
            msg_inbox_.set_app_consumed(current_pos_);
        }
    }

protected:
    MsgInbox& msg_inbox_;
    disruptor::sequencer<>* msg_outbox_sequencer_ = nullptr;
    disruptor::ring_buffer<MsgOutboxEvent>* msg_outbox_buffer_ = nullptr;
    WSFrameInfo* current_info_ = nullptr;
    uint32_t current_pos_ = 0;

private:
    // Internal send implementation
    // NOTE: Transport handles WebSocket masking (RFC 6455 requirement for client-to-server).
    // AppClient just writes unmasked payload; Transport builds the masked WS frame.
    bool send_impl(const uint8_t* data, size_t len, uint8_t opcode) {
        if (!msg_outbox_sequencer_ || !msg_outbox_buffer_) {
            // TX not configured - legacy RX-only mode
            return false;
        }

        // Claim slot in MSG_OUTBOX (non-blocking)
        int64_t seq = msg_outbox_sequencer_->try_claim();
        if (seq < 0) {
            // MSG_OUTBOX full - backpressure
            return false;
        }

        MsgOutboxEvent& event = (*msg_outbox_buffer_)[seq];

        // Truncate if too large (with warning in debug builds)
        constexpr size_t MAX_PAYLOAD = sizeof(event.data);  // 2030 bytes
        if (len > MAX_PAYLOAD) {
#ifdef PIPELINE_DEBUG
            fprintf(stderr, "[WARN] send_message: truncating %zu bytes to %zu\n",
                    len, MAX_PAYLOAD);
#endif
            len = MAX_PAYLOAD;
        }

        // Copy payload to event.data (unmasked - Transport applies masking)
        memcpy(event.data, data, len);
        event.data_len = static_cast<uint16_t>(len);
        event.opcode = opcode;
        event.msg_type = MSG_TYPE_DATA;

        // Publish to MSG_OUTBOX - Transport will see this event
        msg_outbox_sequencer_->publish(seq);
        return true;
    }
};
```

### Example: Bidirectional Communication

```cpp
class TradingClient : public AppClientHandler<TradingClient> {
public:
    using AppClientHandler::AppClientHandler;

    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        // IMPORTANT: Retry pending orders at the START of each message callback.
        // Since event_processor.run() is blocking, this is the only opportunity
        // to retry without adding a separate timer thread.
        retry_pending_orders();

        // Process incoming market data
        if (opcode == static_cast<uint8_t>(WebSocketOpcode::TEXT)) {
            process_market_data(payload, len);
        }
    }

    void on_message_wrapped(const uint8_t* seg1, uint32_t seg1_len,
                            const uint8_t* seg2, uint32_t seg2_len,
                            uint8_t opcode) {
        // Handle wrapped payload
        std::vector<uint8_t> temp(seg1_len + seg2_len);
        memcpy(temp.data(), seg1, seg1_len);
        memcpy(temp.data() + seg1_len, seg2, seg2_len);
        on_message(temp.data(), temp.size(), opcode);
    }

    void on_fragmented_message(const WSFrameInfo& info) {
        fprintf(stderr, "[WARN] Fragmented message skipped\n");
    }

    // User-initiated send (e.g., from trading logic within on_message)
    void place_order(const char* order_json) {
        if (!send_message(order_json, strlen(order_json))) {
            // Handle backpressure - MSG_OUTBOX full
            fprintf(stderr, "[WARN] MSG_OUTBOX full, order queued locally\n");
            pending_orders_.push_back(order_json);
        }
    }

private:
    // Retry pending orders - called at start of each on_message()
    // This piggybacks on the message processing loop since event_processor.run()
    // is blocking and doesn't provide an idle callback.
    //
    // DESIGN NOTE: For HFT, pending_orders_ should rarely be non-empty because:
    //   1. MSG_OUTBOX should be sized for peak throughput
    //   2. If MSG_OUTBOX is frequently full, the system is misconfigured
    //   3. This retry mechanism is a safety net, not a primary flow control
    //
    // If you need guaranteed delivery with complex retry logic, consider:
    //   - Using a separate thread with a lock-free queue
    //   - Implementing exponential backoff
    //   - Logging dropped messages for post-trade reconciliation
    //
    void retry_pending_orders() {
        while (!pending_orders_.empty()) {
            const auto& order = pending_orders_.front();
            if (send_message(order.c_str(), order.size())) {
                pending_orders_.pop_front();
            } else {
                break;  // Still full, try again on next message
            }
        }
    }

    void process_market_data(const uint8_t* data, uint32_t len) {
        // Parse JSON, update order book, make trading decisions...
        // May call place_order() based on trading signals
    }

    std::deque<std::string> pending_orders_;
};
```

**Note on Retry Strategy**: Since `event_processor.run()` is a blocking call, there's no separate "main loop" where you can periodically retry. The pattern above calls `retry_pending_orders()` at the start of each `on_message()` callback, which ensures retries happen as new messages arrive. For low-traffic scenarios where messages are infrequent, consider using a separate thread with a lock-free queue for pending orders.

### TX Configuration

When creating the AppClient handler, pass the MSG_OUTBOX sequencer and ring buffer to enable TX:

```cpp
// In AppClientProcess setup
void run() {
    // Create handler with TX support (sequencer + ring buffer)
    TradingClient handler(msg_inbox_, msg_outbox_sequencer_, msg_outbox_buffer_);

    // ... rest of event processor setup
}
```

**Note on WebSocket Masking**: Per RFC 6455, all client-to-server WebSocket frames MUST be masked. AppClient writes unmasked payload to MSG_OUTBOX; **Transport** applies masking when building the WebSocket frame header via `build_websocket_header_zerocopy()`. This keeps AppClient simple and avoids masking overhead in the hot path.

### TX Error Handling

| Condition | Behavior |
|-----------|----------|
| MSG_OUTBOX full | `send_message()`/`send_binary()` returns `false` |
| TX not configured | Returns `false` (legacy RX-only mode) |
| Message > 2030 bytes | Truncated to 2030 bytes (warning in debug builds) |

### TX Performance Considerations

1. **Single copy**: Payload is copied once into MsgOutboxEvent (unavoidable for disruptor pattern)
2. **Non-blocking**: `try_claim()` never blocks - returns immediately if full
3. **Batching**: Transport processes MSG_OUTBOX in batches for efficiency
4. **Memory layout**: MsgOutboxEvent is 2KB aligned for cache efficiency

### TX Thread Safety

**Single-threaded**: `send_message()`, `send_binary()`, and `send_close()` are designed for single-threaded use within `event_processor.run()`. The AppClient process runs on a dedicated CPU core with no other threads calling these methods.

**Not thread-safe for external calls**: If you need to send messages from outside the `on_message()` callback (e.g., from a timer thread or signal handler), you must implement your own synchronization or use a separate queue to feed messages to the AppClient thread.

---

## Ring Buffer Interactions

| Ring | Role | API |
|------|------|-----|
| WS_FRAME_INFO_RING | Consumer | `event_processor.run()` with `on_event()` handler |
| MSG_INBOX | Reader | `data_at(offset)` - read-only access to payload |
| MSG_OUTBOX | Producer | `send_message()`, `send_binary()`, `send_close()` - write outbound messages |

---

## Critical Error Handling

**RX Errors**:
| Condition | Action |
|-----------|--------|
| Invalid offset | Should never happen - indicates bug |
| Handler throws | Propagates up, terminates process |

**TX Errors**:
| Condition | Action |
|-----------|--------|
| MSG_OUTBOX full | `send_message()`/`send_binary()` returns `false` - user handles backpressure |
| TX not configured | Returns `false` (RX-only mode, no MSG_OUTBOX producer passed) |
| Message > 2030 bytes | Truncated to 2030 bytes (warning in debug builds) |

---

## Performance Considerations

**RX Path**:
1. **Auto-consumer**: Uses `event_processor.run()` - no manual polling
2. **Zero-copy payload**: `data_at()` returns pointer into MSG_INBOX, no copying
3. **Batch consumption**: Only updates `app_consumed_pos` at end of batch
4. **CRTP dispatch**: Compile-time polymorphism, no virtual call overhead
5. **Cache-friendly**: 128-byte aligned WSFrameInfo fits cache line

**TX Path**:
1. **Single copy**: Payload copied once into MsgOutboxEvent (unavoidable for disruptor)
2. **Non-blocking**: `try_claim()` never blocks - returns immediately if full
3. **Batching**: Transport processes MSG_OUTBOX in batches for efficiency
4. **Memory layout**: MsgOutboxEvent is 2KB aligned for cache efficiency
5. **No syscalls**: send_message() just writes to shared memory, no kernel involvement

---

## MSG_INBOX Flow Control

The MSG_INBOX is a circular buffer. Transport writes decrypted data, AppClient reads it.

**Design Decision - No Backpressure on MSG_INBOX**:
- AppClient process is **OPTIONAL** - user decides whether to use it
- Transport does NOT wait for `app_consumed_pos` - it continues writing
- If Transport's `write_pos` passes `app_consumed_pos`, `dirty_flag` is set
- `dirty_flag` is for metrics/debugging only, not flow control
- This allows the pipeline to run without AppClient, or with a slow AppClient

```
Transport                    MSG_INBOX                      AppClient
    │                            │                              │
    │──── write_ptr_ ──────────►│◄──── app_consumed_pos ───────│
    │                            │                              │
    │  If write_ptr_ passes      │  AppClient updates           │
    │  app_consumed_pos:         │  app_consumed_pos after      │
    │    → Set dirty_flag        │  processing each batch       │
    │    → Continue writing      │                              │
```

**For users who need AppClient**:
- Ensure AppClient keeps up with Transport (size buffers appropriately)
- Check `dirty_flag` periodically to detect if data was lost
- If `dirty_flag` is set, some messages may have been overwritten

---

## Data Flow

```
                              RX PATH (Server → AppClient)
                              ════════════════════════════
WS_FRAME_INFO_RING ──event_processor.run()──► on_event()
                                                   │
MSG_INBOX ◄──────────data_at(offset)───────────────┤
                                                   │
                                                   ▼
                                          on_message() callback
                                                   │
                                                   ▼
                                          User application code
                                          (JSON parsing, order book, etc.)
                                                   │
                                                   ▼
                                          set_app_consumed()
                                                   │
                                                   ▼
                                          Transport sees space freed


                              TX PATH (AppClient → Server)
                              ════════════════════════════
                                          User application code
                                          (trading logic, orders, etc.)
                                                   │
                                                   ▼
                                      send_message() / send_binary()
                                                   │
                                                   ▼
                                            MSG_OUTBOX
                                                   │
                                                   ▼
                                   Transport: process_manually()
                                   SSL_write() → TCP packet
                                                   │
                                                   ▼
                                             RAW_OUTBOX
                                                   │
                                                   ▼
                                   XDP Poll: submit to tx_ring
                                                   │
                                                   ▼
                                              NIC → Server
```

---

## Fragmented Messages

WebSocket fragmentation (RFC 6455) splits a single logical message across multiple frames. The WebSocket process accumulates fragments and publishes a single `WSFrameInfo` with `is_fragmented=true` when complete.

**IMPORTANT**: For fragmented messages, `msg_inbox_offset` is NOT usable because fragment payloads are scattered throughout MSG_INBOX with WS headers between them. The `FragmentAssemblingClient` pattern below handles this by receiving fragment data during WebSocket parsing (not post-hoc from MSG_INBOX).

### Option 1: Ignore Fragmented Messages (Simple)

For HFT applications where servers send single-frame messages:

```cpp
class SimpleAppClient : public AppClientHandler<SimpleAppClient> {
public:
    using AppClientHandler::AppClientHandler;

    void on_fragmented_message(const WSFrameInfo& info) {
        // Log and skip - fragmented messages not supported
        fprintf(stderr, "[WARN] Fragmented message skipped (len=%u)\n", info.payload_len);
    }

    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        process_json(payload, len);
    }

    void on_message_wrapped(const uint8_t* seg1, uint32_t seg1_len,
                            const uint8_t* seg2, uint32_t seg2_len, uint8_t opcode) {
        // Handle wrapped payload
    }
};
```

### Option 2: WebSocket-Level Fragment Assembly

To properly handle fragmented messages, fragment assembly must happen at the **WebSocket process level**, not AppClient. This requires modifying the WebSocket process to:

1. Accumulate fragment payloads into a dedicated buffer as each fragment arrives
2. Publish a single `WSFrameInfo` with the assembled payload location

This is NOT currently implemented. If fragmented message support is needed:

```cpp
// In WebSocketProcess - accumulate fragments into separate buffer
class WebSocketProcess {
    // Fragment assembly buffer (separate from MSG_INBOX)
    alignas(64) uint8_t fragment_buffer_[MAX_FRAGMENT_MSG_SIZE];
    uint32_t fragment_buffer_len_ = 0;

    void handle_complete_frame(...) {
        if (frame.opcode == TEXT || frame.opcode == BINARY) {
            if (!frame.fin) {
                // First fragment - copy to fragment buffer
                memcpy(fragment_buffer_, frame.payload, frame.payload_len);
                fragment_buffer_len_ = frame.payload_len;
                // ... save timestamps
                return;
            }
            // Complete single-frame message - publish as normal
        } else if (frame.opcode == 0x00) {  // CONTINUATION
            // Append to fragment buffer
            memcpy(fragment_buffer_ + fragment_buffer_len_,
                   frame.payload, frame.payload_len);
            fragment_buffer_len_ += frame.payload_len;

            if (frame.fin) {
                // Publish with fragment_buffer_ location
                // AppClient reads from this buffer, not MSG_INBOX
            }
        }
    }
};
```

**Trade-off**: Fragment assembly requires memory copy (not zero-copy). For HFT, prefer servers that send single-frame messages.

Note: The current implementation publishes fragmented messages with `is_fragmented=true` and `msg_inbox_offset=0` to signal that direct MSG_INBOX access is not possible. AppClient's `on_fragmented_message()` receives metadata only.
