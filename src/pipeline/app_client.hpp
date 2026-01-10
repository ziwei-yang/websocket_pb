// pipeline/app_client.hpp
// AppClient Handler - User-facing CRTP template for message handling
// Zero-copy message access with full timestamp chain
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// LatencyHelper - Convert TSC cycles to nanoseconds and calculate breakdown
// ============================================================================

struct LatencyHelper {
    uint64_t tsc_freq_hz;

    explicit LatencyHelper(uint64_t freq = 0) : tsc_freq_hz(freq) {}

    // Convert cycles to nanoseconds
    uint64_t cycles_to_ns(uint64_t cycles) const {
        if (tsc_freq_hz == 0) return 0;
        return (cycles * 1000000000ULL) / tsc_freq_hz;
    }

    // Calculate latency breakdown from WSFrameInfo
    struct Breakdown {
        uint64_t nic_to_poll_ns;      // NIC timestamp to XDP Poll
        uint64_t poll_to_ssl_ns;      // XDP Poll to SSL_read
        uint64_t ssl_to_ws_ns;        // SSL_read to WS parse
        uint64_t ws_to_callback_ns;   // WS parse to user callback
        uint64_t total_ns;            // Total NIC to callback
    };

    Breakdown calculate(const WSFrameInfo& info, uint64_t callback_cycle) const {
        Breakdown b = {};

        if (tsc_freq_hz == 0) return b;

        // NIC to poll (use NIC timestamps in ns, poll cycles)
        // This requires knowing the relationship between NIC clock and TSC
        // For simplicity, we use the poll cycle as the reference point
        b.nic_to_poll_ns = 0;  // Would need NIC-to-system clock correlation

        // Poll to SSL (both in TSC)
        if (info.ssl_read_cycle > info.first_raw_frame_poll_cycle) {
            b.poll_to_ssl_ns = cycles_to_ns(info.ssl_read_cycle - info.first_raw_frame_poll_cycle);
        }

        // SSL to WS parse
        if (info.ws_parse_cycle > info.ssl_read_cycle) {
            b.ssl_to_ws_ns = cycles_to_ns(info.ws_parse_cycle - info.ssl_read_cycle);
        }

        // WS parse to callback
        if (callback_cycle > info.ws_parse_cycle) {
            b.ws_to_callback_ns = cycles_to_ns(callback_cycle - info.ws_parse_cycle);
        }

        // Total from poll to callback
        if (callback_cycle > info.first_raw_frame_poll_cycle) {
            b.total_ns = cycles_to_ns(callback_cycle - info.first_raw_frame_poll_cycle);
        }

        return b;
    }

    void print_breakdown(const Breakdown& b) const {
        printf("Latency breakdown:\n");
        printf("  Poll → SSL:      %lu ns\n", b.poll_to_ssl_ns);
        printf("  SSL → WS:        %lu ns\n", b.ssl_to_ws_ns);
        printf("  WS → Callback:   %lu ns\n", b.ws_to_callback_ns);
        printf("  Total:           %lu ns (%.2f µs)\n", b.total_ns, b.total_ns / 1000.0);
    }
};

// ============================================================================
// AppClientHandler - CRTP base class for user message handlers
//
// Usage:
//   class MyHandler : public AppClientHandler<MyHandler> {
//       void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
//           // Process message
//       }
//       void on_message_wrapped(const uint8_t* seg1, uint32_t len1,
//                               const uint8_t* seg2, uint32_t len2, uint8_t opcode) {
//           // Handle wrapped message
//       }
//       void on_fragmented_message(const WSFrameInfo& info) {
//           // Handle fragmented message (or skip)
//       }
//   };
//
// Callbacks:
// - on_message(): Contiguous payload in MSG_INBOX (common case)
// - on_message_wrapped(): Payload wraps around MSG_INBOX boundary (rare)
// - on_fragmented_message(): Fragmented WS message (payload not contiguous)
//
// TX Methods (inherited):
// - send_message(): Send TEXT message
// - send_binary(): Send BINARY message
// - send_close(): Send CLOSE frame
// ============================================================================

// Template parameters:
// - Derived: CRTP derived class
// - WSFrameInfoCons: Consumer type for WSFrameInfo (e.g., IPCRingConsumer<WSFrameInfo>)
// - MsgOutboxProd: Producer type for MsgOutboxEvent (e.g., IPCRingProducer<MsgOutboxEvent>)
template<typename Derived,
         typename WSFrameInfoCons,   // IPCRingConsumer<WSFrameInfo>
         typename MsgOutboxProd>     // IPCRingProducer<MsgOutboxEvent>
struct AppClientHandler {
    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(MsgInbox* msg_inbox,
              WSFrameInfoCons* ws_frame_info_cons,
              MsgOutboxProd* msg_outbox_prod,
              TCPStateShm* tcp_state) {

        msg_inbox_ = msg_inbox;
        ws_frame_info_cons_ = ws_frame_info_cons;
        msg_outbox_prod_ = msg_outbox_prod;
        tcp_state_ = tcp_state;

        latency_helper_ = LatencyHelper(tcp_state->tsc_freq_hz);
        current_pos_ = 0;

        printf("[APP-CLIENT] Initialized\n");
        return true;
    }

    // ========================================================================
    // disruptor::event_processor Handler Interface
    // Called by event_processor.run() when events are available
    // ========================================================================

    void on_event(WSFrameInfo& event, int64_t sequence, bool end_of_batch) {
        (void)sequence;  // Not used, but required by handler interface
        process_frame(event, end_of_batch);
    }

    // ========================================================================
    // Frame Processing
    // ========================================================================

    void process_frame(WSFrameInfo& info, bool end_of_batch) {
        current_info_ = &info;
        uint64_t callback_cycle = rdtsc();

        // Handle fragmented messages
        if (info.is_fragmented) {
            static_cast<Derived*>(this)->on_fragmented_message(info);

            // Advance consumption position conservatively
            current_pos_ = (current_pos_ + info.frame_total_len) % MSG_INBOX_SIZE;

            if (end_of_batch) {
                msg_inbox_->set_app_consumed(current_pos_);
            }
            return;
        }

        // Check if payload wraps around MSG_INBOX boundary
        uint32_t end_offset = (info.msg_inbox_offset + info.payload_len) % MSG_INBOX_SIZE;
        bool payload_wraps = (end_offset < info.msg_inbox_offset) && (info.payload_len > 0);

        if (payload_wraps) {
            // Wrapped payload - call on_message_wrapped
            const uint8_t* seg1;
            uint32_t seg1_len;
            const uint8_t* seg2;
            uint32_t seg2_len;

            msg_inbox_->get_wrapped_segments(info.msg_inbox_offset, info.payload_len,
                                             seg1, seg1_len, seg2, seg2_len);

            static_cast<Derived*>(this)->on_message_wrapped(seg1, seg1_len, seg2, seg2_len,
                                                            info.opcode);
        } else {
            // Contiguous payload - call on_message
            const uint8_t* payload = msg_inbox_->data_at(info.msg_inbox_offset);
            static_cast<Derived*>(this)->on_message(payload, info.payload_len, info.opcode);
        }

        // Update consumption position
        current_pos_ = end_offset;

        if (end_of_batch) {
            msg_inbox_->set_app_consumed(current_pos_);
        }

        current_info_ = nullptr;
    }

    // ========================================================================
    // TX Methods
    // ========================================================================

    // Send TEXT message
    bool send_message(const char* data, size_t len) {
        MsgOutboxEvent event;
        event.clear();

        if (!event.set_text(data, len)) {
            return false;  // Too long
        }

        return msg_outbox_prod_->try_publish(event);
    }

    bool send_message(const std::string& msg) {
        return send_message(msg.data(), msg.size());
    }

    // Send BINARY message
    bool send_binary(const uint8_t* data, size_t len) {
        MsgOutboxEvent event;
        event.clear();

        if (!event.set_binary(data, len)) {
            return false;  // Too long
        }

        return msg_outbox_prod_->try_publish(event);
    }

    // Send CLOSE frame
    bool send_close(uint16_t status_code = 1000, const char* reason = nullptr) {
        MsgOutboxEvent event;
        event.clear();

        size_t reason_len = reason ? strlen(reason) : 0;
        event.set_close(status_code, reason, reason_len);

        return msg_outbox_prod_->try_publish(event);
    }

    // ========================================================================
    // Latency Helpers
    // ========================================================================

    // Get current frame info (valid during on_message callback)
    const WSFrameInfo* current_frame_info() const {
        return current_info_;
    }

    // Calculate latency breakdown for current frame
    LatencyHelper::Breakdown calculate_latency() const {
        if (!current_info_) {
            return LatencyHelper::Breakdown{};
        }
        return latency_helper_.calculate(*current_info_, rdtsc());
    }

    // Print latency breakdown
    void print_latency() const {
        auto b = calculate_latency();
        latency_helper_.print_breakdown(b);
    }

    // Get latency helper for custom calculations
    const LatencyHelper& latency_helper() const {
        return latency_helper_;
    }

protected:
    // State
    MsgInbox* msg_inbox_ = nullptr;
    WSFrameInfoCons* ws_frame_info_cons_ = nullptr;
    MsgOutboxProd* msg_outbox_prod_ = nullptr;
    TCPStateShm* tcp_state_ = nullptr;

    // Current frame (valid during callback)
    const WSFrameInfo* current_info_ = nullptr;

    // Consumption tracking
    uint32_t current_pos_ = 0;

    // Latency calculation helper
    LatencyHelper latency_helper_;
};

// ============================================================================
// Default Handler Implementation (for reference/testing)
// ============================================================================

template<typename RingProducer, typename RingConsumer>
struct DefaultAppHandler : public AppClientHandler<DefaultAppHandler<RingProducer, RingConsumer>,
                                                    RingProducer, RingConsumer> {
    using Base = AppClientHandler<DefaultAppHandler, RingProducer, RingConsumer>;

    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        // Default: print message info
        printf("[MSG] opcode=%u len=%u\n", opcode, len);
        if (opcode == WS_OP_TEXT && len < 200) {
            printf("  %.200s\n", reinterpret_cast<const char*>(payload));
        }
    }

    void on_message_wrapped(const uint8_t* seg1, uint32_t len1,
                            const uint8_t* seg2, uint32_t len2, uint8_t opcode) {
        printf("[MSG-WRAPPED] opcode=%u len=%u+%u\n", opcode, len1, len2);
    }

    void on_fragmented_message(const WSFrameInfo& info) {
        printf("[MSG-FRAGMENTED] opcode=%u total_len=%u\n", info.opcode, info.frame_total_len);
    }
};

}  // namespace websocket::pipeline
