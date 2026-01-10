// pipeline/websocket_process.hpp
// WebSocket Process - Frame parsing and control frame handling
// Parses WS frames from MSG_INBOX, publishes to AppClient via WS_FRAME_INFO
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "ws_parser.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// WebSocketProcess - WS frame parser and control frame handler
//
// Responsibilities:
// 1. Consume MsgMetadata from MSG_METADATA ring
// 2. Parse WebSocket frames from MSG_INBOX data
// 3. Handle control frames: PING → PONGS, CLOSE → MSG_OUTBOX
// 4. Publish WSFrameInfo for TEXT/BINARY to AppClient
// 5. Track partial frames across SSL_read boundaries
// 6. Accumulate timestamps from first packet of each message
//
// Fragment handling:
// - WebSocket allows fragmented messages (FIN=0, continuation frames)
// - This process accumulates fragment metadata
// - AppClient receives WSFrameInfo with is_fragmented=true
//
// Batching (process_manually + commit_manually pattern):
// - Uses accumulated_metadata_[] array (256 entries) for batch processing
// - Deferred commit reduces atomic operations per event
// - Commits on: end_of_batch, WS frame complete, or array full
// ============================================================================

// Maximum metadata entries to accumulate before forced commit
constexpr size_t MAX_ACCUMULATED_METADATA = 256;

// Template parameters for each ring type used by WebSocketProcess
template<typename MsgMetadataCons,     // IPCRingConsumer<MsgMetadata>
         typename WSFrameInfoProd,     // IPCRingProducer<WSFrameInfo>
         typename PongsProd,           // IPCRingProducer<PongFrameAligned>
         typename MsgOutboxProd>       // IPCRingProducer<MsgOutboxEvent>
struct WebSocketProcess {
    // ========================================================================
    // Initialization
    // ========================================================================

    bool init(MsgInbox* msg_inbox,
              MsgMetadataCons* msg_metadata_cons,
              WSFrameInfoProd* ws_frame_info_prod,
              PongsProd* pongs_prod,
              MsgOutboxProd* msg_outbox_prod,
              TCPStateShm* tcp_state) {

        msg_inbox_ = msg_inbox;
        msg_metadata_cons_ = msg_metadata_cons;
        ws_frame_info_prod_ = ws_frame_info_prod;
        pongs_prod_ = pongs_prod;
        msg_outbox_prod_ = msg_outbox_prod;
        tcp_state_ = tcp_state;

        pending_frame_.clear();
        reset_accumulator();
        reset_fragment_state();

        printf("[WS-PROCESS] Initialized\n");
        return true;
    }

    // ========================================================================
    // Main Loop - uses process_manually + commit_manually pattern
    // ========================================================================

    void run() {
        printf("[WS-PROCESS] Running main loop\n");

        // Mark ourselves as ready
        tcp_state_->set_ready(PROC_WEBSOCKET);

        while (tcp_state_->is_running(PROC_WEBSOCKET)) {
            // Process batch of metadata events
            size_t processed = msg_metadata_cons_->process_manually(
                [this](MsgMetadata& meta, int64_t seq, bool end_of_batch) {
                    return process_metadata_batched(meta, seq, end_of_batch);
                },
                MAX_ACCUMULATED_METADATA
            );

            if (processed > 0) {
                // Commit after batch (deferred commit pattern)
                if (deferred_commit_pending_) {
                    msg_metadata_cons_->commit_manually();
                    deferred_commit_pending_ = false;
                    deferred_commit_seq_ = -1;
                }
            } else {
                __builtin_ia32_pause();  // CPU hint for spin-wait
            }
        }
    }

    // ========================================================================
    // disruptor::event_processor Handler Interface (legacy)
    // Called by event_processor.run() when events are available
    // ========================================================================

    void on_event(MsgMetadata& event, int64_t sequence, bool end_of_batch) {
        (void)sequence;      // Not used, but required by handler interface
        (void)end_of_batch;  // Not used, but required by handler interface
        process_metadata(event);
    }

    // ========================================================================
    // Metadata Processing (Batched - with deferred commit)
    // ========================================================================

    /**
     * Process metadata in batch mode with deferred commit
     * Gap N5: Per-frame accumulation - metadata stored until WS frame completes
     * @return true to continue processing, false to stop batch early
     */
    bool process_metadata_batched(MsgMetadata& meta, int64_t seq, bool end_of_batch) {
        // Gap N5: Store in accumulated array for per-frame latency analysis
        // Array preserves all SSL_read metadata until WS frame is complete
        if (frame_accumulated_count_ < MAX_ACCUMULATED_METADATA) {
            frame_accumulated_metadata_[frame_accumulated_count_++] = meta;
        }

        // Track deferred commit
        deferred_commit_pending_ = true;
        deferred_commit_seq_ = seq;

        // Process the metadata (same as non-batched)
        process_metadata_internal(meta);

        // Note: frame_accumulated_metadata_ is reset in publish_frame_info()
        // when a WS frame completes, NOT on end_of_batch

        return true;  // Continue processing
    }

    // ========================================================================
    // Metadata Processing (Legacy - immediate commit)
    // ========================================================================

    void process_metadata(MsgMetadata& meta) {
        process_metadata_internal(meta);
    }

    // ========================================================================
    // Internal Metadata Processing
    // ========================================================================

    void process_metadata_internal(MsgMetadata& meta) {
        // Accumulate timestamps from first packet of this batch
        if (!has_accumulated_meta_) {
            accumulated_meta_.first_nic_timestamp_ns = meta.first_nic_timestamp_ns;
            accumulated_meta_.first_raw_frame_poll_cycle = meta.first_raw_frame_poll_cycle;
            has_accumulated_meta_ = true;
        }
        accumulated_meta_.latest_nic_timestamp_ns = meta.latest_nic_timestamp_ns;
        accumulated_meta_.latest_raw_frame_poll_cycle = meta.latest_raw_frame_poll_cycle;
        accumulated_meta_.ssl_read_cycle = meta.ssl_read_cycle;

        // Parse WebSocket frames from this SSL_read chunk
        const uint8_t* data = msg_inbox_->data_at(meta.msg_inbox_offset);
        size_t remaining = meta.decrypted_len;
        uint32_t current_offset = meta.msg_inbox_offset;

        while (remaining > 0) {
            size_t consumed = 0;

            if (!pending_frame_.header_complete) {
                // Need to complete header first
                if (pending_frame_.header_bytes_received == 0) {
                    consumed = start_parse_frame(pending_frame_, data, remaining);
                } else {
                    consumed = continue_partial_frame(pending_frame_, data, remaining);
                }

                data += consumed;
                remaining -= consumed;
                current_offset += consumed;

                if (!pending_frame_.header_complete) {
                    // Still need more header bytes
                    break;
                }
            }

            // Header is complete, process payload
            if (pending_frame_.header_complete) {
                uint64_t payload_remaining = pending_frame_.payload_remaining();

                if (payload_remaining > 0 && remaining > 0) {
                    // Calculate how much payload we can process
                    size_t payload_consumed = (remaining < payload_remaining)
                        ? remaining : static_cast<size_t>(payload_remaining);

                    // Track payload offset (first byte of payload)
                    if (pending_frame_.payload_bytes_received == 0) {
                        current_payload_offset_ = current_offset;
                    }

                    pending_frame_.payload_bytes_received += payload_consumed;
                    data += payload_consumed;
                    remaining -= payload_consumed;
                    current_offset += payload_consumed;
                }

                // Check if frame is complete
                if (pending_frame_.is_complete()) {
                    handle_complete_frame();
                    pending_frame_.clear();
                }
            }
        }
    }

    // ========================================================================
    // Complete Frame Handling
    // ========================================================================

    void handle_complete_frame() {
        uint64_t parse_cycle = rdtsc();

        uint8_t opcode = pending_frame_.opcode;
        bool fin = pending_frame_.fin;
        uint64_t payload_len = pending_frame_.payload_len;
        uint32_t frame_total_len = pending_frame_.expected_header_len + static_cast<uint32_t>(payload_len);

        // Handle based on opcode
        switch (opcode) {
            case WS_OP_TEXT:
            case WS_OP_BINARY:
                handle_data_frame(opcode, fin, payload_len, frame_total_len, parse_cycle);
                break;

            case WS_OP_CONTINUATION:
                handle_continuation_frame(fin, payload_len, frame_total_len, parse_cycle);
                break;

            case WS_OP_PING:
                handle_ping(payload_len);
                break;

            case WS_OP_PONG:
                // Ignore PONG frames (we sent PING, server responded)
                break;

            case WS_OP_CLOSE:
                handle_close(payload_len);
                break;

            default:
                fprintf(stderr, "[WS-PROCESS] Unknown opcode: 0x%02X\n", opcode);
                break;
        }
    }

    void handle_data_frame(uint8_t opcode, bool fin, uint64_t payload_len, uint32_t frame_total_len, uint64_t parse_cycle) {
        if (fin) {
            // Complete message in single frame
            publish_frame_info(opcode, payload_len, frame_total_len, parse_cycle, false);
        } else {
            // Start of fragmented message
            fragment_opcode_ = opcode;
            fragment_payload_total_ = payload_len;
            fragment_total_len_ = frame_total_len;  // Tracks total bytes including headers
            fragment_first_offset_ = current_payload_offset_;
            accumulating_fragments_ = true;

            // Store timestamps from first fragment
            fragment_meta_ = accumulated_meta_;
        }
    }

    void handle_continuation_frame(bool fin, uint64_t payload_len, uint32_t frame_total_len, uint64_t parse_cycle) {
        if (!accumulating_fragments_) {
            fprintf(stderr, "[WS-PROCESS] Unexpected continuation frame\n");
            return;
        }

        fragment_payload_total_ += payload_len;
        fragment_total_len_ += frame_total_len;  // Add this frame's total (header + payload)

        if (fin) {
            // End of fragmented message
            WSFrameInfo info;
            info.msg_inbox_offset = fragment_first_offset_;
            info.payload_len = static_cast<uint32_t>(fragment_payload_total_);  // Total payload bytes
            info.opcode = fragment_opcode_;
            info.is_fin = 1;
            info.is_fragmented = 1;  // Signal fragmentation to AppClient
            info.frame_total_len = fragment_total_len_;  // Total bytes including headers

            // Use timestamps from first fragment (Gap N6: renamed fields)
            info.first_byte_ts = fragment_meta_.first_nic_timestamp_ns;
            info.first_raw_frame_poll_cycle = fragment_meta_.first_raw_frame_poll_cycle;
            info.last_byte_ts = accumulated_meta_.latest_nic_timestamp_ns;
            info.latest_raw_frame_poll_cycle = accumulated_meta_.latest_raw_frame_poll_cycle;
            info.ssl_read_cycle = accumulated_meta_.ssl_read_cycle;
            info.ws_parse_cycle = parse_cycle;

            if (!ws_frame_info_prod_->try_publish(info)) {
                fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
                abort();
            }

            reset_fragment_state();
            reset_accumulator();
        }
    }

    void handle_ping(uint64_t payload_len) {
        // Queue PONG response
        PongFrameAligned pong;
        pong.clear();

        if (payload_len > 0 && payload_len <= 125) {
            // Copy PING payload to PONG
            const uint8_t* payload = msg_inbox_->data_at(current_payload_offset_);
            pong.set(payload, payload_len);
        }

        if (!pongs_prod_->try_publish(pong)) {
            // PONG queue full - not critical, skip
            fprintf(stderr, "[WS-PROCESS] PONG queue full, skipping\n");
        }
    }

    void handle_close(uint64_t payload_len) {
        // Echo CLOSE frame back
        MsgOutboxEvent event;
        event.clear();

        if (payload_len >= 2) {
            const uint8_t* payload = msg_inbox_->data_at(current_payload_offset_);
            uint16_t status_code = (payload[0] << 8) | payload[1];

            // Copy status code and optional reason
            event.set_close(status_code,
                            payload_len > 2 ? reinterpret_cast<const char*>(payload + 2) : nullptr,
                            payload_len > 2 ? payload_len - 2 : 0);
        } else {
            event.set_close(1000);  // Normal closure
        }

        if (!msg_outbox_prod_->try_publish(event)) {
            fprintf(stderr, "[WS-PROCESS] MSG_OUTBOX full for CLOSE\n");
        }

        // Signal shutdown to all processes
        tcp_state_->shutdown_all();
    }

    void publish_frame_info(uint8_t opcode, uint64_t payload_len, uint32_t frame_total_len, uint64_t parse_cycle, bool is_fragmented) {
        WSFrameInfo info;
        info.clear();

        info.msg_inbox_offset = current_payload_offset_;
        info.payload_len = static_cast<uint32_t>(payload_len);
        info.opcode = opcode;
        info.is_fin = 1;
        info.is_fragmented = is_fragmented ? 1 : 0;
        info.frame_total_len = frame_total_len;  // Total bytes including header

        // Copy accumulated timestamps (Gap N6: renamed fields)
        info.first_byte_ts = accumulated_meta_.first_nic_timestamp_ns;
        info.first_raw_frame_poll_cycle = accumulated_meta_.first_raw_frame_poll_cycle;
        info.last_byte_ts = accumulated_meta_.latest_nic_timestamp_ns;
        info.latest_raw_frame_poll_cycle = accumulated_meta_.latest_raw_frame_poll_cycle;
        info.ssl_read_cycle = accumulated_meta_.ssl_read_cycle;
        info.ws_parse_cycle = parse_cycle;

        if (!ws_frame_info_prod_->try_publish(info)) {
            fprintf(stderr, "[WS-PROCESS] FATAL: WS_FRAME_INFO full\n");
            abort();
        }

        // Reset accumulator for next message
        reset_accumulator();

        // Gap N5: Reset per-frame accumulated metadata
        frame_accumulated_count_ = 0;
    }

private:
    void reset_accumulator() {
        has_accumulated_meta_ = false;
        accumulated_meta_.clear();
    }

    void reset_fragment_state() {
        accumulating_fragments_ = false;
        fragment_opcode_ = 0;
        fragment_payload_total_ = 0;
        fragment_total_len_ = 0;
        fragment_first_offset_ = 0;
    }

    // State
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataCons* msg_metadata_cons_ = nullptr;
    WSFrameInfoProd* ws_frame_info_prod_ = nullptr;
    PongsProd* pongs_prod_ = nullptr;
    MsgOutboxProd* msg_outbox_prod_ = nullptr;
    TCPStateShm* tcp_state_ = nullptr;

    // Partial frame tracking
    PartialWebSocketFrame pending_frame_;
    uint32_t current_payload_offset_ = 0;

    // Metadata accumulator (tracks timestamps across SSL_reads for same WS message)
    bool has_accumulated_meta_ = false;
    MsgMetadata accumulated_meta_;

    // Gap N5: Per-frame accumulated metadata array
    // Stores all SSL_read metadata contributing to current WS frame
    // Reset when WS frame is complete (in publish_frame_info)
    MsgMetadata frame_accumulated_metadata_[MAX_ACCUMULATED_METADATA];
    size_t frame_accumulated_count_ = 0;

    // Deferred commit tracking (Gap 16)
    bool deferred_commit_pending_ = false;
    int64_t deferred_commit_seq_ = -1;

    // Fragment state
    bool accumulating_fragments_ = false;
    uint8_t fragment_opcode_ = 0;
    uint64_t fragment_payload_total_ = 0;  // Total payload bytes across all fragments
    uint32_t fragment_total_len_ = 0;       // Total bytes including headers
    uint32_t fragment_first_offset_ = 0;
    MsgMetadata fragment_meta_;
};

}  // namespace websocket::pipeline
