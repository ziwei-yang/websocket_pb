// pipeline/disruptor_packet_io.hpp
// DisruptorPacketIO - IPC-backed PacketIO Policy for PacketTransport
//
// Implements the same interface as XDPPacketIO but delegates packet I/O
// to XDP Poll process via IPC Disruptor Rings (RAW_INBOX/RAW_OUTBOX).
//
// Architecture:
//   PacketTransport<DisruptorPacketIO>
//       │
//       └── DisruptorPacketIO (this file)
//               │
//               ├── RAW_INBOX (consumer) - RX packets from XDP Poll
//               └── RAW_OUTBOX (producer) - TX packets to XDP Poll
//
// Frame Pool Usage (50/50 split, mirrors XDPTransport):
//   - RX: Frames 0-32767 (consumed from RAW_INBOX, produced by XDP Poll)
//   - TX: Frames 32768-65535 (unified pool for data + ACKs + retransmits)
//
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <atomic>
#include <unordered_map>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "../xdp/packet_frame_descriptor.hpp"
#include "../core/timing.hpp"

namespace websocket::pipeline {

// ============================================================================
// DisruptorPacketIO Configuration
// ============================================================================

struct DisruptorPacketIOConfig {
    void* umem_area = nullptr;                                      // UMEM base pointer
    uint32_t frame_size = FRAME_SIZE;                               // Frame size in bytes
    IPCRingConsumer<websocket::xdp::PacketFrameDescriptor>* raw_inbox_cons = nullptr;
    IPCRingProducer<websocket::xdp::PacketFrameDescriptor>* raw_outbox_prod = nullptr;
    ConnStateShm* conn_state = nullptr;
};

// ============================================================================
// DisruptorPacketIO - IPC-backed PacketIO Policy
// ============================================================================

struct DisruptorPacketIO {
    using config_type = DisruptorPacketIOConfig;

    DisruptorPacketIO() = default;
    ~DisruptorPacketIO() = default;

    // Prevent copying
    DisruptorPacketIO(const DisruptorPacketIO&) = delete;
    DisruptorPacketIO& operator=(const DisruptorPacketIO&) = delete;

    // ========================================================================
    // Initialization
    // ========================================================================

    void init(const DisruptorPacketIOConfig& config) {
        umem_area_ = static_cast<uint8_t*>(config.umem_area);
        frame_size_ = config.frame_size;
        raw_inbox_cons_ = config.raw_inbox_cons;
        raw_outbox_prod_ = config.raw_outbox_prod;
        conn_state_ = config.conn_state;

        // Initialize TX pool state
        tx_alloc_pos_ = 0;
        tx_free_pos_ = 0;
        pending_tx_count_ = 0;
        for (uint32_t i = 0; i < TX_POOL_SIZE; ++i) {
            frame_acked_[i] = false;
            frame_sent_[i] = false;
        }

        // Initialize RX tracking
        frame_idx_to_seq_.clear();
        rx_process_pos_ = 0;
        rx_need_commit_ = false;
    }

    void close() {
        // Nothing to close - XDP Poll owns the XDP resources
    }

    // ========================================================================
    // RX Path - Consume from RAW_INBOX
    // ========================================================================

    template<typename Func>
    size_t process_rx_frames(size_t max_frames, Func&& callback) {
        if (!raw_inbox_cons_) return 0;

        size_t processed = 0;

        raw_inbox_cons_->process_manually([&](websocket::xdp::PacketFrameDescriptor& ipc_desc,
                                              int64_t seq, bool end_of_batch) -> bool {
            if (processed >= max_frames) {
                return false;  // Stop processing
            }

            // Make a local copy and convert UMEM offset to actual pointer
            websocket::xdp::PacketFrameDescriptor desc = ipc_desc;
            desc.frame_ptr = reinterpret_cast<uint64_t>(umem_area_) + ipc_desc.frame_ptr;

            // Track frame_idx -> seq mapping for mark_frame_consumed()
            uint32_t frame_idx = static_cast<uint32_t>(ipc_desc.frame_ptr / frame_size_);
            frame_idx_to_seq_[frame_idx] = static_cast<uint64_t>(seq);

            callback(static_cast<uint32_t>(processed), desc);

            processed++;
            rx_process_pos_++;
            return true;
        }, max_frames);

        // Commit after processing - allow XDP Poll to reclaim frames
        if (processed > 0) {
            raw_inbox_cons_->commit_manually();
            rx_need_commit_ = false;
        }

        return processed;
    }

    void mark_frame_consumed(uint32_t frame_idx) {
        auto it = frame_idx_to_seq_.find(frame_idx);
        if (it == frame_idx_to_seq_.end()) {
            return;
        }

        frame_idx_to_seq_.erase(it);
        rx_need_commit_ = true;
    }

    uint32_t get_rx_process_pos() const {
        return rx_process_pos_;
    }

    // ========================================================================
    // TX Path - Unified TX pool (frames 32768-65535)
    // ========================================================================

    template<typename Func>
    uint32_t claim_tx_frames(uint32_t count, Func&& callback) {
        if (!raw_outbox_prod_ || !conn_state_) return 0;

        // 1. Check pool capacity
        uint32_t in_use = tx_alloc_pos_ - tx_free_pos_;
        if (in_use + count > TX_POOL_SIZE) {
            return 0;
        }

        // 2. Claim IPC ring slots
        auto batch = raw_outbox_prod_->try_claim_batch(count);
        if (batch.count == 0) return 0;

        // 3. For each slot, allocate frame and invoke callback
        for (size_t i = 0; i < batch.count; i++) {
            uint32_t frame_idx = TX_POOL_START + (tx_alloc_pos_ % TX_POOL_SIZE);
            uint32_t relative_idx = tx_alloc_pos_ % TX_POOL_SIZE;
            frame_sent_[relative_idx] = false;
            uint64_t umem_offset = static_cast<uint64_t>(frame_idx) * frame_size_;

            // Write UMEM offset to IPC ring descriptor
            int64_t seq = batch.start + static_cast<int64_t>(i);
            auto& ipc_desc = (*raw_outbox_prod_)[seq];
            ipc_desc.frame_ptr = umem_offset;
            ipc_desc.nic_frame_poll_cycle = rdtsc();
            ipc_desc.frame_type = websocket::xdp::FRAME_TYPE_TX_DATA;
            ipc_desc.consumed = 0;
            ipc_desc.acked = 0;

            // Create local desc with actual pointer for callback
            websocket::xdp::PacketFrameDescriptor desc = ipc_desc;
            desc.frame_ptr = reinterpret_cast<uint64_t>(umem_area_) + umem_offset;

            callback(static_cast<uint32_t>(i), desc);

            // Copy back frame_len and frame_type from callback
            ipc_desc.frame_len = desc.frame_len;
            ipc_desc.frame_type = desc.frame_type;

            tx_alloc_pos_++;
            conn_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        }

        pending_batch_ = batch;
        pending_tx_count_ = static_cast<uint32_t>(batch.count);
        return static_cast<uint32_t>(batch.count);
    }

    void commit_tx_frames([[maybe_unused]] uint32_t lowest_idx, [[maybe_unused]] uint32_t highest_idx) {
        if (pending_tx_count_ == 0) return;

        // Mark all pending frames as sent
        // The frames were allocated at positions [tx_alloc_pos_ - pending_tx_count_, tx_alloc_pos_)
        uint32_t start_pos = tx_alloc_pos_ - pending_tx_count_;
        for (uint32_t i = 0; i < pending_tx_count_; i++) {
            uint32_t relative_idx = (start_pos + i) % TX_POOL_SIZE;
            frame_sent_[relative_idx] = true;
        }

        raw_outbox_prod_->publish_batch(pending_batch_.start, pending_batch_.end);
        pending_tx_count_ = 0;
    }

    template<typename Func>
    uint32_t commit_ack_frame(Func&& callback) {
        if (!raw_outbox_prod_ || !conn_state_) return 0;

        // Check pool capacity
        uint32_t in_use = tx_alloc_pos_ - tx_free_pos_;
        if (in_use >= TX_POOL_SIZE) return 0;

        // Claim single slot from RAW_OUTBOX
        int64_t seq = raw_outbox_prod_->try_claim();
        if (seq < 0) return 0;

        // Allocate frame from unified TX pool
        uint32_t frame_idx = TX_POOL_START + (tx_alloc_pos_ % TX_POOL_SIZE);
        uint32_t relative_idx = tx_alloc_pos_ % TX_POOL_SIZE;
        frame_sent_[relative_idx] = false;
        uint64_t umem_offset = static_cast<uint64_t>(frame_idx) * frame_size_;

        auto& ipc_desc = (*raw_outbox_prod_)[seq];
        ipc_desc.frame_ptr = umem_offset;
        ipc_desc.nic_frame_poll_cycle = rdtsc();
        ipc_desc.frame_type = websocket::xdp::FRAME_TYPE_TX_ACK;
        ipc_desc.consumed = 0;
        ipc_desc.acked = 0;

        // Create local desc with actual pointer for callback
        websocket::xdp::PacketFrameDescriptor desc = ipc_desc;
        desc.frame_ptr = reinterpret_cast<uint64_t>(umem_area_) + umem_offset;

        callback(desc);

        ipc_desc.frame_len = desc.frame_len;

        tx_alloc_pos_++;
        conn_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_relaxed);

        // Mark sent and publish
        frame_sent_[relative_idx] = true;

        raw_outbox_prod_->publish(seq);

        // Immediate release (fire-and-forget ACK)
        mark_frame_acked(frame_idx);

        return frame_idx;
    }

    void mark_frame_acked(uint32_t frame_idx) {
        if (frame_idx < TX_POOL_START || frame_idx >= TX_POOL_START + TX_POOL_SIZE) return;

        uint32_t relative_idx = (frame_idx - TX_POOL_START) % TX_POOL_SIZE;
        frame_acked_[relative_idx] = true;

        // FIFO release: advance tx_free_pos_ while contiguous frames are acked
        while (tx_free_pos_ < tx_alloc_pos_) {
            uint32_t free_rel = tx_free_pos_ % TX_POOL_SIZE;
            if (!frame_acked_[free_rel]) break;
            frame_acked_[free_rel] = false;
            frame_sent_[free_rel] = false;
            tx_free_pos_++;
        }

        // Update cross-process counter
        conn_state_->tx_frame.msg_acked_pos.store(tx_free_pos_, std::memory_order_release);
    }

    ssize_t retransmit_frame(uint32_t idx, uint16_t len) {
        if (!raw_outbox_prod_) return -1;

        // Guard: skip if frame not yet committed
        if (idx >= TX_POOL_START && idx < TX_POOL_START + TX_POOL_SIZE) {
            uint32_t relative_idx = (idx - TX_POOL_START) % TX_POOL_SIZE;
            if (!frame_sent_[relative_idx]) {
                return len;  // Not an error, just not ready
            }
        }

        // Claim single slot from RAW_OUTBOX
        int64_t seq = raw_outbox_prod_->try_claim();
        if (seq < 0) return -1;

        auto& desc = (*raw_outbox_prod_)[seq];
        desc.frame_ptr = static_cast<uint64_t>(idx) * frame_size_;
        desc.frame_len = len;
        desc.nic_frame_poll_cycle = rdtsc();
        desc.frame_type = websocket::xdp::FRAME_TYPE_TX_RETX;
        desc.consumed = 0;
        desc.acked = 0;

        raw_outbox_prod_->publish(seq);

        return len;
    }

    // ========================================================================
    // No-ops (XDP-specific operations handled by XDP Poll)
    // ========================================================================

    int poll_wait() { return 0; }
    void add_remote_ip([[maybe_unused]] const char* ip) {}
    void add_remote_port([[maybe_unused]] uint16_t port) {}
    void set_local_ip([[maybe_unused]] const char* ip) {}
    void stop_rx_trickle_thread() {}
    bool is_bpf_enabled() const { return false; }
    void print_stats() const {}

    // ========================================================================
    // Frame Utilities
    // ========================================================================

    uint32_t frame_ptr_to_idx(uint64_t frame_ptr) const {
        return static_cast<uint32_t>((frame_ptr - reinterpret_cast<uint64_t>(umem_area_)) / frame_size_);
    }

    uint64_t frame_idx_to_addr(uint32_t idx) const {
        return static_cast<uint64_t>(idx) * frame_size_;
    }

    uint8_t* get_frame_ptr(uint64_t addr) {
        return umem_area_ + addr;
    }

    uint32_t frame_capacity() const {
        return frame_size_;
    }

    // ========================================================================
    // Accessors for compatibility
    // ========================================================================

    const char* get_mode() const { return "IPC-Disruptor"; }
    const char* get_interface() const { return "disruptor"; }
    uint32_t get_queue_id() const { return 0; }
    uint32_t get_frame_size() const { return frame_size_; }
    void* get_umem_area() { return umem_area_; }

private:
    // ========================================================================
    // Member Variables
    // ========================================================================

    // UMEM
    uint8_t* umem_area_ = nullptr;
    uint32_t frame_size_ = FRAME_SIZE;

    // IPC rings
    IPCRingConsumer<websocket::xdp::PacketFrameDescriptor>* raw_inbox_cons_ = nullptr;
    IPCRingProducer<websocket::xdp::PacketFrameDescriptor>* raw_outbox_prod_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // TX pool (50/50 split: frames 32768-65535)
    static constexpr uint32_t TX_POOL_START = 32768;
    static constexpr uint32_t TX_POOL_SIZE = 32768;
    uint32_t tx_alloc_pos_ = 0;    // monotonic, next to allocate
    uint32_t tx_free_pos_ = 0;     // monotonic, next available for reuse
    bool frame_acked_[TX_POOL_SIZE] = {};
    bool frame_sent_[TX_POOL_SIZE] = {};

    // TX pending (for claim -> commit two-phase)
    typename IPCRingProducer<websocket::xdp::PacketFrameDescriptor>::ClaimContext pending_batch_;
    uint32_t pending_tx_count_ = 0;

    // RX tracking
    std::unordered_map<uint32_t, uint64_t> frame_idx_to_seq_;
    uint32_t rx_process_pos_ = 0;
    bool rx_need_commit_ = false;
};

}  // namespace websocket::pipeline
