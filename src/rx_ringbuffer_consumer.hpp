// rx_ringbuffer_consumer.hpp
// Standalone consumer for reading batches from shared memory ring buffer
// Uses ShmRingBuffer to attach to .hdr/.dat files created by WebSocketClient
//
// Usage:
//   RXRingBufferConsumer consumer;
//   consumer.init("/path/to/shm");  // Opens /path/to/shm.hdr and .dat
//   consumer.set_on_messages([](const BatchInfo& batch, const MessageInfo* msgs, size_t n) { ... });
//   consumer.run();  // Blocking busy-poll
//
#pragma once

#include "ringbuffer.hpp"
#include "core/timing.hpp"
#include <functional>
#include <cstring>

// Batch metadata passed to callback
struct BatchInfo {
    size_t hdr_size;      // sizeof(ShmBatchHeader)
    size_t data_size;     // Padded SSL data size
    size_t tail_size;     // Overflow descriptors size
    size_t total_size;    // Total batch size
    uint8_t frame_count;  // Number of frames in batch
};

class RXRingBufferConsumer {
public:
    // Callback types
    using MessageCallback = std::function<void(const BatchInfo&, const MessageInfo*, size_t)>;
    using CloseCallback = std::function<void()>;      // Optional
    using ConnectCallback = std::function<void()>;    // Optional

    RXRingBufferConsumer() = default;

    ~RXRingBufferConsumer() {
        if (message_batch_) {
            delete[] message_batch_;
            message_batch_ = nullptr;
        }
    }

    // Disable copy
    RXRingBufferConsumer(const RXRingBufferConsumer&) = delete;
    RXRingBufferConsumer& operator=(const RXRingBufferConsumer&) = delete;

    // Initialize by opening shared memory files
    // path: base path, opens {path}.hdr and {path}.dat
    void init(const char* path) {
        rx_buffer_.init(path);
        if (!message_batch_) {
            message_batch_ = new MessageInfo[256];
            message_batch_capacity_ = 256;
        }
    }

    // Set message callback (REQUIRED)
    // Signature: void(const BatchInfo& batch, const MessageInfo* msgs, size_t count)
    void set_on_messages(MessageCallback cb) { on_messages_ = std::move(cb); }

    // Set connection closed callback (optional)
    void set_on_close(CloseCallback cb) { on_close_ = std::move(cb); }

    // Set connection established callback (optional)
    void set_on_connect(ConnectCallback cb) { on_connect_ = std::move(cb); }

    // Non-blocking: process all available batches, return message count
    size_t poll() {
        if (!on_messages_) return 0;

        size_t total = 0;
        while (rx_buffer_.readable() >= sizeof(ShmBatchHeader)) {
            size_t n = process_one_batch();
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    // Blocking: busy-poll until stop() called
    void run() {
        running_ = true;
        while (running_) {
            poll();
            // Busy poll - no sleep for lowest latency
        }
    }

    // Stop the run() loop
    void stop() { running_ = false; }

    // Check if running
    bool is_running() const { return running_; }

    // Buffer statistics
    size_t readable() const { return rx_buffer_.readable(); }
    size_t capacity() const { return rx_buffer_.buffer_capacity(); }
    size_t current_read_pos() const { return rx_buffer_.current_read_pos(); }
    size_t current_write_pos() const { return rx_buffer_.current_write_pos(); }

private:
    // Decode one batch (ShmBatchHeader + frames)
    // Returns number of frames processed, 0 if incomplete or invalid
    size_t process_one_batch() {
        const uint8_t* buffer = rx_buffer_.buffer_base();
        size_t capacity = rx_buffer_.buffer_capacity();
        size_t read_pos = rx_buffer_.current_read_pos();
        size_t available = rx_buffer_.readable();

        if (available < sizeof(ShmBatchHeader)) {
            return 0;  // Not enough data for header
        }

        // Read header from circular buffer
        ShmBatchHeader hdr;
        circular_read(buffer, capacity, read_pos,
                      reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr));

        // Validate header
        if (hdr.ssl_data_len_in_CLS == 0 || hdr.frame_count == 0) {
            // Empty or invalid batch - skip header
            rx_buffer_.commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        // Sanity checks
        if (hdr.ssl_data_len_in_CLS > 16384) {  // >1MB, likely corrupt
            rx_buffer_.commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        // Calculate batch size
        size_t padded_ssl_len = cls_to_bytes(hdr.ssl_data_len_in_CLS);
        size_t overflow_size = overflow_descs_size(hdr.frame_count);
        size_t batch_size = sizeof(ShmBatchHeader) + padded_ssl_len + overflow_size;

        // Sanity check batch size
        if (batch_size > capacity) {
            rx_buffer_.commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        if (available < batch_size) {
            return 0;  // Incomplete batch - wait for more data
        }

        // Read frame descriptors
        ShmFrameDesc descs[255];
        uint8_t embedded_count = std::min(hdr.frame_count, static_cast<uint8_t>(EMBEDDED_FRAMES));
        std::memcpy(descs, hdr.embedded, embedded_count * sizeof(ShmFrameDesc));

        uint8_t overflow_count = overflow_frame_count(hdr.frame_count);
        if (overflow_count > 0) {
            size_t overflow_pos = (read_pos + sizeof(ShmBatchHeader) + padded_ssl_len) % capacity;
            circular_read(buffer, capacity, overflow_pos,
                          reinterpret_cast<uint8_t*>(descs + EMBEDDED_FRAMES),
                          overflow_count * sizeof(ShmFrameDesc));
        }

        // Build message batch
        size_t ssl_data_pos = (read_pos + sizeof(ShmBatchHeader)) % capacity;
        ensure_batch_capacity(hdr.frame_count);

        for (uint8_t i = 0; i < hdr.frame_count; i++) {
            // Bounds check
            if (descs[i].payload_start + descs[i].payload_len > padded_ssl_len) {
                // Invalid frame bounds - skip entire batch
                rx_buffer_.commit_read(batch_size);
                return 0;
            }

            size_t payload_pos = (ssl_data_pos + descs[i].payload_start) % capacity;
            message_batch_[i] = {
                buffer + payload_pos,  // Zero-copy pointer
                descs[i].payload_len,
                0,  // parse_cycle not needed in consumer
                descs[i].opcode
            };
        }

        // Build batch info
        BatchInfo batch_info = {
            sizeof(ShmBatchHeader),  // hdr_size
            padded_ssl_len,          // data_size
            overflow_size,           // tail_size
            batch_size,              // total_size
            hdr.frame_count          // frame_count
        };

        // Invoke callback with batch info
        on_messages_(batch_info, message_batch_, hdr.frame_count);

        // Commit read
        rx_buffer_.commit_read(batch_size);
        return hdr.frame_count;
    }

    void ensure_batch_capacity(size_t needed) {
        if (needed > message_batch_capacity_) {
            delete[] message_batch_;
            message_batch_capacity_ = needed * 2;
            message_batch_ = new MessageInfo[message_batch_capacity_];
        }
    }

    ShmRingBuffer<ShmBufferRole::Consumer> rx_buffer_;
    MessageCallback on_messages_;
    CloseCallback on_close_;
    ConnectCallback on_connect_;
    MessageInfo* message_batch_ = nullptr;
    size_t message_batch_capacity_ = 0;
    volatile bool running_ = false;
};
