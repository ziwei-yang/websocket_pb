// websocket_txrx/rx_consumer.hpp
// RXRingBufferConsumer for external processes to consume WebSocket RX shared memory
// Part of websocket_txrx export headers
//
// Prerequisites:
//   - hft-shm init --config ~/hft.toml (creates shared memory files)
//   - Include path: -I/path/to/01_shared_headers (for hftshm/layout.hpp)
//
// Usage:
//   #include <websocket_txrx/rx_consumer.hpp>
//
//   RXRingBufferConsumer consumer;
//   consumer.init("/dev/shm/hft/test.mktdata.binance.raw.rx");
//
//   consumer.set_on_messages([&](const ShmBatchHeader* hdr, const ShmMessageInfo* msgs) {
//       if (hdr->is_status_only()) {
//           // Handle connection status changes
//           if (hdr->is_connected()) {
//               printf("Connected! Refill TX for re-subscription.\n");
//           } else {
//               printf("Disconnected!\n");
//           }
//           return;
//       }
//       // Process messages
//       for (uint16_t i = 0; i < hdr->frame_count; i++) {
//           const uint8_t* payload = consumer.resolve_payload(msgs[i]);
//           int32_t len = msgs[i].len;
//           // ... process payload
//       }
//   });
//
//   while (running) {
//       consumer.poll();  // Non-blocking
//   }
//
#pragma once

// Debug printing - enable with -DDEBUG
#ifdef DEBUG
#define DEBUG_PRINT(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define DEBUG_FPRINTF(...) do { fprintf(__VA_ARGS__); fflush(stderr); } while(0)
#else
#define DEBUG_PRINT(...) ((void)0)
#define DEBUG_FPRINTF(...) ((void)0)
#endif

#include "shm_batch_header.hpp"
#include "message_info.hpp"
#include "circular_helpers.hpp"
#include <hftshm/layout.hpp>

#include <functional>
#include <cstring>
#include <atomic>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <string>

// Producer/consumer section layouts (must match websocket_pb's ringbuffer.hpp)
namespace hftshm {
struct producer_section {
    std::atomic<int64_t> cursor;
    std::atomic<int64_t> published;  // write_seq
};

struct consumer_section {
    std::atomic<int64_t> sequence;   // read_seq
    std::atomic<bool> dirty;         // true if producer bypassed consumer
};
} // namespace hftshm

class RXRingBufferConsumer {
public:
    // Assembly buffer size for wrapped payloads (2MB fixed)
    static constexpr size_t ASSEMBLY_BUFFER_SIZE = 2 * 1024 * 1024;

    // Callback types
    // New simplified signature: header contains status, frame_count, cpucycle; no separate size_t n
    using MessageCallback = std::function<void(const ShmBatchHeader*, const ShmMessageInfo*)>;
    using CloseCallback = std::function<void()>;      // Optional
    using ConnectCallback = std::function<void()>;    // Optional

    RXRingBufferConsumer() = default;

    ~RXRingBufferConsumer() {
        cleanup();
        if (message_batch_) {
            delete[] message_batch_;
            message_batch_ = nullptr;
        }
        if (assembly_buffer_) {
            delete[] assembly_buffer_;
            assembly_buffer_ = nullptr;
        }
    }

    // Disable copy
    RXRingBufferConsumer(const RXRingBufferConsumer&) = delete;
    RXRingBufferConsumer& operator=(const RXRingBufferConsumer&) = delete;

    // Initialize by opening shared memory files (hft-shm format)
    // path: base path without extension, opens {path}.hdr and {path}.dat
    void init(const char* path) {
        std::string hdr_path = std::string(path) + ".hdr";
        std::string dat_path = std::string(path) + ".dat";

        // Open and mmap header
        header_fd_ = open(hdr_path.c_str(), O_RDWR);
        if (header_fd_ < 0) {
            throw std::runtime_error("Failed to open header: " + hdr_path);
        }

        struct stat st;
        if (fstat(header_fd_, &st) < 0) {
            close(header_fd_);
            header_fd_ = -1;
            throw std::runtime_error("Failed to stat header");
        }
        header_size_ = st.st_size;

        header_ = mmap(nullptr, header_size_, PROT_READ | PROT_WRITE, MAP_SHARED, header_fd_, 0);
        if (header_ == MAP_FAILED) {
            close(header_fd_);
            header_fd_ = -1;
            header_ = nullptr;
            throw std::runtime_error("Failed to mmap header");
        }

        // Validate hft-shm metadata
        auto* meta = static_cast<hftshm::metadata*>(header_);
        if (meta->magic != hftshm::METADATA_MAGIC) {
            cleanup();
            throw std::runtime_error("Invalid hft-shm magic in header");
        }

        index_mask_ = meta->index_mask;
        buffer_capacity_ = meta->buffer_size;

        // Open and mmap data
        data_fd_ = open(dat_path.c_str(), O_RDWR);
        if (data_fd_ < 0) {
            cleanup();
            throw std::runtime_error("Failed to open data: " + dat_path);
        }

        data_ = mmap(nullptr, buffer_capacity_, PROT_READ | PROT_WRITE, MAP_SHARED, data_fd_, 0);
        if (data_ == MAP_FAILED) {
            cleanup();
            throw std::runtime_error("Failed to mmap data segment");
        }

        buffer_ = static_cast<uint8_t*>(data_);

        // Set up sequence pointers (hft-shm layout)
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(header_) + meta->producer_offset);
        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(header_) + meta->consumer_0_offset);

        write_seq_ = &producer->published;
        read_seq_ = &consumer->sequence;
        dirty_flag_ = &consumer->dirty;

        // Check if we need to resync (stale consumer position from previous run)
        // Resync if: readable < 0, readable > half buffer, or data looks invalid
        int64_t w = write_seq_->load(std::memory_order_acquire);
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        int64_t readable_bytes = w - r;
        bool need_resync = (readable_bytes < 0 || readable_bytes > static_cast<int64_t>(buffer_capacity_ / 2));

        // Also check if data at read_pos looks like valid batch header
        if (!need_resync && readable_bytes >= static_cast<int64_t>(sizeof(ShmBatchHeader))) {
            size_t read_pos = static_cast<size_t>(r) & index_mask_;
            const auto* hdr = reinterpret_cast<const ShmBatchHeader*>(buffer_ + read_pos);
            // Check for reasonable values (ssl_data typically < 64KB, frame_count < 1000)
            if (hdr->ssl_data_len_in_CLS > 1024 || hdr->frame_count > 1000 ||
                hdr->ssl_data_len_in_CLS == 0 || hdr->frame_count == 0) {
                need_resync = true;
            }
        }

        if (need_resync) {
            DEBUG_FPRINTF(stderr, "[INFO] Consumer resync: invalid/stale position, jumping to write_pos\n");
            read_seq_->store(w, std::memory_order_release);
        }

        // Allocate message batch (ShmMessageInfo: 8 bytes each)
        if (!message_batch_) {
            message_batch_ = new ShmMessageInfo[256];
            message_batch_capacity_ = 256;
        }

        // Pre-allocate assembly buffer for wrapped payloads (fixed 2MB)
        // Used when a payload spans the buffer wrap-around point
        if (!assembly_buffer_) {
            assembly_buffer_ = new uint8_t[ASSEMBLY_BUFFER_SIZE];
        }
    }

    // Set message callback (REQUIRED)
    void set_on_messages(MessageCallback cb) { on_messages_ = std::move(cb); }

    // Set connection closed callback (optional)
    void set_on_close(CloseCallback cb) { on_close_ = std::move(cb); }

    // Set connection established callback (optional)
    void set_on_connect(ConnectCallback cb) { on_connect_ = std::move(cb); }

    // Non-blocking: process all available batches, return message count
    // Limits processing per call to min(buffer_capacity/2, 1MB) to prevent infinite loops
    size_t poll() {
        if (!on_messages_) return 0;

        // Check if producer marked us dirty (data was overwritten)
        if (dirty_flag_ && dirty_flag_->load(std::memory_order_acquire)) {
            DEBUG_FPRINTF(stderr, "[WARN] Consumer marked dirty - producer overwrote data. "
                    "Resetting to write_pos (data loss)\n");
            // Reset read position to current write position
            int64_t w = write_seq_->load(std::memory_order_acquire);
            read_seq_->store(w, std::memory_order_release);
            dirty_flag_->store(false, std::memory_order_release);
            return 0;  // No data this call, next call will start fresh
        }

        size_t total = 0;
        size_t bytes_processed = 0;
        size_t max_bytes = (buffer_capacity_ / 2 < 1024 * 1024)
                         ? buffer_capacity_ / 2
                         : 1024 * 1024;

        while (readable() >= sizeof(ShmBatchHeader) && bytes_processed < max_bytes) {
            size_t batch_size = 0;
            size_t n = process_one_batch(&batch_size);
            if (n == 0) break;
            total += n;
            bytes_processed += batch_size;
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
    size_t readable() const {
        int64_t w = write_seq_->load(std::memory_order_acquire);
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        return static_cast<size_t>(w - r);
    }

    size_t capacity() const { return buffer_capacity_; }

    size_t current_read_pos() const {
        return static_cast<size_t>(read_seq_->load(std::memory_order_relaxed));
    }

    size_t current_write_pos() const {
        return static_cast<size_t>(write_seq_->load(std::memory_order_relaxed));
    }

    // Get pointer to SSL data region (valid only during callback)
    // Use this to resolve offsets: ssl_data_ptr() + msg.offset
    const uint8_t* ssl_data_ptr() const { return current_ssl_data_ptr_; }

    // Get assembly buffer for wrapped payloads
    // When msg.offset < 0: payload is at assembly_buffer + (-offset - 1)
    const uint8_t* get_assembly_buffer() const { return assembly_buffer_; }

    // Helper to resolve payload pointer from ShmMessageInfo
    // If offset >= 0: pointer is ssl_data_ptr() + offset
    // If offset < 0: pointer is assembly_buffer + (-offset - 1)
    const uint8_t* resolve_payload(const ShmMessageInfo& msg) const {
        if (msg.offset >= 0) {
            return current_ssl_data_ptr_ + msg.offset;
        } else {
            return assembly_buffer_ + static_cast<size_t>(-msg.offset - 1);
        }
    }

private:
    void cleanup() {
        if (data_ && data_ != MAP_FAILED) {
            munmap(data_, buffer_capacity_);
            data_ = nullptr;
        }
        if (data_fd_ >= 0) {
            close(data_fd_);
            data_fd_ = -1;
        }
        if (header_ && header_ != MAP_FAILED) {
            munmap(header_, header_size_);
            header_ = nullptr;
        }
        if (header_fd_ >= 0) {
            close(header_fd_);
            header_fd_ = -1;
        }
    }

    void commit_read(size_t len) {
        if (len == 0) return;
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        read_seq_->store(r + static_cast<int64_t>(len), std::memory_order_release);
    }

    // Decode one batch (ShmBatchHeader + frames)
    // Returns number of frames processed, 0 if incomplete or invalid
    // Optionally returns batch_size through out parameter
    size_t process_one_batch(size_t* out_batch_size = nullptr) {
        size_t capacity = buffer_capacity_;
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        size_t read_pos = static_cast<size_t>(r) & index_mask_;
        size_t available = readable();

        if (available < sizeof(ShmBatchHeader)) {
            return 0;
        }

        // Header is always CLS-aligned (producer writes at CLS boundaries)
        // sizeof(ShmBatchHeader) = 1 CLS, so header never wraps within itself
        const ShmBatchHeader* hdr = reinterpret_cast<const ShmBatchHeader*>(buffer_ + read_pos);

        // Handle status-only batch (connection events)
        // frame_count=0 and ssl_data_len_in_CLS=0 indicates a status-only message
        if (hdr->is_status_only()) {
            // Invoke callback with empty message array for status events
            on_messages_(hdr, nullptr);
            commit_read(sizeof(ShmBatchHeader));
            if (out_batch_size) *out_batch_size = sizeof(ShmBatchHeader);
            return 0;  // No frames, but batch was processed
        }

        // Validate header for data batches
        if (hdr->ssl_data_len_in_CLS == 0 || hdr->frame_count == 0) {
            commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        // Sanity checks
        if (hdr->ssl_data_len_in_CLS > 16384) {  // >1MB, likely corrupt
            commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        // Calculate batch size
        size_t padded_ssl_len = cls_to_bytes(hdr->ssl_data_len_in_CLS);
        size_t overflow_size = overflow_descs_size(hdr->frame_count);
        size_t batch_size = sizeof(ShmBatchHeader) + padded_ssl_len + overflow_size;

        if (batch_size > capacity || available < batch_size) {
            if (batch_size > capacity) commit_read(sizeof(ShmBatchHeader));
            return 0;
        }

        // Build message batch with offsets (ShmMessageInfo)
        size_t ssl_data_pos = (read_pos + sizeof(ShmBatchHeader)) & index_mask_;
        size_t overflow_pos = (read_pos + sizeof(ShmBatchHeader) + padded_ssl_len) & index_mask_;
        ensure_batch_capacity(hdr->frame_count);
        size_t assembly_offset = 0;  // Track position in assembly buffer for wrapped payloads

        for (uint16_t i = 0; i < hdr->frame_count; i++) {
            const ShmFrameDesc* desc;
            if (i < EMBEDDED_FRAME_NUM) {
                // Embedded descriptors: direct pointer into header
                desc = &hdr->embedded[i];
            } else {
                // Overflow: use CLS-by-CLS addressing (each CLS holds 8 descriptors)
                uint16_t overflow_idx = i - static_cast<uint16_t>(EMBEDDED_FRAME_NUM);
                size_t cls_idx = overflow_idx >> DESCS_PER_CLS_SHIFT;  // / 8
                size_t cls_pos = (overflow_pos + (cls_idx << CLS_SHIFT)) & index_mask_;  // * 64, wrap
                const ShmFrameDesc* cls_ptr = reinterpret_cast<const ShmFrameDesc*>(buffer_ + cls_pos);
                desc = &cls_ptr[overflow_idx & DESCS_PER_CLS_MASK];  // % 8
            }

            // Bounds check
            if (desc->payload_start + desc->payload_len > padded_ssl_len) {
                commit_read(batch_size);
                return 0;
            }

            size_t payload_pos = (ssl_data_pos + desc->payload_start) & index_mask_;

            // Check if payload wraps around buffer boundary
            if (payload_pos + desc->payload_len <= capacity) {
                // No wrap - store offset directly (common case)
                message_batch_[i] = {
                    static_cast<int32_t>(desc->payload_start),
                    static_cast<int32_t>(desc->payload_len)
                };
            } else {
                // Payload wraps - copy to assembly buffer for contiguous access
                // Store negative offset to indicate assembly buffer location
                circular_read(buffer_, capacity, payload_pos,
                              assembly_buffer_ + assembly_offset, desc->payload_len);
                // Use negative offset to signal "in assembly buffer"
                // Consumer can detect this and use get_assembly_buffer() + (-offset - 1)
                message_batch_[i] = {
                    -static_cast<int32_t>(assembly_offset) - 1,  // Negative = assembly buffer
                    static_cast<int32_t>(desc->payload_len)
                };
                assembly_offset += desc->payload_len;
            }
        }

        // Set ssl_data_ptr for callback (valid only during callback)
        size_t ssl_data_start = (read_pos + sizeof(ShmBatchHeader)) & index_mask_;
        current_ssl_data_ptr_ = buffer_ + ssl_data_start;

        // Invoke callback with new signature: (header, messages)
        // frame_count available from hdr->frame_count
        on_messages_(hdr, message_batch_);

        // Clear ssl_data_ptr after callback
        current_ssl_data_ptr_ = nullptr;
        commit_read(batch_size);
        if (out_batch_size) *out_batch_size = batch_size;
        return hdr->frame_count;
    }

    void ensure_batch_capacity(size_t needed) {
        if (needed > message_batch_capacity_) {
            delete[] message_batch_;
            message_batch_capacity_ = needed * 2;
            message_batch_ = new ShmMessageInfo[message_batch_capacity_];
        }
    }

    // hft-shm mmap state
    int header_fd_ = -1;
    int data_fd_ = -1;
    void* header_ = nullptr;
    void* data_ = nullptr;
    size_t header_size_ = 0;
    size_t buffer_capacity_ = 0;
    uint32_t index_mask_ = 0;
    uint8_t* buffer_ = nullptr;
    std::atomic<int64_t>* write_seq_ = nullptr;
    std::atomic<int64_t>* read_seq_ = nullptr;
    std::atomic<bool>* dirty_flag_ = nullptr;

    // Callbacks
    MessageCallback on_messages_;
    CloseCallback on_close_;
    ConnectCallback on_connect_;

    // Batch processing state
    ShmMessageInfo* message_batch_ = nullptr;
    size_t message_batch_capacity_ = 0;
    uint8_t* assembly_buffer_ = nullptr;  // Pre-allocated 2MB for wrapped payloads
    volatile bool running_ = false;

    // Current SSL data pointer (valid only during callback)
    const uint8_t* current_ssl_data_ptr_ = nullptr;
};
