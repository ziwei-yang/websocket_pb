// rx_ringbuffer_consumer.hpp
// Standalone consumer for reading batches from shared memory ring buffer
// Compatible with HftShmRingBuffer (hft-shm format) created by WebSocketClient
//
// Usage:
//   RXRingBufferConsumer consumer;
//   consumer.init("/dev/shm/hft/test.mktdata.binance.raw.rx");
//   consumer.set_on_messages([](const BatchInfo& batch, const MessageInfo* msgs, size_t n) { ... });
//   consumer.run();  // Blocking busy-poll
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

#include "ringbuffer.hpp"
#include "core/timing.hpp"
#include <functional>
#include <cstring>
#include <atomic>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <string>

// Batch metadata passed to callback
struct BatchInfo {
    size_t hdr_size;      // sizeof(ShmBatchHeader)
    size_t data_size;     // Padded SSL data size
    size_t tail_size;     // Overflow descriptors size
    size_t total_size;    // Total batch size
    uint16_t frame_count; // Number of frames in batch (up to 65535)
};

class RXRingBufferConsumer {
public:
    // Callback types
    using MessageCallback = std::function<void(const BatchInfo&, const MessageInfo*, size_t)>;
    using CloseCallback = std::function<void()>;      // Optional
    using ConnectCallback = std::function<void()>;    // Optional

    RXRingBufferConsumer() = default;

    ~RXRingBufferConsumer() {
        cleanup();
        if (message_batch_) {
            delete[] message_batch_;
            message_batch_ = nullptr;
        }
        if (payload_copy_) {
            delete[] payload_copy_;
            payload_copy_ = nullptr;
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

        // Allocate message batch
        if (!message_batch_) {
            message_batch_ = new MessageInfo[256];
            message_batch_capacity_ = 256;
        }

        // Pre-allocate payload copy buffer (max possible = buffer capacity)
        // Eliminates dynamic allocation in hot path
        if (!payload_copy_) {
            payload_copy_ = new uint8_t[buffer_capacity_];
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

        // Validate header
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

        // Build message batch - direct access to descriptors
        // Opcode is batch-wide (from header), same for all frames in batch
        size_t ssl_data_pos = (read_pos + sizeof(ShmBatchHeader)) & index_mask_;
        size_t overflow_pos = (read_pos + sizeof(ShmBatchHeader) + padded_ssl_len) & index_mask_;
        uint8_t batch_opcode = hdr->opcode;  // Single opcode for all frames
        ensure_batch_capacity(hdr->frame_count);
        size_t payload_copy_offset = 0;

        for (uint16_t i = 0; i < hdr->frame_count; i++) {
            const ShmFrameDesc* desc;
            if (i < EMBEDDED_FRAMES) {
                // Embedded descriptors: direct pointer into header
                desc = &hdr->embedded[i];
            } else {
                // Overflow: use CLS-by-CLS addressing (each CLS holds 8 descriptors)
                // No copy needed - just locate the correct CLS and index within
                uint16_t overflow_idx = i - static_cast<uint16_t>(EMBEDDED_FRAMES);
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
                // No wrap - direct pointer (common case, zero-copy)
                message_batch_[i] = {
                    buffer_ + payload_pos,
                    desc->payload_len,
                    0,
                    batch_opcode  // Same for all frames in batch
                };
            } else {
                // Payload wraps - must copy to contiguous buffer (rare)
                // payload_copy_ pre-allocated to buffer_capacity_ in init()
                circular_read(buffer_, capacity, payload_pos,
                              payload_copy_ + payload_copy_offset, desc->payload_len);
                message_batch_[i] = {
                    payload_copy_ + payload_copy_offset,
                    desc->payload_len,
                    0,
                    batch_opcode  // Same for all frames in batch
                };
                payload_copy_offset += desc->payload_len;
            }
        }

        // Build batch info
        BatchInfo batch_info = {
            sizeof(ShmBatchHeader),
            padded_ssl_len,
            overflow_size,
            batch_size,
            hdr->frame_count
        };

        on_messages_(batch_info, message_batch_, hdr->frame_count);
        commit_read(batch_size);
        if (out_batch_size) *out_batch_size = batch_size;
        return hdr->frame_count;
    }

    void ensure_batch_capacity(size_t needed) {
        if (needed > message_batch_capacity_) {
            delete[] message_batch_;
            message_batch_capacity_ = needed * 2;
            message_batch_ = new MessageInfo[message_batch_capacity_];
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
    MessageInfo* message_batch_ = nullptr;
    size_t message_batch_capacity_ = 0;
    uint8_t* payload_copy_ = nullptr;  // Pre-allocated to buffer_capacity_ in init()
    volatile bool running_ = false;
};
