// core/hftshm_ringbuffer.hpp
// HftShmRingBuffer policy - attaches to hft-shm managed shared memory segments
// Uses SPSC (Single-Producer-Single-Consumer) memory ordering
//
// Usage:
//   HftShmRxBuffer<"test.mktdata.binance.raw.rx"> rx;  // RX = Producer
//   HftShmTxBuffer<"test.mktdata.binance.raw.tx"> tx;  // TX = Consumer
//
#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Compile-time string for segment name (C++20 NTTP)
template<size_t N>
struct FixedString {
    char data[N]{};
    constexpr FixedString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) data[i] = str[i];
    }
    constexpr operator std::string_view() const { return {data, N - 1}; }
};
template<size_t N> FixedString(const char (&)[N]) -> FixedString<N>;

// Minimal hft-shm metadata (matches layout.hpp)
namespace hftshm {

struct metadata {
    uint64_t magic;
    uint8_t  version;
    uint8_t  max_consumers;
    uint16_t event_size;
    uint32_t producer_pid;
    uint32_t buffer_size;
    uint32_t producer_offset;
    uint32_t consumer_0_offset;
    uint32_t header_size;
    uint32_t index_mask;
};
static constexpr uint64_t MAGIC = 0x00024D4853544648ULL;

struct producer_section {
    std::atomic<int64_t> cursor;
    std::atomic<int64_t> published;
    // Rest of section (metrics, padding) ignored
};

struct consumer_section {
    std::atomic<int64_t> sequence;
    // Rest of section (metrics, padding) ignored
};

} // namespace hftshm

// IsRxBuffer: true = this is RX buffer (we are producer), false = TX buffer (we are consumer)
template<FixedString SegmentName, bool IsRxBuffer, uint8_t ConsumerIndex = 0>
struct HftShmRingBuffer {
    // Parsed info from hft-shm info command
    struct SegmentInfo {
        std::string hdr_path;
        std::string dat_path;
        size_t buffer_size = 0;
        size_t hugepage_size = 0;
        std::string type;
        bool initialized = false;
    };

    HftShmRingBuffer() = default;

    ~HftShmRingBuffer() {
        cleanup();
    }

    // Disable copy
    HftShmRingBuffer(const HftShmRingBuffer&) = delete;
    HftShmRingBuffer& operator=(const HftShmRingBuffer&) = delete;

    // Initialize by querying hft-shm info and mmapping segments
    void init() {
        // Query segment info via hft-shm CLI
        SegmentInfo info = query_segment_info(std::string_view(SegmentName));

        if (!info.initialized) {
            throw std::runtime_error("Segment not initialized: " + std::string(SegmentName));
        }
        if (info.type != "ringbuffer") {
            throw std::runtime_error("Segment type must be 'ringbuffer', got: " + info.type);
        }

        // Open and mmap header
        header_fd_ = open(info.hdr_path.c_str(), O_RDWR);
        if (header_fd_ < 0) {
            throw std::runtime_error("Failed to open header: " + info.hdr_path +
                                     " (errno=" + std::to_string(errno) + ")");
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

        // Validate metadata
        auto* meta = static_cast<hftshm::metadata*>(header_);
        if (meta->magic != hftshm::MAGIC) {
            cleanup();
            throw std::runtime_error("Invalid hft-shm magic in header");
        }

        index_mask_ = meta->index_mask;
        data_size_ = meta->buffer_size;

        // Verify buffer_size matches what hft-shm info reported
        if (data_size_ != info.buffer_size) {
            cleanup();
            throw std::runtime_error("Buffer size mismatch: header says " +
                std::to_string(data_size_) + ", info says " + std::to_string(info.buffer_size));
        }

        // Open and mmap data (use hugepage flags if configured)
        data_fd_ = open(info.dat_path.c_str(), O_RDWR);
        if (data_fd_ < 0) {
            cleanup();
            throw std::runtime_error("Failed to open data: " + info.dat_path +
                                     " (errno=" + std::to_string(errno) + ")");
        }

        int mmap_flags = MAP_SHARED;
#ifdef __linux__
        if (info.hugepage_size > 0) {
            mmap_flags |= MAP_HUGETLB;
            // MAP_HUGE_1GB may not be defined on all systems
#ifdef MAP_HUGE_1GB
            if (info.hugepage_size >= 1024UL * 1024 * 1024) {
                mmap_flags |= MAP_HUGE_1GB;
            }
#endif
        }
#endif
        data_ = mmap(nullptr, data_size_, PROT_READ | PROT_WRITE, mmap_flags, data_fd_, 0);
        if (data_ == MAP_FAILED) {
            cleanup();
            throw std::runtime_error("Failed to mmap data segment");
        }

        buffer_ = static_cast<uint8_t*>(data_);

        // Set up sequence pointers from header
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(header_) + meta->producer_offset);
        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(header_) + meta->consumer_0_offset +
            ConsumerIndex * 128);  // 128 bytes per consumer section

        write_seq_ = &producer->published;
        read_seq_ = &consumer->sequence;
    }

    //=== SPSC Producer Interface (used when IsRxBuffer=true) ===

    uint8_t* next_write_region(size_t* available_len) {
        static_assert(IsRxBuffer, "next_write_region only valid for RX buffer (producer)");

        if (!available_len) return nullptr;

        size_t avail = writable();
        if (avail == 0) {
            *available_len = 0;
            return nullptr;
        }

        // SPSC: we own write_seq_, relaxed is safe
        int64_t w = write_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(w) & index_mask_;
        size_t to_end = (index_mask_ + 1) - pos;

        *available_len = (avail < to_end) ? avail : to_end;
        return buffer_ + pos;
    }

    void commit_write(size_t len) {
        static_assert(IsRxBuffer, "commit_write only valid for RX buffer (producer)");

        if (len == 0) return;

        // SPSC: we are sole writer, use load+store instead of fetch_add
        int64_t w = write_seq_->load(std::memory_order_relaxed);
        write_seq_->store(w + static_cast<int64_t>(len), std::memory_order_release);
    }

    // Producer checks how much space is available (reads consumer's sequence)
    inline size_t writable() const {
        static_assert(IsRxBuffer, "writable() only valid for RX buffer (producer)");

        int64_t w = write_seq_->load(std::memory_order_relaxed);  // We own this
        int64_t r = read_seq_->load(std::memory_order_acquire);   // Consumer's position
        return static_cast<size_t>(index_mask_) - static_cast<size_t>(w - r);
    }

    //=== SPSC Consumer Interface (used when IsRxBuffer=false) ===

    const uint8_t* next_read_region(size_t* available_len) {
        static_assert(!IsRxBuffer, "next_read_region only valid for TX buffer (consumer)");

        if (!available_len) return nullptr;

        size_t avail = readable();
        if (avail == 0) {
            *available_len = 0;
            return nullptr;
        }

        // SPSC: we own read_seq_, relaxed is safe
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(r) & index_mask_;
        size_t to_end = (index_mask_ + 1) - pos;

        *available_len = (avail < to_end) ? avail : to_end;
        return buffer_ + pos;
    }

    void commit_read(size_t len) {
        static_assert(!IsRxBuffer, "commit_read only valid for TX buffer (consumer)");

        if (len == 0) return;

        // SPSC: we are sole writer of read_seq_, use load+store
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        read_seq_->store(r + static_cast<int64_t>(len), std::memory_order_release);
    }

    // Consumer checks how much data is available (reads producer's sequence)
    inline size_t readable() const {
        static_assert(!IsRxBuffer, "readable() only valid for TX buffer (consumer)");

        int64_t w = write_seq_->load(std::memory_order_acquire);  // Producer's position
        int64_t r = read_seq_->load(std::memory_order_relaxed);   // We own this
        return static_cast<size_t>(w - r);
    }

    //=== Common Interface (matches RingBuffer) ===

    size_t capacity() const { return data_size_; }

    void reset() {
        // Sequences are managed by hft-shm, don't reset
    }

    bool is_mirrored() const { return false; }

    bool is_mmap() const { return true; }

private:
    void cleanup() {
        if (data_ && data_ != MAP_FAILED) {
            munmap(data_, data_size_);
            data_ = nullptr;
        }
        if (header_ && header_ != MAP_FAILED) {
            munmap(header_, header_size_);
            header_ = nullptr;
        }
        if (data_fd_ >= 0) {
            close(data_fd_);
            data_fd_ = -1;
        }
        if (header_fd_ >= 0) {
            close(header_fd_);
            header_fd_ = -1;
        }
        buffer_ = nullptr;
        write_seq_ = nullptr;
        read_seq_ = nullptr;
    }

    // Query segment info by invoking: hft-shm info <segment_name>
    // Parses output to extract paths, sizes, and type
    // Uses HFT_SHM_CONFIG environment variable for config path if set
    static SegmentInfo query_segment_info(std::string_view segment_name) {
        SegmentInfo info;

        std::string cmd = "hft-shm info " + std::string(segment_name);
        // Check for config path in environment
        if (const char* config_path = std::getenv("HFT_SHM_CONFIG")) {
            cmd += " --config " + std::string(config_path);
        }
        cmd += " 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to run hft-shm info command");
        }

        char line[512];
        while (fgets(line, sizeof(line), pipe)) {
            std::string_view sv(line);

            // Parse key: value lines
            // Expected format from hft-shm info:
            //   header_path: /dev/shm/hft/test/mktdata/binance/raw/rx.hdr
            //   data_path: /dev/shm/hft/test/mktdata/binance/raw/rx.dat
            //   type: ringbuffer
            //   capacity: 33554432
            //   hugepage_size: 0
            //   initialized: true

            auto colon = sv.find(':');
            if (colon == std::string_view::npos) continue;

            auto key = sv.substr(0, colon);
            auto val = sv.substr(colon + 1);

            // Trim leading/trailing whitespace from key
            while (!key.empty() && key.front() == ' ') key.remove_prefix(1);
            while (!key.empty() && key.back() == ' ') key.remove_suffix(1);

            // Trim leading/trailing whitespace and newlines from value
            while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
            while (!val.empty() && (val.back() == '\n' || val.back() == '\r' || val.back() == ' ')) {
                val.remove_suffix(1);
            }

            if (key == "header_path") {
                info.hdr_path = std::string(val);
            } else if (key == "data_path") {
                info.dat_path = std::string(val);
            } else if (key == "type") {
                info.type = std::string(val);
            } else if (key == "buffer_size" || key == "capacity") {
                // Prefer buffer_size from metadata section, but also accept capacity
                try {
                    info.buffer_size = std::stoull(std::string(val));
                } catch (...) {
                    // Ignore parse errors
                }
            } else if (key == "hugepage_size") {
                // Format may be "0B" or "2MB" etc - extract number
                try {
                    info.hugepage_size = std::stoull(std::string(val));
                } catch (...) {
                    // Ignore parse errors (e.g., "0B" won't parse)
                    info.hugepage_size = 0;
                }
            } else if (key == "status") {
                // hft-shm uses "status: active" not "initialized: true"
                info.initialized = (val == "active");
            } else if (key == "initialized") {
                info.initialized = (val == "true");
            }
        }

        int status = pclose(pipe);
        if (status != 0 || info.hdr_path.empty() || info.dat_path.empty()) {
            throw std::runtime_error("hft-shm info failed for segment: " + std::string(segment_name) +
                                     " (is hft-shm installed and segment created?)");
        }

        return info;
    }

    // Member variables
    void* header_ = nullptr;
    void* data_ = nullptr;
    size_t header_size_ = 0;
    size_t data_size_ = 0;
    int header_fd_ = -1;
    int data_fd_ = -1;

    std::atomic<int64_t>* write_seq_ = nullptr;  // -> producer.published
    std::atomic<int64_t>* read_seq_ = nullptr;   // -> consumer[N].sequence
    uint8_t* buffer_ = nullptr;
    uint32_t index_mask_ = 0;
};

// Convenience aliases - Role is determined by position in WebSocketClient template
// RX buffer: WebSocketClient is producer (writes received data)
// TX buffer: WebSocketClient is consumer (reads data to send)

template<FixedString Name, uint8_t ConsumerIdx = 0>
using HftShmRxBuffer = HftShmRingBuffer<Name, true, ConsumerIdx>;   // RX = Producer

template<FixedString Name, uint8_t ConsumerIdx = 0>
using HftShmTxBuffer = HftShmRingBuffer<Name, false, ConsumerIdx>;  // TX = Consumer
