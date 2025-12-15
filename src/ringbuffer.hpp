// ringbuffer.hpp
// Unified ring buffer implementation for WebSocket client
// Supports two buffer modes:
// - Private: PrivateRingBuffer<Capacity> - allocates private memory, on_messages() ENABLED
// - Shared:  ShmRxBuffer/ShmTxBuffer - runtime path to hft-shm files, on_messages() DISABLED
//
// All buffer types use the same batch format (ShmBatchHeader + ShmFrameDesc),
// enabling a single codepath in WebSocketClient for all buffer types.
//
#pragma once

// For memfd_create on Linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <atomic>
#include <cerrno>
#include <cassert>
#include <charconv>
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

#ifdef __APPLE__
#include <sys/shm.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <emmintrin.h>  // SSE2 for _mm_prefetch
#endif

// ============================================================================
// Section 1: Cache line, memory barriers, power-of-2 check
// ============================================================================

// Memory barriers for multi-core safety
#ifdef __aarch64__
// ARM64 (Apple Silicon, etc.) - use DMB (Data Memory Barrier)
#define WRITE_BARRIER() __asm__ __volatile__("dmb ishst" ::: "memory")
#define READ_BARRIER()  __asm__ __volatile__("dmb ishld" ::: "memory")
#elif defined(__x86_64__) || defined(__i386__)
// x86/x64 - TSO memory model, only need compiler barrier
#define WRITE_BARRIER() __asm__ __volatile__("" ::: "memory")
#define READ_BARRIER()  __asm__ __volatile__("" ::: "memory")
#else
// Generic fallback - compiler barrier
#define WRITE_BARRIER() __asm__ __volatile__("" ::: "memory")
#define READ_BARRIER()  __asm__ __volatile__("" ::: "memory")
#endif

// Platform-specific cache line size
#ifndef CACHE_LINE_SIZE
#if defined(__aarch64__) && defined(__APPLE__)
#define CACHE_LINE_SIZE 128  // Apple Silicon M1/M2/M3/M4
#else
#define CACHE_LINE_SIZE 64   // x86/x64, other ARM
#endif
#endif

// Platform-specific expectations for branch prediction
#ifdef __linux__
#define LIKELY_MIRRORED 1    // Linux: mirroring usually succeeds
#else
#define LIKELY_MIRRORED 0    // macOS/others: mirroring often fails, expect fallback
#endif

// Enable hugepages/superpages by default on supported platforms
#ifndef WS_DISABLE_HUGEPAGES
#define WS_USE_HUGEPAGES 1
#endif

// Compile-time check: Capacity must be power of 2
template<size_t N>
struct IsPowerOfTwo {
    static constexpr bool value = (N != 0) && ((N & (N - 1)) == 0);
};

// ============================================================================
// Section 2: Circular buffer helpers
// ============================================================================

// Max size for circular_read/write: 65535 frame descriptors × 12 bytes = 786,420 bytes
// These functions are for metadata (headers, descriptors), not SSL payloads
static constexpr size_t MAX_CIRCULAR_ACCESS_SIZE = 786432;

// Write len bytes to circular buffer starting at logical position
inline void circular_write(uint8_t* buffer, size_t capacity, size_t pos,
                           const uint8_t* src, size_t len) {
    assert(len <= MAX_CIRCULAR_ACCESS_SIZE &&
           "circular_write is for small metadata only; use direct access for payloads");
    pos = pos % capacity;  // Normalize position
    size_t first = std::min(len, capacity - pos);
    std::memcpy(buffer + pos, src, first);
    if (len > first) {
        std::memcpy(buffer, src + first, len - first);
    }
}

// Read len bytes from circular buffer starting at logical position
inline void circular_read(const uint8_t* buffer, size_t capacity, size_t pos,
                          uint8_t* dest, size_t len) {
    assert(len <= MAX_CIRCULAR_ACCESS_SIZE &&
           "circular_read is for small metadata only; use direct access for payloads");
    pos = pos % capacity;  // Normalize position
    size_t first = std::min(len, capacity - pos);
    std::memcpy(dest, buffer + pos, first);
    if (len > first) {
        std::memcpy(dest + first, buffer, len - first);
    }
}

// Copy len bytes within circular buffer from src_pos to dst_pos
// Processes chunk-by-chunk where both src and dst are contiguous
// memmove handles overlap within each chunk safely
inline void circular_copy(uint8_t* buffer, size_t capacity, size_t src_pos, size_t dst_pos, size_t len) {
    if (len == 0) return;
    src_pos %= capacity;
    dst_pos %= capacity;

    while (len > 0) {
        size_t src_chunk = std::min(len, capacity - src_pos);
        size_t dst_chunk = std::min(len, capacity - dst_pos);
        size_t chunk = std::min(src_chunk, dst_chunk);

        std::memmove(buffer + dst_pos, buffer + src_pos, chunk);

        src_pos = (src_pos + chunk) % capacity;
        dst_pos = (dst_pos + chunk) % capacity;
        len -= chunk;
    }
}

// Get pointer with wrap: returns buffer + (pos % capacity)
inline uint8_t* circular_ptr(uint8_t* buffer, size_t capacity, size_t pos) {
    return buffer + (pos % capacity);
}

inline const uint8_t* circular_ptr(const uint8_t* buffer, size_t capacity, size_t pos) {
    return buffer + (pos % capacity);
}

// ============================================================================
// Section 3: Shared memory batch types (from shm_types.hpp)
// ============================================================================

// Frame descriptor (9 bytes packed)
#pragma pack(push, 1)
struct ShmFrameDesc {
    uint32_t payload_start;   // Offset from ssl_data start to payload
    uint32_t payload_len;     // Payload length
    uint8_t  opcode;          // WebSocket opcode
};
#pragma pack(pop)
static_assert(sizeof(ShmFrameDesc) == 9);

// Number of frame descriptors that fit in header's reserved space
// 64-byte CLS: (64-3)/9 = 6 frames, 128-byte CLS: (128-3)/9 = 13 frames
constexpr size_t EMBEDDED_FRAMES = (CACHE_LINE_SIZE - 3) / sizeof(ShmFrameDesc);

// Batch format for RX buffer entries:
// Case 1 (≤EMBEDDED_FRAMES): [ShmBatchHeader with embedded descs: CLS][raw_ssl_data padded: N*CLS]
// Case 2 (>EMBEDDED_FRAMES): [Header: CLS][ssl_data: N*CLS][overflow descs: M*CLS]

struct alignas(CACHE_LINE_SIZE) ShmBatchHeader {
    uint16_t ssl_data_len_in_CLS;  // SSL data length in cache line units
    uint16_t frame_count;          // Total number of WebSocket frames (up to 65535)
    ShmFrameDesc embedded[EMBEDDED_FRAMES];  // First 6 (or 13) frames embedded here
    uint8_t  padding[CACHE_LINE_SIZE - 4 - EMBEDDED_FRAMES * sizeof(ShmFrameDesc)];
};
static_assert(sizeof(ShmBatchHeader) == CACHE_LINE_SIZE);

// Helper functions
inline uint16_t bytes_to_cls(size_t bytes) {
    return static_cast<uint16_t>((bytes + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE);
}

inline size_t cls_to_bytes(uint16_t cls) {
    return static_cast<size_t>(cls) * CACHE_LINE_SIZE;
}

// Number of overflow frames (frames beyond what fits in header)
inline uint16_t overflow_frame_count(uint16_t frame_count) {
    return (frame_count > EMBEDDED_FRAMES) ? (frame_count - EMBEDDED_FRAMES) : 0;
}

// Size of overflow descriptor region (cache-line padded), 0 if all fit in header
inline size_t overflow_descs_size(uint16_t frame_count) {
    uint16_t overflow = overflow_frame_count(frame_count);
    if (overflow == 0) return 0;
    size_t raw = overflow * sizeof(ShmFrameDesc);
    return (raw + CACHE_LINE_SIZE - 1) & ~(size_t)(CACHE_LINE_SIZE - 1);
}

// Total batch size
inline size_t batch_total_size(uint16_t ssl_cls, uint16_t frame_count) {
    return sizeof(ShmBatchHeader) + cls_to_bytes(ssl_cls) + overflow_descs_size(frame_count);
}

// ============================================================================
// Section 4: Unified HftShmRingBuffer - Two Modes (Private + Shared Runtime Path)
// ============================================================================
// Replaces: RingBuffer<Capacity>, ShmRingBuffer<Role>, old HftShmRingBuffer<Name>
// Both modes use hftshm::metadata layout for consistency.

// Allocation mode enum
enum class HftShmAllocMode {
    Private,           // Allocate private memory (replaces RingBuffer)
    SharedRuntimePath  // Open runtime path (replaces ShmRingBuffer)
};

// Self-documenting buffer role enum
enum class HftShmBufferRole {
    Producer,   // You WRITE to buffer (RX from network)
    Consumer,   // You READ from buffer (TX to network)
    RX = Producer,
    TX = Consumer
};

// ============================================================================
// Section 5: hftshm::metadata namespace (file format)
// ============================================================================

// Include shared header layout definitions (metadata struct, constants)
#include <hftshm/layout.hpp>

namespace hftshm {

// Alias for backward compatibility with existing code
static constexpr uint64_t MAGIC = METADATA_MAGIC;

// Producer/consumer sections (specific to this library, not shared)
struct producer_section {
    std::atomic<int64_t> cursor;
    std::atomic<int64_t> published;  // write_seq
};

struct consumer_section {
    std::atomic<int64_t> sequence;   // read_seq
    std::atomic<bool> dirty;         // true if producer bypassed consumer
};

} // namespace hftshm

// Split region for circular buffer access (data may span wrap point)
struct SplitRegion {
    uint8_t* ptr1;
    size_t   len1;
    uint8_t* ptr2;
    size_t   len2;

    size_t total() const { return len1 + len2; }
};

// ============================================================================
// Section 6: Unified HftShmRingBuffer - Two Modes (Private + Shared Runtime Path)
// ============================================================================
// Replaces: RingBuffer<Capacity>, ShmRingBuffer<Role>, old HftShmRingBuffer<Name>
// Both modes use hftshm::metadata layout for consistency.

// Unified ring buffer - supports both private and shared modes
// Uses hftshm::metadata layout for both modes (consistent internal format)
template<HftShmBufferRole Role = HftShmBufferRole::Producer,
         size_t Capacity = 0,
         HftShmAllocMode Mode = HftShmAllocMode::SharedRuntimePath>
struct HftShmRingBuffer {
    // Compile-time traits (used by WebSocketClient for dispatch)
    static constexpr bool is_hftshm = true;
    static constexpr bool is_shm_ringbuffer = (Mode == HftShmAllocMode::SharedRuntimePath);
    static constexpr bool is_private = (Mode == HftShmAllocMode::Private);
    static constexpr bool uses_runtime_path = (Mode == HftShmAllocMode::SharedRuntimePath);
    static constexpr bool is_rx = (Role == HftShmBufferRole::Producer);

    HftShmRingBuffer() = default;
    ~HftShmRingBuffer() { cleanup(); }
    HftShmRingBuffer(const HftShmRingBuffer&) = delete;
    HftShmRingBuffer& operator=(const HftShmRingBuffer&) = delete;

    // ========== Private Mode Init (no-arg) ==========
    void init() {
        if constexpr (Mode == HftShmAllocMode::Private) {
            init_private();
        } else {
            throw std::runtime_error("Shared mode requires path: use init(path)");
        }
    }

    void set_path(const char* path) {
        if constexpr (Mode == HftShmAllocMode::SharedRuntimePath) {
            path_ = path;
        }
    }

    void init_private() {
        static_assert(Capacity > 0, "Private mode requires compile-time Capacity");
        static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");

        constexpr size_t HEADER_SIZE = 256;

        // Allocate private header
        header_ = mmap(nullptr, HEADER_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (header_ == MAP_FAILED) {
            header_ = nullptr;
            throw std::runtime_error("Failed to allocate private header");
        }

        // Initialize with hftshm::metadata format
        hftshm::metadata_init(header_,
            /*max_consumers=*/1,
            /*event_size=*/0,           // Variable-size ringbuffer
            /*buffer_size=*/static_cast<uint32_t>(Capacity),
            /*producer_offset=*/64,
            /*consumer_0_offset=*/128,
            /*header_size=*/static_cast<uint32_t>(HEADER_SIZE));

        // Initialize producer/consumer sections
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(header_) + 64);
        producer->cursor.store(0, std::memory_order_relaxed);
        producer->published.store(0, std::memory_order_relaxed);

        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(header_) + 128);
        consumer->sequence.store(0, std::memory_order_relaxed);
        consumer->dirty.store(false, std::memory_order_relaxed);

        // Set up sequence pointers
        write_seq_ = &producer->published;
        read_seq_ = &consumer->sequence;
        index_mask_ = static_cast<uint32_t>(Capacity - 1);
        data_size_ = Capacity;
        header_size_ = HEADER_SIZE;

        // Allocate private data buffer (try mirrored first)
        if (try_create_mirrored_buffer() != 0) {
            buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                                  PROT_READ | PROT_WRITE,
                                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
            if (buffer_ == MAP_FAILED) {
                munmap(header_, HEADER_SIZE);
                header_ = nullptr;
                buffer_ = nullptr;
                throw std::runtime_error("Failed to allocate private buffer");
            }
            is_mirrored_ = false;
        }

        is_private_ = true;
    }

    // ========== Shared Runtime Path Mode Init ==========
    void init(const char* path) {
        path_ = path;
        std::string hdr_path = std::string(path) + ".hdr";
        std::string dat_path = std::string(path) + ".dat";

        // Open header
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

        // Validate metadata
        auto* meta = static_cast<hftshm::metadata*>(header_);
        if (meta->magic != hftshm::METADATA_MAGIC) {
            cleanup();
            throw std::runtime_error("Invalid hft-shm magic in header");
        }

        index_mask_ = meta->index_mask;
        data_size_ = meta->buffer_size;

        // Open data
        data_fd_ = open(dat_path.c_str(), O_RDWR);
        if (data_fd_ < 0) {
            cleanup();
            throw std::runtime_error("Failed to open data: " + dat_path);
        }

        data_ = mmap(nullptr, data_size_, PROT_READ | PROT_WRITE, MAP_SHARED, data_fd_, 0);
        if (data_ == MAP_FAILED) {
            cleanup();
            throw std::runtime_error("Failed to mmap data");
        }

        buffer_ = static_cast<uint8_t*>(data_);

        // Set up sequence pointers
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(header_) + meta->producer_offset);
        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(header_) + meta->consumer_0_offset);

        write_seq_ = &producer->published;
        read_seq_ = &consumer->sequence;
        dirty_flag_ = &consumer->dirty;

        is_private_ = false;
    }

    // ========== Static Create (for shared mode) ==========
    static void create(const char* path, size_t capacity) {
        if (capacity == 0 || (capacity & (capacity - 1)) != 0) {
            throw std::runtime_error("Capacity must be power of 2");
        }

        std::string hdr_path = std::string(path) + ".hdr";
        std::string dat_path = std::string(path) + ".dat";

        // Create header file
        int hdr_fd = open(hdr_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (hdr_fd < 0) throw std::runtime_error("Failed to create header: " + hdr_path);

        size_t header_size = 256;
        if (ftruncate(hdr_fd, header_size) != 0) {
            close(hdr_fd);
            throw std::runtime_error("Failed to size header");
        }

        void* hdr_map = mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, hdr_fd, 0);
        if (hdr_map == MAP_FAILED) {
            close(hdr_fd);
            throw std::runtime_error("Failed to mmap header");
        }

        // Initialize metadata
        hftshm::metadata_init(hdr_map,
            /*max_consumers=*/1,
            /*event_size=*/0,
            /*buffer_size=*/static_cast<uint32_t>(capacity),
            /*producer_offset=*/64,
            /*consumer_0_offset=*/128,
            /*header_size=*/static_cast<uint32_t>(header_size));

        // Initialize producer/consumer sections
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(hdr_map) + 64);
        producer->cursor.store(0, std::memory_order_relaxed);
        producer->published.store(0, std::memory_order_relaxed);

        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(hdr_map) + 128);
        consumer->sequence.store(0, std::memory_order_relaxed);
        consumer->dirty.store(false, std::memory_order_relaxed);

        munmap(hdr_map, header_size);
        close(hdr_fd);

        // Create data file
        int dat_fd = open(dat_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (dat_fd < 0) throw std::runtime_error("Failed to create data: " + dat_path);
        if (ftruncate(dat_fd, capacity) != 0) {
            close(dat_fd);
            throw std::runtime_error("Failed to size data");
        }
        close(dat_fd);
    }

    // ========== Producer Interface ==========
    uint8_t* next_write_region(size_t* available_len) {
        if (!available_len) return nullptr;

        size_t avail = writable();
        if (avail == 0) {
            *available_len = 0;
            return nullptr;
        }

        int64_t w = write_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(w) & index_mask_;
        size_t to_end = (index_mask_ + 1) - pos;

        *available_len = (avail < to_end) ? avail : to_end;
        return buffer_ + pos;
    }

    void commit_write(size_t len) {
        if (len == 0) return;
        int64_t w = write_seq_->load(std::memory_order_relaxed);
        write_seq_->store(w + static_cast<int64_t>(len), std::memory_order_release);
    }

    inline size_t writable() const {
        int64_t w = write_seq_->load(std::memory_order_relaxed);
        int64_t r = read_seq_->load(std::memory_order_acquire);
        return static_cast<size_t>(index_mask_ + 1) - static_cast<size_t>(w - r);
    }

    SplitRegion next_write_regions(size_t* total_available = nullptr) {
        SplitRegion result = {nullptr, 0, nullptr, 0};

        size_t avail = writable();
        if (avail == 0) {
            if (total_available) *total_available = 0;
            return result;
        }

        int64_t w = write_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(w) & index_mask_;
        size_t cap = index_mask_ + 1;
        size_t to_end = cap - pos;

        if (avail <= to_end) {
            result.ptr1 = buffer_ + pos;
            result.len1 = avail;
        } else {
            result.ptr1 = buffer_ + pos;
            result.len1 = to_end;
            result.ptr2 = buffer_;
            result.len2 = avail - to_end;
        }

        if (total_available) *total_available = avail;
        return result;
    }

    // Mark consumer as dirty (producer bypassed consumer position)
    void mark_reader_dirty() {
        if (dirty_flag_) {
            dirty_flag_->store(true, std::memory_order_release);
        }
    }

    // Check if consumer is marked dirty
    bool is_reader_dirty() const {
        return dirty_flag_ && dirty_flag_->load(std::memory_order_acquire);
    }

    // Clear dirty flag (called by consumer after resetting)
    void clear_reader_dirty() {
        if (dirty_flag_) {
            dirty_flag_->store(false, std::memory_order_release);
        }
    }

    // ========== Consumer Interface ==========
    const uint8_t* next_read_region(size_t* available_len) {
        if (!available_len) return nullptr;

        size_t avail = readable();
        if (avail == 0) {
            *available_len = 0;
            return nullptr;
        }

        int64_t r = read_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(r) & index_mask_;
        size_t to_end = (index_mask_ + 1) - pos;

        *available_len = (avail < to_end) ? avail : to_end;
        return buffer_ + pos;
    }

    void commit_read(size_t len) {
        if (len == 0) return;
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        read_seq_->store(r + static_cast<int64_t>(len), std::memory_order_release);
    }

    inline size_t readable() const {
        int64_t w = write_seq_->load(std::memory_order_acquire);
        int64_t r = read_seq_->load(std::memory_order_relaxed);
        return static_cast<size_t>(w - r);
    }

    SplitRegion next_read_regions(size_t* total_available = nullptr) const {
        SplitRegion result = {nullptr, 0, nullptr, 0};

        size_t avail = readable();
        if (avail == 0) {
            if (total_available) *total_available = 0;
            return result;
        }

        int64_t r = read_seq_->load(std::memory_order_relaxed);
        size_t pos = static_cast<size_t>(r) & index_mask_;
        size_t cap = index_mask_ + 1;
        size_t to_end = cap - pos;

        if (avail <= to_end) {
            result.ptr1 = const_cast<uint8_t*>(buffer_ + pos);
            result.len1 = avail;
        } else {
            result.ptr1 = const_cast<uint8_t*>(buffer_ + pos);
            result.len1 = to_end;
            result.ptr2 = const_cast<uint8_t*>(buffer_);
            result.len2 = avail - to_end;
        }

        if (total_available) *total_available = avail;
        return result;
    }

    // ========== Accessors ==========
    uint8_t* buffer() { return buffer_; }
    const uint8_t* buffer() const { return buffer_; }
    uint8_t* buffer_base() { return buffer_; }
    const uint8_t* buffer_base() const { return buffer_; }
    size_t capacity() const { return data_size_; }
    size_t buffer_capacity() const { return index_mask_ + 1; }
    uint32_t index_mask() const { return index_mask_; }

    size_t current_write_pos() const {
        return static_cast<size_t>(write_seq_->load(std::memory_order_relaxed)) & index_mask_;
    }
    size_t current_read_pos() const {
        return static_cast<size_t>(read_seq_->load(std::memory_order_relaxed)) & index_mask_;
    }
    size_t write_pos() const {
        return static_cast<size_t>(write_seq_->load(std::memory_order_acquire));
    }
    size_t read_pos() const {
        return static_cast<size_t>(read_seq_->load(std::memory_order_acquire));
    }

    bool is_mirrored() const { return is_mirrored_; }
    bool is_mmap() const { return true; }

    // Reset sequences to 0 (called by producer on startup)
    void reset() {
        if (write_seq_) {
            write_seq_->store(0, std::memory_order_release);
        }
        if (read_seq_) {
            read_seq_->store(0, std::memory_order_release);
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

private:
    // ========== Cleanup ==========
    void cleanup() {
        if (is_private_) {
            if (buffer_) {
                munmap(buffer_, is_mirrored_ ? (2 * data_size_) : data_size_);
                buffer_ = nullptr;
            }
            if (header_) {
                munmap(header_, header_size_);
                header_ = nullptr;
            }
        } else {
            if (data_ && data_ != MAP_FAILED) {
                munmap(data_, data_size_);
                data_ = nullptr;
            }
            if (header_ && header_ != MAP_FAILED) {
                munmap(header_, header_size_);
                header_ = nullptr;
            }
            if (data_fd_ >= 0) { close(data_fd_); data_fd_ = -1; }
            if (header_fd_ >= 0) { close(header_fd_); header_fd_ = -1; }
        }
        buffer_ = nullptr;
        write_seq_ = nullptr;
        read_seq_ = nullptr;
        dirty_flag_ = nullptr;
    }

    // ========== Mirrored Buffer Creation ==========
    // Creates a virtually mirrored buffer for seamless wrap-around access
    int try_create_mirrored_buffer() {
        if constexpr (Mode != HftShmAllocMode::Private) {
            return -1;  // Mirroring only for private mode
        }

#ifdef __linux__
        // Linux: use memfd_create for mirrored mapping
        char name[] = "hftshm-mirror-XXXXXX";
        int fd = memfd_create(name, MFD_CLOEXEC);
        if (fd < 0) return -1;

        if (ftruncate(fd, Capacity) != 0) {
            close(fd);
            return -1;
        }

        // Map twice the size at a contiguous region
        void* base = mmap(nullptr, 2 * Capacity, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) {
            close(fd);
            return -1;
        }

        // First half
        void* first = mmap(base, Capacity, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_FIXED, fd, 0);
        if (first == MAP_FAILED) {
            munmap(base, 2 * Capacity);
            close(fd);
            return -1;
        }

        // Second half (mirror)
        void* second = mmap(static_cast<uint8_t*>(base) + Capacity, Capacity,
                            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
        if (second == MAP_FAILED) {
            munmap(base, 2 * Capacity);
            close(fd);
            return -1;
        }

        close(fd);  // fd not needed after mapping
        buffer_ = static_cast<uint8_t*>(base);
        is_mirrored_ = true;
        return 0;
#else
        // macOS/other: no easy mirroring, fall back to normal mmap
        return -1;
#endif
    }

    void* header_ = nullptr;
    void* data_ = nullptr;
    uint8_t* buffer_ = nullptr;
    std::atomic<int64_t>* write_seq_ = nullptr;
    std::atomic<int64_t>* read_seq_ = nullptr;
    std::atomic<bool>* dirty_flag_ = nullptr;
    size_t header_size_ = 0;
    size_t data_size_ = 0;
    uint32_t index_mask_ = 0;
    int header_fd_ = -1;
    int data_fd_ = -1;
    bool is_private_ = false;
    bool is_mirrored_ = false;
    std::string path_;
};

// ========== Type Aliases ==========

// Private buffer (replaces RingBuffer<Capacity>)
template<size_t Capacity>
using PrivateRingBuffer = HftShmRingBuffer<HftShmBufferRole::Producer, Capacity, HftShmAllocMode::Private>;

// Shared buffer with runtime path (replaces ShmRingBuffer)
template<HftShmBufferRole Role>
using RuntimeShmBuffer = HftShmRingBuffer<Role, 0, HftShmAllocMode::SharedRuntimePath>;

// Convenience aliases (backward compatible)
using ShmRxBuffer = RuntimeShmBuffer<HftShmBufferRole::Producer>;
using ShmTxBuffer = RuntimeShmBuffer<HftShmBufferRole::Consumer>;

// ============================================================================
// Section 7: Convenience aliases (using unified HftShmRingBuffer)
// ============================================================================

// Backward-compatible size aliases (use PrivateRingBuffer internally)
using RingBuffer1MB  = PrivateRingBuffer<1u << 20>;
using RingBuffer2MB  = PrivateRingBuffer<1u << 21>;
using RingBuffer4MB  = PrivateRingBuffer<1u << 22>;
using RingBuffer8MB  = PrivateRingBuffer<1u << 23>;
using RingBuffer16MB = PrivateRingBuffer<1u << 24>;

// Legacy template alias for backward compatibility
template<size_t Capacity>
using RingBuffer = PrivateRingBuffer<Capacity>;
