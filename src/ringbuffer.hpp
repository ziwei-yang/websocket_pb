// ringbuffer.hpp
// Unified ring buffer implementation for WebSocket client
// Supports: Private memory (RingBuffer), Shared memory (ShmRingBuffer, HftShmRingBuffer)
//
// All buffer types use the same batch format (ShmBatchHeader + ShmFrameDesc),
// enabling a single codepath in WebSocketClient for all buffer types.
//
#pragma once

#include <atomic>
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

// Max size for circular_read/write: 255 frame descriptors × 9 bytes = 2295 bytes
// These functions are for metadata (headers, descriptors), not SSL payloads
static constexpr size_t MAX_CIRCULAR_ACCESS_SIZE = 2304;

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
    uint8_t  frame_count;          // Total number of WebSocket frames
    ShmFrameDesc embedded[EMBEDDED_FRAMES];  // First 6 (or 13) frames embedded here
    uint8_t  padding[CACHE_LINE_SIZE - 3 - EMBEDDED_FRAMES * sizeof(ShmFrameDesc)];
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
inline uint8_t overflow_frame_count(uint8_t frame_count) {
    return (frame_count > EMBEDDED_FRAMES) ? (frame_count - EMBEDDED_FRAMES) : 0;
}

// Size of overflow descriptor region (cache-line padded), 0 if all fit in header
inline size_t overflow_descs_size(uint8_t frame_count) {
    uint8_t overflow = overflow_frame_count(frame_count);
    if (overflow == 0) return 0;
    size_t raw = overflow * sizeof(ShmFrameDesc);
    return (raw + CACHE_LINE_SIZE - 1) & ~(size_t)(CACHE_LINE_SIZE - 1);
}

// Total batch size
inline size_t batch_total_size(uint16_t ssl_cls, uint8_t frame_count) {
    return sizeof(ShmBatchHeader) + cls_to_bytes(ssl_cls) + overflow_descs_size(frame_count);
}

// ============================================================================
// Section 4: RingBuffer<Capacity> - Private memory buffer
// ============================================================================

// Template parameter: Buffer capacity in bytes (MUST be power of 2)
template<size_t Capacity>
struct RingBuffer {
    static_assert(IsPowerOfTwo<Capacity>::value, "Capacity must be a power of 2");

    // Compile-time traits for buffer type detection
    static constexpr bool is_hftshm = false;
    static constexpr bool is_shm_ringbuffer = false;

    RingBuffer()
        : buffer_(nullptr)
        , write_pos_(0)
        , is_mmap_(false)
        , is_mirrored_(false)
        , is_external_(false)
        , read_pos_(0)
    {
    }

    ~RingBuffer() {
        if (buffer_ && !is_external_) {
            if (is_mmap_) {
                size_t unmap_size = is_mirrored_ ? (2 * Capacity) : Capacity;
                munmap(buffer_, unmap_size);
            } else {
                free(buffer_);
            }
            buffer_ = nullptr;
        }
    }

    // Initialize ring buffer (allocates memory)
    void init() {
        if (buffer_ && !is_external_) {
            if (is_mmap_) {
                size_t unmap_size = is_mirrored_ ? (2 * Capacity) : Capacity;
                munmap(buffer_, unmap_size);
            } else {
                free(buffer_);
            }
        }
        buffer_ = nullptr;

        read_pos_ = 0;
        write_pos_ = 0;
        is_mirrored_ = false;
        is_mmap_ = false;
        is_external_ = false;

        // Try virtual memory mirroring first (best performance)
        if (try_create_mirrored_buffer() == 0) {
            return;
        }

        // Mirroring failed, fall back to regular allocation
#ifdef WS_USE_HUGEPAGES
#ifdef __linux__
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                             -1, 0));

        if (buffer_ == MAP_FAILED) {
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        } else {
            is_mmap_ = true;
        }
#elif defined(__APPLE__)
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0));

        if (buffer_ != MAP_FAILED) {
            madvise(buffer_, Capacity, MADV_WILLNEED);
            is_mmap_ = true;
        } else {
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        }
#else
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0));

        if (buffer_ == MAP_FAILED) {
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        } else {
            is_mmap_ = true;
        }
#endif
#else
        if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
            throw std::runtime_error("Failed to allocate ring buffer");
        }
        is_mmap_ = false;
#endif

        if (!buffer_) {
            throw std::runtime_error("Failed to allocate ring buffer");
        }
    }

    // Initialize ring buffer with external memory (shared memory outbox)
    void init_external(void* buffer, size_t size) {
        if (size != Capacity) {
            throw std::runtime_error("External buffer size mismatch");
        }

        if (buffer_ && !is_external_) {
            if (is_mmap_) {
                size_t unmap_size = is_mirrored_ ? (2 * Capacity) : Capacity;
                munmap(buffer_, unmap_size);
            } else {
                free(buffer_);
            }
        }

        buffer_ = static_cast<uint8_t*>(buffer);
        write_pos_ = 0;
        read_pos_ = 0;
        is_mmap_ = false;
        is_mirrored_ = false;
        is_external_ = true;
    }

    // Get pointer to next writable region (zero-copy write)
    uint8_t* next_write_region(size_t* available_len) {
        if (__builtin_expect(!buffer_ || !available_len, 0)) {
            if (available_len) *available_len = 0;
            return nullptr;
        }

        size_t available = writable();

        if (__builtin_expect(available == 0, 0)) {
            *available_len = 0;
            return nullptr;
        }

        uint8_t* data = buffer_ + write_pos_;
        prefetch_write(data);

        if (__builtin_expect(available > CACHE_LINE_SIZE, 1)) {
            prefetch_write(data + CACHE_LINE_SIZE);
            if (__builtin_expect(available > 2 * CACHE_LINE_SIZE, 1)) {
                prefetch_write(data + 2 * CACHE_LINE_SIZE);
            }
            if (__builtin_expect(available > 4 * CACHE_LINE_SIZE, 0)) {
                prefetch_write(data + 4 * CACHE_LINE_SIZE);
            }
        }

        if (__builtin_expect(is_mirrored_, LIKELY_MIRRORED)) {
            *available_len = available;
        } else {
            size_t space_to_end = Capacity - write_pos_;
            if (__builtin_expect(write_pos_ >= read_pos_, 1)) {
                if (__builtin_expect(space_to_end > 1, 1)) {
                    *available_len = space_to_end - 1;
                    if (*available_len > available) *available_len = available;
                } else {
                    *available_len = 0;
                }
            } else {
                *available_len = read_pos_ - write_pos_ - 1;
            }
        }

        return data;
    }

    // Commit written bytes to the buffer
    void commit_write(size_t len) {
        if (__builtin_expect(len == 0, 0)) return;

        size_t available = writable();
        if (__builtin_expect(len > available, 0)) len = available;

        WRITE_BARRIER();
        write_pos_ = (write_pos_ + len) & (Capacity - 1);
    }

    // Get pointer to next readable region (zero-copy read)
    const uint8_t* next_read_region(size_t* available_len) {
        if (__builtin_expect(!buffer_ || !available_len, 0)) {
            if (available_len) *available_len = 0;
            return nullptr;
        }

        READ_BARRIER();
        size_t available = readable();

        if (__builtin_expect(available == 0, 0)) {
            *available_len = 0;
            return nullptr;
        }

        const uint8_t* data = buffer_ + read_pos_;

        if (__builtin_expect(available > CACHE_LINE_SIZE, 1)) {
            prefetch_read(data + CACHE_LINE_SIZE);
            if (__builtin_expect(available > 256, 1)) {
                prefetch_read(data + 256);
            }
        }

        if (__builtin_expect(is_mirrored_, LIKELY_MIRRORED)) {
            *available_len = available;
        } else {
            if (__builtin_expect(write_pos_ >= read_pos_, 1)) {
                *available_len = write_pos_ - read_pos_;
            } else {
                *available_len = Capacity - read_pos_;
            }
            if (__builtin_expect(*available_len > available, 0)) *available_len = available;
        }

        return data;
    }

    // Commit consumed bytes from the buffer
    void commit_read(size_t len) {
        if (__builtin_expect(len == 0, 0)) return;

        size_t available = readable();
        if (__builtin_expect(len > available, 0)) len = available;

        read_pos_ = (read_pos_ + len) & (Capacity - 1);
    }

    // Get number of bytes available for reading
    inline size_t readable() const {
        size_t w = write_pos_;
        size_t r = read_pos_;
        return (w - r) & (Capacity - 1);
    }

    // Get number of bytes available for writing
    inline size_t writable() const {
        size_t w = write_pos_;
        size_t r = read_pos_;
        return (r - w - 1) & (Capacity - 1);
    }

    void reset() {
        read_pos_ = 0;
        write_pos_ = 0;
    }

    constexpr size_t capacity() const { return Capacity; }
    bool is_mirrored() const { return is_mirrored_; }
    bool is_mmap() const { return is_mmap_; }

    // Circular buffer interface (compatibility with HftShmRingBuffer)
    uint8_t* buffer_base() { return buffer_; }
    const uint8_t* buffer_base() const { return buffer_; }
    size_t buffer_capacity() const { return Capacity; }
    size_t current_write_pos() const { return write_pos_; }
    size_t current_read_pos() const { return read_pos_; }

    // Disable copy and move
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

private:
    static inline void prefetch_read(const void* addr) {
#if defined(__x86_64__) || defined(__i386__)
        _mm_prefetch(static_cast<const char*>(addr), _MM_HINT_T0);
#elif defined(__aarch64__)
        __asm__ __volatile__("prfm pldl1keep, [%0]" : : "r"(addr));
#else
        __builtin_prefetch(addr, 0, 3);
#endif
    }

    static inline void prefetch_write(void* addr) {
#if defined(__x86_64__) || defined(__i386__)
        _mm_prefetch(static_cast<const char*>(addr), _MM_HINT_T0);
#elif defined(__aarch64__)
        __asm__ __volatile__("prfm pstl1keep, [%0]" : : "r"(addr));
#else
        __builtin_prefetch(addr, 1, 3);
#endif
    }

    int try_create_mirrored_buffer() {
#if defined(__APPLE__) || defined(__linux__)
        void* addr = mmap(nullptr, 2 * Capacity, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            return -1;
        }

        int fd;
#ifdef __APPLE__
        static std::atomic<int> shm_counter{0};
        int counter = shm_counter.fetch_add(1, std::memory_order_seq_cst);

        char shm_name[256];
        int ret = snprintf(shm_name, sizeof(shm_name), "/tmp/ringbuffer_%d_%d_%lx",
                           getpid(), counter, reinterpret_cast<unsigned long>(this));
        if (ret < 0 || ret >= static_cast<int>(sizeof(shm_name))) {
            munmap(addr, 2 * Capacity);
            return -1;
        }

        fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            munmap(addr, 2 * Capacity);
            return -1;
        }
        shm_unlink(shm_name);
#else
        fd = memfd_create("ringbuffer", 0);
        if (fd < 0) {
            static std::atomic<int> shm_counter{0};
            int counter = shm_counter.fetch_add(1, std::memory_order_seq_cst);

            char shm_name[256];
            int ret = snprintf(shm_name, sizeof(shm_name), "/ringbuffer_%d_%d_%lx",
                               getpid(), counter, reinterpret_cast<unsigned long>(this));
            if (ret < 0 || ret >= static_cast<int>(sizeof(shm_name))) {
                munmap(addr, 2 * Capacity);
                return -1;
            }

            fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
            if (fd < 0) {
                munmap(addr, 2 * Capacity);
                return -1;
            }
            shm_unlink(shm_name);
        }
#endif

        if (ftruncate(fd, Capacity) != 0) {
            close(fd);
            munmap(addr, 2 * Capacity);
            return -1;
        }

        void* addr1 = mmap(addr, Capacity, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_SHARED, fd, 0);
        if (addr1 == MAP_FAILED || addr1 != addr) {
            close(fd);
            munmap(addr, 2 * Capacity);
            return -1;
        }

        void* addr2 = mmap(static_cast<uint8_t*>(addr) + Capacity, Capacity,
                           PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0);
        if (addr2 == MAP_FAILED || addr2 != static_cast<uint8_t*>(addr) + Capacity) {
            munmap(addr, 2 * Capacity);
            close(fd);
            return -1;
        }

        close(fd);
        buffer_ = static_cast<uint8_t*>(addr);
        is_mmap_ = true;
        is_mirrored_ = true;
        return 0;
#else
        return -1;
#endif
    }

    // Producer-owned cache line
    uint8_t* buffer_;
    size_t write_pos_;
    bool is_mmap_;
    bool is_mirrored_;
    bool is_external_;

    alignas(CACHE_LINE_SIZE) char _pad_producer[CACHE_LINE_SIZE - sizeof(uint8_t*) - sizeof(size_t) - 3*sizeof(bool)];

    // Consumer-owned cache line
    alignas(CACHE_LINE_SIZE) size_t read_pos_;
    char _pad_consumer[CACHE_LINE_SIZE - sizeof(size_t)];

} __attribute__((aligned(CACHE_LINE_SIZE)));

// ============================================================================
// Section 5: hftshm::metadata namespace (file format)
// ============================================================================

namespace hftshm {

struct metadata {
    uint64_t magic;              // 0x00024D4853544648
    uint8_t  version;
    uint8_t  max_consumers;
    uint16_t event_size;
    uint32_t producer_pid;
    uint32_t buffer_size;
    uint32_t producer_offset;    // 64
    uint32_t consumer_0_offset;  // 128
    uint32_t header_size;
    uint32_t index_mask;
};
static constexpr uint64_t MAGIC = 0x00024D4853544648ULL;

struct producer_section {
    std::atomic<int64_t> cursor;
    std::atomic<int64_t> published;  // write_seq
};

struct consumer_section {
    std::atomic<int64_t> sequence;   // read_seq
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
// Section 6: ShmRingBuffer<Role> - Runtime path (NEW)
// ============================================================================

enum class ShmBufferRole { Producer, Consumer };

// Runtime shared memory ring buffer using hdr+dat file scheme
template<ShmBufferRole Role>
class ShmRingBuffer {
public:
    // Compile-time traits
    static constexpr bool is_hftshm = false;
    static constexpr bool is_shm_ringbuffer = true;
    static constexpr bool is_rx = (Role == ShmBufferRole::Producer);

    ShmRingBuffer() = default;

    ~ShmRingBuffer() {
        cleanup();
    }

    // Disable copy
    ShmRingBuffer(const ShmRingBuffer&) = delete;
    ShmRingBuffer& operator=(const ShmRingBuffer&) = delete;

    // Create new shared memory files (one-time setup)
    static void create(const char* path, size_t capacity) {
        // Validate capacity is power of 2
        if (capacity == 0 || (capacity & (capacity - 1)) != 0) {
            throw std::runtime_error("Capacity must be a power of 2");
        }

        std::string hdr_path = std::string(path) + ".hdr";
        std::string dat_path = std::string(path) + ".dat";

        // Create header file
        int hdr_fd = open(hdr_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (hdr_fd < 0) {
            throw std::runtime_error("Failed to create header file: " + hdr_path);
        }

        // Calculate header size (metadata + producer section + consumer section)
        size_t header_size = 256;  // Align to cache line, enough for all sections
        if (ftruncate(hdr_fd, header_size) != 0) {
            close(hdr_fd);
            throw std::runtime_error("Failed to size header file");
        }

        void* hdr_map = mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, hdr_fd, 0);
        if (hdr_map == MAP_FAILED) {
            close(hdr_fd);
            throw std::runtime_error("Failed to mmap header file");
        }

        // Initialize metadata
        auto* meta = static_cast<hftshm::metadata*>(hdr_map);
        std::memset(meta, 0, sizeof(hftshm::metadata));
        meta->magic = hftshm::MAGIC;
        meta->version = 2;
        meta->max_consumers = 1;
        meta->event_size = 0;  // Not used for ringbuffer
        meta->producer_pid = getpid();
        meta->buffer_size = static_cast<uint32_t>(capacity);
        meta->producer_offset = 64;   // Producer section at offset 64
        meta->consumer_0_offset = 128; // Consumer section at offset 128
        meta->header_size = static_cast<uint32_t>(header_size);
        meta->index_mask = static_cast<uint32_t>(capacity - 1);

        // Initialize producer section (sequences start at 0)
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(hdr_map) + meta->producer_offset);
        producer->cursor.store(0, std::memory_order_relaxed);
        producer->published.store(0, std::memory_order_relaxed);

        // Initialize consumer section
        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(hdr_map) + meta->consumer_0_offset);
        consumer->sequence.store(0, std::memory_order_relaxed);

        munmap(hdr_map, header_size);
        close(hdr_fd);

        // Create data file
        int dat_fd = open(dat_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (dat_fd < 0) {
            throw std::runtime_error("Failed to create data file: " + dat_path);
        }

        if (ftruncate(dat_fd, capacity) != 0) {
            close(dat_fd);
            throw std::runtime_error("Failed to size data file");
        }

        close(dat_fd);
    }

    void set_path(const char* path) { path_ = path; }

    void init() {
        if (path_.empty()) {
            throw std::runtime_error("ShmRingBuffer: path not set");
        }
        init(path_.c_str());
    }

    void init(const char* path) {
        path_ = path;
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

        // Validate metadata
        auto* meta = static_cast<hftshm::metadata*>(header_);
        if (meta->magic != hftshm::MAGIC) {
            cleanup();
            throw std::runtime_error("Invalid magic in header");
        }

        index_mask_ = meta->index_mask;
        data_size_ = meta->buffer_size;

        // Open and mmap data
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
    }

    // === SPSC Producer Interface ===

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

    // === SPSC Consumer Interface ===

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

    // === Common Interface ===

    uint8_t* buffer_base() { return buffer_; }
    const uint8_t* buffer_base() const { return buffer_; }
    size_t buffer_capacity() const { return index_mask_ + 1; }
    size_t current_write_pos() const {
        return static_cast<size_t>(write_seq_->load(std::memory_order_relaxed)) & index_mask_;
    }
    size_t current_read_pos() const {
        return static_cast<size_t>(read_seq_->load(std::memory_order_relaxed)) & index_mask_;
    }

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

    void* header_ = nullptr;
    void* data_ = nullptr;
    size_t header_size_ = 0;
    size_t data_size_ = 0;
    int header_fd_ = -1;
    int data_fd_ = -1;

    std::atomic<int64_t>* write_seq_ = nullptr;
    std::atomic<int64_t>* read_seq_ = nullptr;
    uint8_t* buffer_ = nullptr;
    uint32_t index_mask_ = 0;
    std::string path_;
};

using ShmRxBuffer = ShmRingBuffer<ShmBufferRole::Producer>;
using ShmTxBuffer = ShmRingBuffer<ShmBufferRole::Consumer>;

// ============================================================================
// Section 7: HftShmRingBuffer - Compile-time segment name (C++20 only)
// ============================================================================

#if __cplusplus >= 202002L

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

// Self-documenting buffer role enum
enum class HftShmBufferRole {
    Producer,   // You WRITE to buffer
    Consumer,   // You READ from buffer
    RX = Producer,
    TX = Consumer
};

// HftShmRingBuffer - derives paths from segment name (no CLI query)
template<FixedString SegmentName, HftShmBufferRole Role, uint8_t ConsumerIndex = 0>
struct HftShmRingBuffer {
    static_assert(ConsumerIndex == 0,
        "HftShmRingBuffer only supports SPSC mode (ConsumerIndex must be 0)");

    // Compile-time traits
    static constexpr bool is_hftshm = true;
    static constexpr bool is_shm_ringbuffer = false;
    static constexpr bool is_rx = (Role == HftShmBufferRole::Producer);

    HftShmRingBuffer() = default;

    ~HftShmRingBuffer() {
        cleanup();
    }

    HftShmRingBuffer(const HftShmRingBuffer&) = delete;
    HftShmRingBuffer& operator=(const HftShmRingBuffer&) = delete;

    // Initialize by deriving paths from segment name
    void init() {
        // Derive paths from segment name (hft-shm keeps dots in filename)
        // "test.mktdata.binance.raw.rx" → "/dev/shm/hft/test.mktdata.binance.raw.rx"
        std::string base = segment_name_to_path(std::string_view(SegmentName));
        std::string hdr_path = base + ".hdr";
        std::string dat_path = base + ".dat";

        // Open and mmap header
        header_fd_ = open(hdr_path.c_str(), O_RDWR);
        if (header_fd_ < 0) {
            throw std::runtime_error("Failed to open header: " + hdr_path +
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

        // Open and mmap data
        data_fd_ = open(dat_path.c_str(), O_RDWR);
        if (data_fd_ < 0) {
            cleanup();
            throw std::runtime_error("Failed to open data: " + dat_path +
                                     " (errno=" + std::to_string(errno) + ")");
        }

        data_ = mmap(nullptr, data_size_, PROT_READ | PROT_WRITE, MAP_SHARED, data_fd_, 0);
        if (data_ == MAP_FAILED) {
            cleanup();
            throw std::runtime_error("Failed to mmap data segment");
        }

        buffer_ = static_cast<uint8_t*>(data_);

        // Set up sequence pointers
        auto* producer = reinterpret_cast<hftshm::producer_section*>(
            static_cast<uint8_t*>(header_) + meta->producer_offset);
        static constexpr size_t CONSUMER_SECTION_STRIDE = 128;
        auto* consumer = reinterpret_cast<hftshm::consumer_section*>(
            static_cast<uint8_t*>(header_) + meta->consumer_0_offset +
            ConsumerIndex * CONSUMER_SECTION_STRIDE);

        write_seq_ = &producer->published;
        read_seq_ = &consumer->sequence;

        std::atomic_thread_fence(std::memory_order_seq_cst);

        int64_t w = write_seq_->load(std::memory_order_seq_cst);
        int64_t r = read_seq_->load(std::memory_order_seq_cst);
        int64_t readable = w - r;
        if (readable < 0 || readable > static_cast<int64_t>(data_size_)) {
            cleanup();
            throw std::runtime_error("Invalid sequence values in shared memory");
        }
    }

    // === SPSC Producer Interface ===

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

    // === SPSC Consumer Interface ===

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

    // === Common Interface ===

    uint8_t* buffer_base() { return buffer_; }
    const uint8_t* buffer_base() const { return buffer_; }
    size_t buffer_capacity() const { return index_mask_ + 1; }
    size_t capacity() const { return data_size_; }

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

    void reset() { /* Sequences are managed by hft-shm, don't reset */ }
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

    // Derive file path from segment name (hft-shm keeps dots in filename)
    // "test.mktdata.binance.raw.rx" → "/dev/shm/hft/test.mktdata.binance.raw.rx"
    static std::string segment_name_to_path(std::string_view name) {
        std::string path = "/dev/shm/hft/";
        path.append(name);
        return path;
    }

    void* header_ = nullptr;
    void* data_ = nullptr;
    size_t header_size_ = 0;
    size_t data_size_ = 0;
    int header_fd_ = -1;
    int data_fd_ = -1;

    std::atomic<int64_t>* write_seq_ = nullptr;
    std::atomic<int64_t>* read_seq_ = nullptr;
    uint8_t* buffer_ = nullptr;
    uint32_t index_mask_ = 0;
};

template<FixedString Name, uint8_t ConsumerIdx = 0>
using HftShmRxBuffer = HftShmRingBuffer<Name, HftShmBufferRole::Producer, ConsumerIdx>;

template<FixedString Name, uint8_t ConsumerIdx = 0>
using HftShmTxBuffer = HftShmRingBuffer<Name, HftShmBufferRole::Consumer, ConsumerIdx>;

#endif // __cplusplus >= 202002L (C++20)

// ============================================================================
// Section 8: Convenience aliases
// ============================================================================

using RingBuffer1MB  = RingBuffer<1u << 20>;
using RingBuffer2MB  = RingBuffer<1u << 21>;
using RingBuffer4MB  = RingBuffer<1u << 22>;
using RingBuffer8MB  = RingBuffer<1u << 23>;
using RingBuffer16MB = RingBuffer<1u << 24>;
