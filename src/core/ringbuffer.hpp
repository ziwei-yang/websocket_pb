// core/ringbuffer.hpp
// Lock-free single-producer single-consumer ring buffer with compile-time size
// Optimized for high-frequency trading with cache-line alignment, memory barriers,
// and optional virtual memory mirroring
#pragma once

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>

#ifdef __APPLE__
#include <sys/shm.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <emmintrin.h>  // SSE2 for _mm_prefetch
#endif

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
#if defined(__aarch64__) && defined(__APPLE__)
#define CACHE_LINE_SIZE 128  // Apple Silicon M1/M2/M3/M4
#else
#define CACHE_LINE_SIZE 64   // x86/x64, other ARM
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

// Circular buffer helper functions (shared between RingBuffer and HftShmRingBuffer)
// Guard allows both ringbuffer.hpp and hftshm_ringbuffer.hpp to define these
// (hftshm_ringbuffer.hpp can be used standalone without ringbuffer.hpp)
#ifndef CIRCULAR_BUFFER_HELPERS_DEFINED
#define CIRCULAR_BUFFER_HELPERS_DEFINED

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

#endif // CIRCULAR_BUFFER_HELPERS_DEFINED

// Template parameter: Buffer capacity in bytes (MUST be power of 2)
template<size_t Capacity>
struct RingBuffer {
    static_assert(IsPowerOfTwo<Capacity>::value, "Capacity must be a power of 2");

    RingBuffer()
        : buffer_(nullptr)
        , write_pos_(0)
        , is_mmap_(false)
        , is_mirrored_(false)
        , is_external_(false)
        , read_pos_(0)
    {
        // Warn if structure is not cache-line aligned
        if (reinterpret_cast<uintptr_t>(this) % CACHE_LINE_SIZE != 0) {
            // Note: This check happens at construction time
        }
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
            // Success - mirrored buffer allocated
            return;
        }

        // Mirroring failed, fall back to regular allocation
#ifdef WS_USE_HUGEPAGES
#ifdef __linux__
        // Linux: Try to use hugepages (2MB)
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                             -1, 0));

        if (buffer_ == MAP_FAILED) {
            // Fallback to regular pages with cache-line alignment
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        } else {
            is_mmap_ = true;
        }
#elif defined(__APPLE__)
        // macOS: Use superpages (VM_FLAGS_SUPERPAGE_SIZE_2MB)
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0));

        if (buffer_ != MAP_FAILED) {
            // Advise the kernel to use superpages for this region
            madvise(buffer_, Capacity, MADV_WILLNEED);
            is_mmap_ = true;
        } else {
            // Fallback: aligned malloc
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        }
#else
        // Other platforms: use regular mmap
        buffer_ = static_cast<uint8_t*>(mmap(nullptr, Capacity,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0));

        if (buffer_ == MAP_FAILED) {
            // Fallback to aligned malloc
            if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
                throw std::runtime_error("Failed to allocate ring buffer");
            }
            is_mmap_ = false;
        } else {
            is_mmap_ = true;
        }
#endif
#else
        // Hugepages disabled, use cache-line aligned allocation
        if (posix_memalign(reinterpret_cast<void**>(&buffer_), CACHE_LINE_SIZE, Capacity) != 0) {
            throw std::runtime_error("Failed to allocate ring buffer");
        }
        is_mmap_ = false;
#endif

        if (!buffer_) {
            throw std::runtime_error("Failed to allocate ring buffer");
        }
    }

    /**
     * Initialize ring buffer with external memory (shared memory outbox)
     * Does NOT own memory - caller responsible for allocation/deallocation
     *
     * @param buffer  Pointer to pre-allocated/mapped memory
     * @param size    Size of memory region (must equal Capacity)
     */
    void init_external(void* buffer, size_t size) {
        if (size != Capacity) {
            throw std::runtime_error("External buffer size mismatch");
        }

        // Cleanup existing buffer if any (but not external ones)
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
    // Returns: pointer to writable region, sets available_len to size
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

        // Always return contiguous space
        uint8_t* data = buffer_ + write_pos_;

        // Aggressive prefetching for streaming writes
        prefetch_write(data);

        if (__builtin_expect(available > CACHE_LINE_SIZE, 1)) {
            prefetch_write(data + CACHE_LINE_SIZE);

            // Prefetch third cache line for typical message sizes
            if (__builtin_expect(available > 2 * CACHE_LINE_SIZE, 1)) {
                prefetch_write(data + 2 * CACHE_LINE_SIZE);
            }

            // For very large messages, prefetch even further
            if (__builtin_expect(available > 4 * CACHE_LINE_SIZE, 0)) {
                prefetch_write(data + 4 * CACHE_LINE_SIZE);
            }
        }

        if (__builtin_expect(is_mirrored_, LIKELY_MIRRORED)) {
            // Mirrored buffer: always contiguous, no wraparound logic!
            *available_len = available;
        } else {
            // Non-mirrored: need to handle wraparound
            size_t space_to_end = Capacity - write_pos_;

            if (__builtin_expect(write_pos_ >= read_pos_, 1)) {
                // Write pointer ahead, can write to end but leave 1 byte buffer
                if (__builtin_expect(space_to_end > 1, 1)) {
                    *available_len = space_to_end - 1;
                    if (*available_len > available) *available_len = available;
                } else {
                    *available_len = 0;
                }
            } else {
                // Read pointer ahead, can write up to read pointer
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

        // Ensure all data writes complete before updating offset (critical for ARM)
        WRITE_BARRIER();

        // Optimized: bitwise AND instead of expensive modulo
        write_pos_ = (write_pos_ + len) & (Capacity - 1);
    }

    // Get pointer to next readable region (zero-copy read)
    // Returns: const pointer to readable region, sets available_len to size
    const uint8_t* next_read_region(size_t* available_len) {
        if (__builtin_expect(!buffer_ || !available_len, 0)) {
            if (available_len) *available_len = 0;
            return nullptr;
        }

        // Ensure offset read completes before accessing data (critical for ARM)
        READ_BARRIER();

        size_t available = readable();

        if (__builtin_expect(available == 0, 0)) {
            *available_len = 0;
            return nullptr;
        }

        // Return pointer to readable data
        const uint8_t* data = buffer_ + read_pos_;

        // Prefetch next cache line(s) immediately
        if (__builtin_expect(available > CACHE_LINE_SIZE, 1)) {
            prefetch_read(data + CACHE_LINE_SIZE);

            // For large available data, prefetch further ahead
            if (__builtin_expect(available > 256, 1)) {
                prefetch_read(data + 256);
            }
        }

        if (__builtin_expect(is_mirrored_, LIKELY_MIRRORED)) {
            // Mirrored buffer: always contiguous, no wraparound logic!
            *available_len = available;
        } else {
            // Non-mirrored: need to handle wraparound
            if (__builtin_expect(write_pos_ >= read_pos_, 1)) {
                // Contiguous data (common case)
                *available_len = write_pos_ - read_pos_;
            } else {
                // Wrapped around - return first contiguous chunk
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

        // Optimized: bitwise AND instead of expensive modulo
        read_pos_ = (read_pos_ + len) & (Capacity - 1);
    }

    // Get number of bytes available for reading (hot function - inlined)
    inline size_t readable() const {
        size_t w = write_pos_;
        size_t r = read_pos_;

        // Branchless calculation using power-of-2 wraparound
        return (w - r) & (Capacity - 1);
    }

    // Get number of bytes available for writing (hot function - inlined)
    inline size_t writable() const {
        size_t w = write_pos_;
        size_t r = read_pos_;

        // Branchless calculation using power-of-2 wraparound
        // Always reserve 1 byte to distinguish full from empty
        return (r - w - 1) & (Capacity - 1);
    }

    // Reset buffer to empty state
    void reset() {
        read_pos_ = 0;
        write_pos_ = 0;
    }

    // Get total capacity (compile-time constant)
    constexpr size_t capacity() const {
        return Capacity;
    }

    // Query mirroring status
    bool is_mirrored() const {
        return is_mirrored_;
    }

    // Query mmap status
    bool is_mmap() const {
        return is_mmap_;
    }

    // Compile-time trait for buffer type detection (false for standard RingBuffer)
    static constexpr bool is_hftshm = false;

    // === Circular buffer interface (compatibility with HftShmRingBuffer) ===
    // These methods enable code to work with both RingBuffer and HftShmRingBuffer

    // Get buffer base pointer for circular access
    uint8_t* buffer_base() { return buffer_; }
    const uint8_t* buffer_base() const { return buffer_; }

    // Get buffer capacity (same as capacity(), but matches HftShmRingBuffer API)
    size_t buffer_capacity() const { return Capacity; }

    // Get current write position (masked to buffer size)
    size_t current_write_pos() const { return write_pos_; }

    // Get current read position (masked to buffer size)
    size_t current_read_pos() const { return read_pos_; }

    // Disable copy and move
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

private:
    // Software prefetch helpers
    static inline void prefetch_read(const void* addr) {
#if defined(__x86_64__) || defined(__i386__)
        _mm_prefetch(static_cast<const char*>(addr), _MM_HINT_T0);  // Prefetch to L1
#elif defined(__aarch64__)
        __asm__ __volatile__("prfm pldl1keep, [%0]" : : "r"(addr));
#else
        __builtin_prefetch(addr, 0, 3);  // GCC/Clang generic
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

    // Try to create virtual memory mirroring for zero-wraparound ringbuffer
    // Returns 0 on success, -1 on failure
    int try_create_mirrored_buffer() {
#if defined(__APPLE__) || defined(__linux__)
        // Step 1: Reserve virtual address space (2x size)
        void* addr = mmap(nullptr, 2 * Capacity, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            return -1;
        }

        // Step 2: Create shared memory
        int fd;
#ifdef __APPLE__
        // macOS: Use temporary file for shared memory
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
        shm_unlink(shm_name);  // Unlink immediately
#else
        // Linux: Use memfd_create if available, otherwise shm_open
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

        // Step 3: Size the shared memory
        if (ftruncate(fd, Capacity) != 0) {
            close(fd);
            munmap(addr, 2 * Capacity);
            return -1;
        }

        // Step 4: Map first half
        void* addr1 = mmap(addr, Capacity, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_SHARED, fd, 0);
        if (addr1 == MAP_FAILED || addr1 != addr) {
            close(fd);
            munmap(addr, 2 * Capacity);
            return -1;
        }

        // Step 5: Map second half (same physical memory)
        void* addr2 = mmap(static_cast<uint8_t*>(addr) + Capacity, Capacity,
                           PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0);
        if (addr2 == MAP_FAILED || addr2 != static_cast<uint8_t*>(addr) + Capacity) {
            // Unmap the full original reservation (both halves)
            munmap(addr, 2 * Capacity);
            close(fd);
            return -1;
        }

        // Success!
        close(fd);

        buffer_ = static_cast<uint8_t*>(addr);
        is_mmap_ = true;
        is_mirrored_ = true;

        return 0;
#else
        return -1;  // Not supported on this platform
#endif
    }

    //
    // === PRODUCER-OWNED CACHE LINE ===
    //
    uint8_t* buffer_;       // Buffer pointer (shared read-only after init)
    size_t write_pos_;      // Producer writes frequently
    bool is_mmap_;          // Initialization only (read-only after init)
    bool is_mirrored_;      // Virtual memory mirroring enabled (read-only after init)
    bool is_external_;      // True if buffer is external (shared memory, don't free)

    // Padding to next cache line boundary
    alignas(CACHE_LINE_SIZE) char _pad_producer[CACHE_LINE_SIZE - sizeof(uint8_t*) - sizeof(size_t) - 3*sizeof(bool)];

    //
    // === CONSUMER-OWNED CACHE LINE ===
    //
    alignas(CACHE_LINE_SIZE) size_t read_pos_;  // Consumer writes frequently

    // Padding to ensure no false sharing after read_pos
    char _pad_consumer[CACHE_LINE_SIZE - sizeof(size_t)];

} __attribute__((aligned(CACHE_LINE_SIZE)));

// Convenience aliases for common buffer sizes (all power-of-2)
using RingBuffer1MB  = RingBuffer<1u << 20>;   // 1,048,576 bytes
using RingBuffer2MB  = RingBuffer<1u << 21>;   // 2,097,152 bytes
using RingBuffer4MB  = RingBuffer<1u << 22>;   // 4,194,304 bytes
using RingBuffer8MB  = RingBuffer<1u << 23>;   // 8,388,608 bytes
using RingBuffer16MB = RingBuffer<1u << 24>;   // 16,777,216 bytes
