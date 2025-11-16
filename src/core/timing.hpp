// core/timing.hpp
// High-resolution timing infrastructure for latency measurement
// Records timestamps from NIC hardware to application callback
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <cerrno>
#include <cstdlib>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <linux/sockios.h>
#endif

// Timestamp recording structure
// Captures timing at 6 stages from network to application
typedef struct {
    uint64_t hw_timestamp_ns;       // Stage 1: NIC RX timestamp (CLOCK_MONOTONIC ns, 0 if unsupported)
    uint64_t event_cycle;           // Stage 2: Event loop start (TSC cycles)
    uint64_t recv_start_cycle;      // Stage 3: Before SSL_read/recv call (TSC cycles)
    uint64_t recv_end_cycle;        // Stage 4: When SSL_read/recv completed (TSC cycles)
    uint64_t frame_parsed_cycle;    // Stage 5: When frame parsing completed (TSC cycles)
    // Stage 6: Implemented in user callback - records both CPU cycle and CLOCK_MONOTONIC
    size_t payload_len;
    uint8_t opcode;
} timing_record_t;

// Read CPU Time Stamp Counter (TSC) - x86/x64 only
// Returns CPU cycles since boot (not wall clock time)
// Serialized version for more accurate measurement
static inline uint64_t rdtsc() {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__(
        "lfence\n\t"           // Serialize before reading
        "rdtsc\n\t"            // Read timestamp counter
        : "=a"(lo), "=d"(hi)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__(
        "isb\n\t"              // Instruction synchronization barrier
        "mrs %0, cntvct_el0"   // Read virtual count register
        : "=r"(val)
    );
    return val;
#else
    // Fallback: use clock_gettime (much slower)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// Read TSC at the end of a critical section
// Uses RDTSCP for better accuracy (reads after all previous instructions complete)
static inline uint64_t rdtscp() {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    uint32_t aux;  // Processor ID
    __asm__ __volatile__(
        "rdtscp\n\t"           // Read timestamp counter and processor ID
        "lfence\n\t"           // Serialize after reading
        : "=a"(lo), "=d"(hi), "=c"(aux)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
#else
    return rdtsc();  // Fall back to rdtsc on non-x86
#endif
}

// Convert TSC cycles to nanoseconds
// Requires TSC frequency in Hz (can be obtained from /proc/cpuinfo or calibration)
static inline uint64_t cycles_to_ns(uint64_t cycles, uint64_t tsc_freq_hz) {
    if (tsc_freq_hz == 0) return 0;
    return (cycles * 1000000000ULL) / tsc_freq_hz;
}

// Get current monotonic timestamp in nanoseconds
// This is used for Stage 1 timing (kernel wakeup)
static inline uint64_t get_monotonic_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Calculate TSC frequency by measuring over a short period
// Returns TSC frequency in Hz
// Note: This is a simple calibration; for production use a more accurate method
static inline uint64_t calibrate_tsc_freq() {
#if defined(__linux__)
    // On Linux, try to read from /sys/devices/system/cpu/cpu0/tsc_freq_khz
    FILE* f = fopen("/sys/devices/system/cpu/cpu0/tsc_freq_khz", "r");
    if (f) {
        uint64_t freq_khz = 0;
        if (fscanf(f, "%lu", &freq_khz) == 1) {
            fclose(f);
            return freq_khz * 1000;
        }
        fclose(f);
    }
#endif

    // Fallback: measure over 100ms
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    uint64_t tsc_start = rdtsc();

    // Busy wait for 100ms
    struct timespec req = {0, 100000000};  // 100ms
    nanosleep(&req, nullptr);

    uint64_t tsc_end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL +
                         (end.tv_nsec - start.tv_nsec);
    uint64_t tsc_elapsed = tsc_end - tsc_start;

    return (tsc_elapsed * 1000000000ULL) / elapsed_ns;
}

// Enable hardware timestamping on a socket
// Requests hardware timestamps from NIC (if supported)
// Returns true on success, false on failure
static inline bool enable_hw_timestamping(int sockfd) {
#ifdef __linux__
    // Step 1: Configure NIC hardware to capture RX timestamps
    struct hwtstamp_config hwconfig;
    memset(&hwconfig, 0, sizeof(hwconfig));
    hwconfig.tx_type = HWTSTAMP_TX_OFF;  // We only care about RX
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;  // Timestamp all incoming packets

    // Make NIC interface configurable via environment variable
    const char* nic_interface = getenv("WS_NIC_INTERFACE");
    if (!nic_interface) {
        nic_interface = "enp108s0";  // Default fallback
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", nic_interface);
    ifr.ifr_data = (char*)&hwconfig;

    if (ioctl(sockfd, SIOCSHWTSTAMP, &ifr) < 0) {
        printf("[TIMESTAMP] Warning: Failed to configure NIC hardware timestamping on %s: %s\n",
               nic_interface, strerror(errno));
        printf("[TIMESTAMP] Continuing anyway - timestamps may not be available\n");
        printf("[TIMESTAMP] Tip: Set WS_NIC_INTERFACE env var to your network interface name\n");
    } else {
        printf("[TIMESTAMP] Configured NIC %s for hardware RX timestamping\n", nic_interface);
    }

    // Step 2: Request hardware timestamping on socket
    // SOF_TIMESTAMPING_RX_HARDWARE: Hardware RX timestamp from NIC
    // SOF_TIMESTAMPING_SOFTWARE: Transforms hardware timestamp to system clock (CLOCK_REALTIME)
    // SOF_TIMESTAMPING_RAW_HARDWARE: Use raw hardware clock (required for some NICs)
    int flags = SOF_TIMESTAMPING_RX_HARDWARE |
                SOF_TIMESTAMPING_SOFTWARE |
                SOF_TIMESTAMPING_RAW_HARDWARE;

    if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) == 0) {
        printf("[TIMESTAMP] Enabled hardware timestamping on socket\n");
        return true;
    }

    // Hardware timestamping failed
    printf("[TIMESTAMP] Failed to enable timestamping: %s\n", strerror(errno));
    return false;
#else
    (void)sockfd;
    return false;  // Not supported on non-Linux platforms
#endif
}

// Extract RX hardware/software timestamp from socket and convert to CLOCK_MONOTONIC
// Attempts to retrieve timestamp from when packet arrived at NIC/kernel
// Returns timestamp in CLOCK_MONOTONIC nanoseconds, or 0 if not available
static inline uint64_t extract_hw_timestamp(int sockfd) {
#ifdef __linux__
    char control[512];
    char data[2048];  // Buffer for peeking at socket data
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));

    iov.iov_base = data;
    iov.iov_len = sizeof(data);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    // Capture current time for REALTIME to MONOTONIC conversion
    struct timespec now_real, now_mono;
    clock_gettime(CLOCK_REALTIME, &now_real);
    clock_gettime(CLOCK_MONOTONIC, &now_mono);

    // Approach 1: Try MSG_ERRQUEUE (for TX timestamps, but worth checking)
    ssize_t ret = recvmsg(sockfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    if (ret >= 0) {
        // Parse control messages to find timestamp
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);

                // SO_TIMESTAMPING returns 3 timestamps: software, deprecated, hardware
                // Since we're using HARDWARE-ONLY mode, only check index 2
                struct timespec rx_ts = ts[2];  // Hardware timestamp (index 2)

                if (rx_ts.tv_sec > 0 || rx_ts.tv_nsec > 0) {
                    // Convert CLOCK_REALTIME to CLOCK_MONOTONIC
                    // Formula: monotonic = (realtime_rx - realtime_now) + monotonic_now
                    int64_t real_rx_ns = (int64_t)rx_ts.tv_sec * 1000000000LL + rx_ts.tv_nsec;
                    int64_t real_now_ns = (int64_t)now_real.tv_sec * 1000000000LL + now_real.tv_nsec;
                    int64_t mono_now_ns = (int64_t)now_mono.tv_sec * 1000000000LL + now_mono.tv_nsec;

                    int64_t mono_rx_ns = mono_now_ns + (real_rx_ns - real_now_ns);

                    return (mono_rx_ns > 0) ? (uint64_t)mono_rx_ns : 0;
                }
            }
        }
    }

    // Approach 2: Try normal recvmsg with MSG_PEEK to get ancillary data without consuming
    // This might work for RX timestamps before SSL_read() processes the data
    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    ret = recvmsg(sockfd, &msg, MSG_PEEK | MSG_DONTWAIT);
    if (ret >= 0) {
        // Parse control messages for RX timestamp
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);

                // With SOFTWARE + RX_HARDWARE + RAW_HARDWARE:
                //   ts[0]: Hardware timestamp transformed to CLOCK_REALTIME
                //   ts[2]: Raw hardware timestamp in PTP clock domain
                // We use ts[0] as it's already in system clock domain
                struct timespec rx_ts = ts[0];

                if (rx_ts.tv_sec > 0 || rx_ts.tv_nsec > 0) {
                    // Convert CLOCK_REALTIME to CLOCK_MONOTONIC
                    int64_t real_rx_ns = (int64_t)rx_ts.tv_sec * 1000000000LL + rx_ts.tv_nsec;
                    int64_t real_now_ns = (int64_t)now_real.tv_sec * 1000000000LL + now_real.tv_nsec;
                    int64_t mono_now_ns = (int64_t)now_mono.tv_sec * 1000000000LL + now_mono.tv_nsec;

                    int64_t mono_rx_ns = mono_now_ns + (real_rx_ns - real_now_ns);

                    return (mono_rx_ns > 0) ? (uint64_t)mono_rx_ns : 0;
                }
            }
        }
    }

    return 0;  // Timestamp not available
#else
    (void)sockfd;
    return 0;  // Not supported on non-Linux platforms
#endif
}

// Pretty print timing record
static inline void print_timing_record(const timing_record_t& tr, uint64_t tsc_freq_hz) {
    printf("Timing Record:\n");
    printf("  Payload length: %zu bytes, Opcode: 0x%02x\n", tr.payload_len, tr.opcode);

    if (tr.hw_timestamp_ns > 0) {
        // Convert CLOCK_MONOTONIC (boot time) to wall clock time
        struct timespec mono_ts;
        mono_ts.tv_sec = tr.hw_timestamp_ns / 1000000000ULL;
        mono_ts.tv_nsec = tr.hw_timestamp_ns % 1000000000ULL;

        // Get current monotonic and realtime to calculate offset
        struct timespec now_mono, now_real;
        clock_gettime(CLOCK_MONOTONIC, &now_mono);
        clock_gettime(CLOCK_REALTIME, &now_real);

        // Calculate wall clock time for this timestamp
        int64_t mono_diff_ns = ((int64_t)now_mono.tv_sec - mono_ts.tv_sec) * 1000000000LL +
                               ((int64_t)now_mono.tv_nsec - mono_ts.tv_nsec);
        int64_t wall_sec = now_real.tv_sec - (mono_diff_ns / 1000000000LL);
        int64_t wall_nsec = now_real.tv_nsec - (mono_diff_ns % 1000000000LL);

        if (wall_nsec < 0) {
            wall_sec--;
            wall_nsec += 1000000000LL;
        }

        // Format wall clock time
        time_t t = wall_sec;
        struct tm* tm_info = localtime(&t);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        // Note: This could be either hardware NIC timestamp or software timestamp
        // depending on what was successfully retrieved
        printf("  [Stage 1] RX timestamp: %s.%09lu\n",
               time_str, (unsigned long)wall_nsec);
        printf("            Monotonic time: %.6f s since boot\n",
               tr.hw_timestamp_ns / 1e9);
    } else {
        printf("  [Stage 1] RX timestamp: Not recorded\n");
    }

    printf("\n  [Stage 2] Event loop:   %lu cycles", tr.event_cycle);
    if (tsc_freq_hz > 0 && tr.event_cycle > 0) {
        // Use floating point division to avoid overflow with large absolute cycle values
        double stage2_time_s = (double)tr.event_cycle / (double)tsc_freq_hz;
        printf(" (%.6f s since boot)\n", stage2_time_s);
    } else {
        printf("\n");
    }

    printf("  [Stage 3] Recv start:   %lu cycles", tr.recv_start_cycle);
    if (tsc_freq_hz > 0 && tr.recv_start_cycle > 0 && tr.event_cycle > 0) {
        uint64_t delta = tr.recv_start_cycle - tr.event_cycle;
        printf(" → Δ%.3f μs\n", cycles_to_ns(delta, tsc_freq_hz) / 1000.0);
    } else {
        printf("\n");
    }

    printf("  [Stage 4] SSL read end: %lu cycles", tr.recv_end_cycle);
    if (tsc_freq_hz > 0 && tr.recv_end_cycle > 0 && tr.recv_start_cycle > 0) {
        uint64_t delta = tr.recv_end_cycle - tr.recv_start_cycle;
        printf(" → Δ%.3f μs (SSL decryption)\n", cycles_to_ns(delta, tsc_freq_hz) / 1000.0);
    } else {
        printf("\n");
    }

    printf("  [Stage 5] Frame parsed: %lu cycles", tr.frame_parsed_cycle);
    if (tsc_freq_hz > 0 && tr.frame_parsed_cycle > 0 && tr.recv_end_cycle > 0) {
        uint64_t delta = tr.frame_parsed_cycle - tr.recv_end_cycle;
        printf(" → Δ%.3f μs (WebSocket parsing)\n", cycles_to_ns(delta, tsc_freq_hz) / 1000.0);
    } else {
        printf("\n");
    }

    printf("  [Stage 6] Callback:     Implemented in user callback\n");
}
