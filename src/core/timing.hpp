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
// Captures timing at multiple stages from NIC hardware to application callback
typedef struct {
    // Stage 1: NIC HW timestamps (CLOCK_REALTIME converted to CLOCK_MONOTONIC ns)
    uint64_t hw_timestamp_oldest_ns;  // Oldest packet timestamp in queue (first arrival)
    uint64_t hw_timestamp_latest_ns;  // Latest packet timestamp in queue (most recent arrival)
    uint32_t hw_timestamp_count;      // Number of packets with timestamps found in queue
    uint64_t hw_timestamp_byte_count; // Total bytes polled from NIC (for stats display)

    // Stage 1.5: BPF entry timestamps (CLOCK_MONOTONIC ns, from bpf_ktime_get_ns())
    uint64_t bpf_entry_oldest_ns;     // BPF entry timestamp of first packet
    uint64_t bpf_entry_latest_ns;     // BPF entry timestamp of latest packet

    // Stage 2: XDP Poll cycles (TSC rdtscp when userspace polled packet)
    uint64_t poll_cycle_oldest;       // XDP Poll rdtscp of first packet
    uint64_t poll_cycle_latest;       // XDP Poll rdtscp of latest packet

    // UMEM frame indices (0..32767)
    uint16_t oldest_pkt_mem_idx;      // UMEM frame index of oldest packet
    uint16_t latest_pkt_mem_idx;      // UMEM frame index of latest packet

    // Stage 3-4: SSL read
    uint64_t recv_start_cycle;        // Stage 3: Before SSL_read/recv call (TSC cycles)
    uint64_t recv_end_cycle;          // Stage 4: When SSL_read/recv completed (TSC cycles)
    ssize_t ssl_read_bytes;           // Bytes returned by SSL_read (for stats display)

    // Stage 5: Frame parsing
    uint64_t frame_parsed_cycle;      // When frame parsing completed (TSC cycles)

    size_t payload_len;
    uint8_t opcode;                   // WebSocket frame opcode (0x01=text, 0x02=binary, 0x08=close, 0x09=ping, 0x0A=pong)
} timing_record_t;

// Per-message info in a batch callback
// Each message has its own parse timestamp, but shares batch-level SSL timing
struct MessageInfo {
    const uint8_t* payload;   // Pointer to message payload (zero-copy)
    size_t len;               // Payload length in bytes
    uint64_t parse_cycle;     // Stage 5: TSC when this frame was parsed
    uint8_t opcode;           // 0x01=text, 0x02=binary
};

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

// Drain all RX hardware/software timestamps from socket and collect metrics
// Drains the entire MSG_ERRQUEUE to prevent stale timestamp accumulation
// Populates timing_record_t with oldest, latest, and count of timestamps found
static inline void drain_hw_timestamps(int sockfd, timing_record_t* timing) {
#ifdef __linux__
    uint64_t oldest_ts_ns = 0;
    uint64_t latest_ts_ns = 0;
    uint32_t count = 0;

    // Capture current time for REALTIME to MONOTONIC conversion
    struct timespec now_real, now_mono;
    clock_gettime(CLOCK_REALTIME, &now_real);
    clock_gettime(CLOCK_MONOTONIC, &now_mono);

    int64_t real_now_ns = (int64_t)now_real.tv_sec * 1000000000LL + now_real.tv_nsec;
    int64_t mono_now_ns = (int64_t)now_mono.tv_sec * 1000000000LL + now_mono.tv_nsec;

    // Approach 1: Drain entire MSG_ERRQUEUE to prevent timestamp accumulation
    // This queue can build up multiple packets' timestamps over time
    while (true) {
        char control[512];
        char data[2048];
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

        ssize_t ret = recvmsg(sockfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (ret < 0) break;  // Queue drained or error

        // Parse control messages to find timestamp
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);

                // SO_TIMESTAMPING returns 3 timestamps:
                //   ts[0]: Hardware timestamp transformed to CLOCK_REALTIME (or software fallback)
                //   ts[1]: Deprecated
                //   ts[2]: Raw hardware timestamp in PTP clock domain
                // We use ts[0] as it's already in system clock domain
                struct timespec rx_ts = ts[0];

                if (rx_ts.tv_sec > 0 || rx_ts.tv_nsec > 0) {
                    // Convert CLOCK_REALTIME to CLOCK_MONOTONIC
                    // Formula: monotonic = (realtime_rx - realtime_now) + monotonic_now
                    int64_t real_rx_ns = (int64_t)rx_ts.tv_sec * 1000000000LL + rx_ts.tv_nsec;
                    int64_t mono_rx_ns = mono_now_ns + (real_rx_ns - real_now_ns);

                    if (mono_rx_ns > 0) {
                        uint64_t ts_ns = (uint64_t)mono_rx_ns;

                        if (count == 0) {
                            // First timestamp found
                            oldest_ts_ns = ts_ns;
                            latest_ts_ns = ts_ns;
                        } else {
                            // Track oldest and latest
                            if (ts_ns < oldest_ts_ns) oldest_ts_ns = ts_ns;
                            if (ts_ns > latest_ts_ns) latest_ts_ns = ts_ns;
                        }
                        count++;
                    }
                }
            }
        }
    }

    // Approach 2: If no timestamps in errqueue, try MSG_PEEK for immediate RX timestamp
    // This gets timestamp for the next packet to be read without consuming it
    if (count == 0) {
        char control[512];
        char data[2048];
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

        ssize_t ret = recvmsg(sockfd, &msg, MSG_PEEK | MSG_DONTWAIT);
        if (ret >= 0) {
            // Parse control messages for RX timestamp
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                    struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);
                    struct timespec rx_ts = ts[0];

                    if (rx_ts.tv_sec > 0 || rx_ts.tv_nsec > 0) {
                        int64_t real_rx_ns = (int64_t)rx_ts.tv_sec * 1000000000LL + rx_ts.tv_nsec;
                        int64_t mono_rx_ns = mono_now_ns + (real_rx_ns - real_now_ns);

                        if (mono_rx_ns > 0) {
                            oldest_ts_ns = latest_ts_ns = (uint64_t)mono_rx_ns;
                            count = 1;
                        }
                    }
                }
            }
        }
    }

    // Populate timing record
    timing->hw_timestamp_oldest_ns = oldest_ts_ns;
    timing->hw_timestamp_latest_ns = latest_ts_ns;
    timing->hw_timestamp_count = count;

#else
    (void)sockfd;
    // Not supported on non-Linux platforms
    timing->hw_timestamp_oldest_ns = 0;
    timing->hw_timestamp_latest_ns = 0;
    timing->hw_timestamp_count = 0;
#endif
}

// Pretty print timing record
static inline void print_timing_record(const timing_record_t& tr, uint64_t tsc_freq_hz) {
    printf("Timing Record:\n");
    printf("  Payload length: %zu bytes, Opcode: 0x%02x\n", tr.payload_len, tr.opcode);

    if (tr.hw_timestamp_count > 0) {
        printf("  [Stage 1] NIC HW Timestamps:\n");
        printf("            Packets timestamped: %u\n", tr.hw_timestamp_count);

        if (tr.hw_timestamp_oldest_ns > 0) {
            printf("            Oldest packet:  %.6f s since boot\n",
                   tr.hw_timestamp_oldest_ns / 1e9);
        }
        if (tr.hw_timestamp_latest_ns > 0) {
            printf("            Latest packet:  %.6f s since boot\n",
                   tr.hw_timestamp_latest_ns / 1e9);
        }
        if (tr.hw_timestamp_count > 1 && tr.hw_timestamp_latest_ns > tr.hw_timestamp_oldest_ns) {
            uint64_t queue_delay_ns = tr.hw_timestamp_latest_ns - tr.hw_timestamp_oldest_ns;
            printf("            Queue span:     %.3f us (oldest->latest)\n",
                   queue_delay_ns / 1000.0);
        }
    } else {
        printf("  [Stage 1] NIC HW timestamp: Not available\n");
    }

    if (tr.bpf_entry_latest_ns > 0) {
        printf("  [Stage 1.5] BPF entry:  %.6f s (MONOTONIC)\n",
               tr.bpf_entry_latest_ns / 1e9);
    }

    if (tr.poll_cycle_latest > 0) {
        printf("  [Stage 2] XDP Poll:     %lu cycles", tr.poll_cycle_latest);
        if (tsc_freq_hz > 0) {
            double stage2_time_s = (double)tr.poll_cycle_latest / (double)tsc_freq_hz;
            printf(" (%.6f s since boot)\n", stage2_time_s);
        } else {
            printf("\n");
        }
    }

    if (tsc_freq_hz > 0 && tr.poll_cycle_latest > 0 && tr.recv_start_cycle > tr.poll_cycle_latest) {
        printf("  [Stage 2->3] Poll->Recv: %.3f us\n",
               cycles_to_ns(tr.recv_start_cycle - tr.poll_cycle_latest, tsc_freq_hz) / 1000.0);
    }

    printf("  [Stage 3] Recv start:   %lu cycles\n", tr.recv_start_cycle);

    if (tsc_freq_hz > 0 && tr.recv_end_cycle > 0 && tr.recv_start_cycle > 0) {
        printf("  [Stage 3->4] SSL decrypt: %.3f us\n",
               cycles_to_ns(tr.recv_end_cycle - tr.recv_start_cycle, tsc_freq_hz) / 1000.0);
    }

    printf("  [Stage 4] SSL read end: %lu cycles\n", tr.recv_end_cycle);

    if (tsc_freq_hz > 0 && tr.frame_parsed_cycle > 0 && tr.recv_end_cycle > 0) {
        printf("  [Stage 4->5] WS parse:   %.3f us\n",
               cycles_to_ns(tr.frame_parsed_cycle - tr.recv_end_cycle, tsc_freq_hz) / 1000.0);
    }

    printf("  [Stage 5] Frame parsed: %lu cycles\n", tr.frame_parsed_cycle);
    printf("  [Stage 6] Callback:     Implemented in user callback\n");
}
