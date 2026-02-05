// pipeline/pipeline_data.hpp
// Data structures for inter-process communication
// All structs are cache-line aligned for zero-copy IPC
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <cmath>
#include <chrono>

#include "../core/timing.hpp"

// Disruptor IPC includes (MUST be before pipeline_config.hpp to avoid macro conflict)
#include <disruptor/src/ipc/shared_region.hpp>
#include <disruptor/src/core/ring_buffer.hpp>
#include <disruptor/src/core/sequence.hpp>
#include <disruptor/src/core/sequence_barrier.hpp>
#include <disruptor/src/core/event_processor.hpp>
#include <disruptor/src/policy/sequence_policy.hpp>
#include <disruptor/src/policy/storage_policy.hpp>
#include <disruptor/src/policy/memory_ordering_policy.hpp>
#include <disruptor/src/policy/wait_policy.hpp>
#include <disruptor/src/policy/batch_policy.hpp>
#include <disruptor/src/policy/error_policy.hpp>
#include <hftshm/layout.hpp>

#include "pipeline_config.hpp"
#include "../xdp/packet_frame_descriptor.hpp"

namespace websocket::pipeline {

// ============================================================================
// DisconnectReason - Tracks root cause of connection termination
// Used by ConnStateShm::disconnect for unified disconnect handling
// ============================================================================

enum class DisconnectReason : uint8_t {
    NONE = 0,
    TCP_RST,            // TCP RST received
    TCP_FIN,            // TCP FIN received (graceful close)
    WS_CLOSE,           // WebSocket CLOSE frame received
    WS_PONG_TIMEOUT,    // Dual watchdog: server PING missing + client PONG missing
    SSL_READ_ERROR,     // SSL_read returned fatal error
    UNKNOWN             // Loop exited for unknown reason
};

// ============================================================================
// UMEMFrameDescriptor - Type alias for PacketFrameDescriptor
// Used in RAW_INBOX/OUTBOX rings. Size: 64 bytes (1 per cache line)
// ============================================================================

using UMEMFrameDescriptor = websocket::xdp::PacketFrameDescriptor;

// ============================================================================
// MsgMetadata - Passed through MSG_METADATA_INBOX ring
// Size: 64 bytes (1 per cache line)
// Tracks timestamps from NIC through SSL_read
// ============================================================================

struct alignas(128) MsgMetadata {
    // Stage 1: NIC HW timestamps
    uint64_t first_nic_timestamp_ns;       // NIC HW timestamp of first packet
    uint64_t latest_nic_timestamp_ns;      // NIC HW timestamp of latest packet

    // Stage 1.5: BPF entry timestamps (CLOCK_MONOTONIC ns)
    uint64_t first_bpf_entry_ns;           // bpf_ktime_get_ns() of first packet
    uint64_t latest_bpf_entry_ns;          // bpf_ktime_get_ns() of latest packet

    // Stage 2: XDP Poll cycles (TSC rdtscp)
    uint64_t first_nic_frame_poll_cycle;   // XDP Poll rdtscp of first packet
    uint64_t latest_nic_frame_poll_cycle;  // XDP Poll rdtscp of latest packet

    // Stage 3-4: SSL read
    uint64_t ssl_read_start_cycle;         // Transport rdtsc BEFORE SSL_read()
    uint64_t ssl_read_end_cycle;           // Transport rdtscp AFTER SSL_read()

    // Batch correlation
    uint64_t ssl_read_id;                  // Monotonic SSL_read counter for batch correlation

    // Data location in MSG_INBOX
    uint32_t msg_inbox_offset;             // Start offset in MSG_INBOX buffer
    uint32_t decrypted_len;                // Length of decrypted data from this SSL_read

    // Packet counting
    uint32_t nic_packet_ct;                // Number of NIC packets in this SSL_read batch

    // Transport process last_op_cycle (TSC rdtscp before this SSL_read publish)
    uint64_t ssl_last_op_cycle;            // Transport's last_op_cycle_ before publish

    bool tls_record_end;                   // true if ssl_read ended at TLS record boundary
    uint8_t _pad[31];                      // Padding to 128 bytes

    void clear() {
        first_nic_timestamp_ns = 0;
        latest_nic_timestamp_ns = 0;
        first_bpf_entry_ns = 0;
        latest_bpf_entry_ns = 0;
        first_nic_frame_poll_cycle = 0;
        latest_nic_frame_poll_cycle = 0;
        ssl_read_start_cycle = 0;
        ssl_read_end_cycle = 0;
        ssl_read_id = 0;
        msg_inbox_offset = 0;
        decrypted_len = 0;
        nic_packet_ct = 0;
        ssl_last_op_cycle = 0;
        tls_record_end = false;
    }
};
static_assert(sizeof(MsgMetadata) == 128, "MsgMetadata must be 128 bytes");

// ============================================================================
// WSFrameInfo - Passed through WS_FRAME_INFO_RING to AppClient
// Size: 128 bytes (2 per cache line)
// Full timestamp chain from NIC to WS frame publish
//
// Layout (128 bytes):
//   offset  0: uint32_t msg_inbox_offset     (4)
//   offset  4: uint32_t payload_len          (4)
//   offset  8: uint8_t  opcode               (1)
//   offset  9: bool     is_fin               (1)
//   offset 10: bool     is_fragmented        (1)
//   offset 11: bool     is_last_fragment     (1)
//   offset 12: uint8_t  ssl_read_ct          (1)
//   offset 13: bool     is_tls_record_end   (1)
//   offset 14: uint16_t nic_packet_ct        (2)
//   offset 16: [10 x uint64_t fields]       (80) — publish_time_ts replaces first_ssl_read_end_cycle
//   offset 96: uint32_t ssl_read_batch_num  (4)
//   offset100: uint32_t ssl_read_total_bytes(4)
//   offset104: [3 x uint64_t timestamps]   (24)
//   offset128: total                        (128)
// ============================================================================

struct alignas(64) WSFrameInfo {
    // Location in MSG_INBOX - valid for ALL messages including partial frames
    uint32_t msg_inbox_offset;             // Start offset of THIS frame/fragment's payload
    uint32_t payload_len;                  // THIS frame/fragment's payload length

    // WebSocket frame info
    uint8_t  opcode;                       // WS opcode (TEXT=1, BINARY=2, PING=9, etc.)
    bool     is_fin;                       // FIN bit from WS header
    bool     is_fragmented;                // True if partial frame OR fragmented WS message
    bool     is_last_fragment;             // True if this is the final fragment/part

    // Each fragment generates a separate WSFrameInfo event immediately.
    // This allows AppClient to process fragments incrementally for lower latency.
    //
    // Fragment/partial handling:
    //   - is_fragmented=false: Complete single-frame message
    //   - is_fragmented=true, is_last_fragment=false: Partial frame or intermediate fragment
    //   - is_fragmented=true, is_last_fragment=true: Final fragment (message complete)

    // Counts (packed into header area)
    uint8_t  ssl_read_ct;                  // Number of SSL_read calls for this frame
    bool     is_tls_record_end;            // true if last frame in TLS record batch
    uint16_t nic_packet_ct;                // Number of NIC packets for this frame

    // Stage 1: NIC HW timestamps
    uint64_t first_byte_ts;                // NIC HW timestamp (first packet)
    uint64_t last_byte_ts;                 // NIC HW timestamp (latest packet)

    // Stage 1.5: BPF entry timestamps (CLOCK_MONOTONIC ns)
    uint64_t first_bpf_entry_ns;           // bpf_ktime_get_ns() (first packet)
    uint64_t latest_bpf_entry_ns;          // bpf_ktime_get_ns() (latest packet)

    // Stage 2: XDP Poll cycles (TSC rdtscp)
    uint64_t first_poll_cycle;             // XDP Poll rdtscp (first packet)
    uint64_t latest_poll_cycle;            // XDP Poll rdtscp (latest packet)

    // Stage 3-4: SSL read
    uint64_t first_ssl_read_start_cycle;   // Start cycle of first SSL_read for this frame
    uint64_t publish_time_ts;              // CLOCK_MONOTONIC ns at publish (for BPF comparison)
    uint64_t ssl_last_op_cycle;            // Transport/SSL layer's last_op_cycle before this read
    uint64_t latest_ssl_read_end_cycle;    // End cycle of latest SSL_read for this frame

    // Batch correlation
    uint32_t ssl_read_batch_num;           // 1-based index of this WS frame within SSL_read batch
    uint32_t ssl_read_total_bytes;         // Total decrypted bytes from the SSL_read batch
    uint64_t ws_last_op_cycle;             // WS process rdtscp after previous operation completed

    // Stage 5: WS parse
    uint64_t ws_parse_cycle;               // WS frame parse completion cycle

    // Stage 6: WS frame publish (stamped just before ring publish)
    uint64_t ws_frame_publish_cycle;       // rdtscp() immediately before publish()

    void clear() {
        msg_inbox_offset = 0;
        payload_len = 0;
        opcode = 0;
        is_fin = false;
        is_fragmented = false;
        is_last_fragment = false;
        ssl_read_ct = 0;
        is_tls_record_end = false;
        nic_packet_ct = 0;
        first_byte_ts = 0;
        last_byte_ts = 0;
        first_bpf_entry_ns = 0;
        latest_bpf_entry_ns = 0;
        first_poll_cycle = 0;
        latest_poll_cycle = 0;
        first_ssl_read_start_cycle = 0;
        publish_time_ts = 0;
        ssl_last_op_cycle = 0;
        latest_ssl_read_end_cycle = 0;
        ssl_read_batch_num = 0;
        ssl_read_total_bytes = 0;
        ws_last_op_cycle = 0;
        ws_parse_cycle = 0;
        ws_frame_publish_cycle = 0;
    }

    void print_timeline(uint64_t tsc_freq_hz,
                        uint64_t prev_publish_mono_ns = 0,
                        uint64_t prev_latest_poll_cycle = 0,
                        const uint8_t* payload_data = nullptr) const {
        uint64_t ref = ws_frame_publish_cycle;
        if (ref == 0) return;
        double to_us = 1e6 / static_cast<double>(tsc_freq_hz);
        auto before_pub = [&](uint64_t cycle) -> double {
            return (cycle > 0 && ref > cycle) ? static_cast<double>(ref - cycle) * to_us : 0.0;
        };
        // Range formatting: same unit (determined by larger value), unit only on second value
        auto fmt_range = [](char* b_first, char* b_last, double us_first, double us_last) {
            double larger = std::max(us_first, us_last);
            if (larger < 1000.0) {
                std::snprintf(b_first, 16, "%5.1f",   us_first);
                std::snprintf(b_last,  16, "%5.1fus",  us_last);
            } else if (larger < 1000000.0) {
                std::snprintf(b_first, 16, "%5.1f",   us_first / 1000.0);
                std::snprintf(b_last,  16, "%5.1fms",  us_last / 1000.0);
            } else {
                std::snprintf(b_first, 16, "%5.2f",   us_first / 1000000.0);
                std::snprintf(b_last,  16, "%5.2fs",   us_last / 1000000.0);
            }
        };
        // Single value (with unit)
        auto fmt = [](char* b, double us) {
            double a = std::fabs(us);
            if (a < 1000.0)        std::snprintf(b, 16, "%5.1fus", us);
            else if (a < 1000000.0) std::snprintf(b, 16, "%5.1fms", us / 1000.0);
            else                    std::snprintf(b, 16, "%5.2fs",  us / 1000000.0);
        };
        char bpf_prefix[80] = "";
        bool is_batch_continuation = (ssl_read_batch_num > 1);
        bool is_chunk_mode = ssl_read_ct > 0 &&
                             (ssl_read_total_bytes / ssl_read_ct) < NIC_MTU;
        bool use_latest_ref = is_chunk_mode || nic_packet_ct > 1;
        uint64_t bpf_ref_ns = (use_latest_ref && latest_bpf_entry_ns > 0)
                               ? latest_bpf_entry_ns : first_bpf_entry_ns;
        if (bpf_ref_ns > 0 && publish_time_ts > 0) {
            double bpf_us = static_cast<double>(publish_time_ts - bpf_ref_ns) / 1000.0;

            bool is_new_packet = (prev_latest_poll_cycle == 0 ||
                                  latest_poll_cycle != prev_latest_poll_cycle);
            if (is_new_packet && prev_publish_mono_ns > 0) {
                double interval_us =
                    static_cast<double>(static_cast<int64_t>(bpf_ref_ns - prev_publish_mono_ns)) / 1000.0;
                char iv[16], bv[16];
                fmt(bv, bpf_us);
                if (interval_us >= 0) {
                    fmt(iv, interval_us);
                    std::snprintf(bpf_prefix, sizeof(bpf_prefix), "%7s empty| bpf %7s ", iv, bv);
                } else {
                    fmt(iv, -interval_us);
                    std::snprintf(bpf_prefix, sizeof(bpf_prefix), "\033[31m%7s block\033[0m| bpf %7s ", iv, bv);
                }
            } else {
                char bv[16];
                fmt(bv, bpf_us);
                std::snprintf(bpf_prefix, sizeof(bpf_prefix), "             | bpf %7s ", bv);
            }
        } else {
            std::snprintf(bpf_prefix, sizeof(bpf_prefix), "             |             ");
        }

        // Stages before publish: poll -> ssl -> parse -> publish(0)
        char t[5][16];
        fmt_range(t[0], t[1], before_pub(first_poll_cycle), before_pub(latest_poll_cycle));
        fmt_range(t[2], t[3], before_pub(first_ssl_read_start_cycle), before_pub(latest_ssl_read_end_cycle));
        fmt(t[4], before_pub(ws_parse_cycle));
        // Total poll-to-publish latency
        double total_us = use_latest_ref ? before_pub(latest_poll_cycle) : before_pub(first_poll_cycle);
        char tot[16];
        fmt(tot, total_us);
        char sz[24];
        int n = std::snprintf(sz, sizeof(sz), "%u/%u%s", payload_len, ssl_read_total_bytes,
                              is_tls_record_end ? "\xe2\x88\x9a" : "");
        // √ is 3 bytes UTF-8 but 1 display char; pad to 10 display chars
        int display_len = n - (is_tls_record_end ? 2 : 0);
        while (display_len < 10 && n < (int)sizeof(sz) - 1) {
            sz[n++] = ' ';
            display_len++;
        }
        sz[n] = '\0';
        char late[160] = "";
        int late_pos = 0;
        double ns_per_cycle = (tsc_freq_hz > 0) ? 1e9 / static_cast<double>(tsc_freq_hz) : 0.0;
        auto append_late = [&](const char* label, double us) {
            char v[16];
            fmt(v, us);
            late_pos += std::snprintf(late + late_pos, sizeof(late) - late_pos,
                " \033[31m%s %s\033[0m", label, v);
        };
        // main_late: to_time(ws_last_op_cycle) - poll_ref (skip for batch continuations)
        uint64_t late_ref_cycle = is_chunk_mode ? latest_poll_cycle : first_poll_cycle;
        if (!is_batch_continuation && ws_last_op_cycle > 0 && late_ref_cycle > 0 && first_bpf_entry_ns > 0 && ns_per_cycle > 0.0) {
            double main_late_ns = static_cast<double>(static_cast<int64_t>(ws_last_op_cycle - late_ref_cycle)) * ns_per_cycle;
            double main_late_us = main_late_ns / 1000.0;
            if (main_late_us > 0.0) append_late("main_late", main_late_us);
        }
        // ssl_late: to_time(ssl_last_op_cycle) - poll_ref
        if (ssl_last_op_cycle > 0 && late_ref_cycle > 0 && first_bpf_entry_ns > 0 && ns_per_cycle > 0.0) {
            double ssl_late_ns = static_cast<double>(static_cast<int64_t>(ssl_last_op_cycle - late_ref_cycle)) * ns_per_cycle;
            double ssl_late_us = ssl_late_ns / 1000.0;
            if (ssl_late_us > 0.0) append_late("ssl_late", ssl_late_us);
        }
        // ws_late: ws_last_op_cycle - latest_ssl_read_end_cycle
        if (!is_batch_continuation && ws_last_op_cycle > 0 && latest_ssl_read_end_cycle > 0 && ns_per_cycle > 0.0) {
            double ws_late_ns = static_cast<double>(static_cast<int64_t>(ws_last_op_cycle - latest_ssl_read_end_cycle)) * ns_per_cycle;
            double ws_late_us = ws_late_ns / 1000.0;
            if (ws_late_us > 0.0) append_late("ws_late", ws_late_us);
        }
        // Parse Binance "E" (event time) from payload for clock skew display
        char exch_diff[24] = "";
        if (opcode == 0x01 && payload_data != nullptr && payload_len > 10) {
            const char* p = reinterpret_cast<const char*>(payload_data);
            const char* p_end = p + payload_len;
            for (const char* s = p; s + 4 < p_end; ++s) {
                if (s[0] == '"' && s[1] == 'E' && s[2] == '"' && s[3] == ':') {
                    const char* d = s + 4;
                    int64_t e_ms = 0;
                    while (d < p_end && *d >= '0' && *d <= '9') {
                        e_ms = e_ms * 10 + (*d - '0');
                        ++d;
                    }
                    if (e_ms > 1000000000000LL) {  // sanity: after 2001
                        struct timespec rts;
                        clock_gettime(CLOCK_REALTIME, &rts);
                        int64_t local_ms = static_cast<int64_t>(rts.tv_sec) * 1000LL
                                         + rts.tv_nsec / 1000000LL;
                        int64_t diff = local_ms - e_ms;
                        std::snprintf(exch_diff, sizeof(exch_diff), " %+ldms", diff);
                    }
                    break;
                }
            }
        }
        const char* line_color = is_tls_record_end ? "\033[34m" : "";
        const char* line_reset = is_tls_record_end ? "\033[0m" : "";
        fprintf(stderr,
                "%s%s"
                "| poll %u pkt %5s ~ %7s "
                "| ssl %u %s %5s ~ %7s "
                "| WS %3u %7s "
                "| TTL %7s |%s%s%s\n",
                line_color, bpf_prefix,
                nic_packet_ct, t[0], t[1],
                ssl_read_ct, sz, t[2], t[3],
                ssl_read_batch_num, t[4], tot, late, exch_diff, line_reset);
    }
};
static_assert(sizeof(WSFrameInfo) == 128, "WSFrameInfo must be 128 bytes");

// ============================================================================
// PongFrameAligned - Pre-framed PONG data passed through PONGS ring
// Size: 128 bytes
// Contains fully-built WebSocket PONG frame (header + masked payload)
// Built by WebSocket Process, Transport just encrypts and sends
// Max frame size: 2 + 4 + 125 = 131 bytes (but we use 128 for alignment)
// ============================================================================

struct alignas(64) PongFrameAligned {
    uint8_t  data[125];               // Pre-framed WS PONG (header + masked payload)
    uint8_t  data_len;                // Actual frame length (header + payload)
    uint8_t  _pad[2];

    void clear() {
        data_len = 0;
    }

    // Set pre-framed PONG data (already includes WS header and masking)
    void set(const uint8_t* frame_data, size_t len) {
        data_len = static_cast<uint8_t>(len > 125 ? 125 : len);
        if (data_len > 0) {
            std::memcpy(data, frame_data, data_len);
        }
    }
};
static_assert(sizeof(PongFrameAligned) == 128, "PongFrameAligned must be 128 bytes");

// ============================================================================
// MsgOutboxEvent - Pre-framed TX data through MSG_OUTBOX
// Size: 2KB (to fit large messages including protocol framing)
// Transport is protocol-agnostic - this contains fully-framed data from upstream
// ============================================================================

struct alignas(2048) MsgOutboxEvent {
    // Pre-framed message data (includes any protocol headers like WS frame header)
    // Built by upstream process (e.g., WebSocket Process builds WS frames)
    uint8_t  data[2044];              // Pre-framed data (fits within 2KB total)
    uint16_t data_len;                // Actual data length
    uint8_t  msg_type;                // MSG_TYPE_DATA or MSG_TYPE_CLOSE
    uint8_t  _pad;

    void clear() {
        data_len = 0;
        msg_type = MSG_TYPE_DATA;
    }

    // Set pre-framed data (already includes protocol headers)
    bool set(const uint8_t* frame_data, size_t len) {
        if (len > sizeof(data)) return false;
        std::memcpy(data, frame_data, len);
        data_len = static_cast<uint16_t>(len);
        msg_type = MSG_TYPE_DATA;
        return true;
    }

    // Signal close to Transport (Transport will send FIN)
    void set_close() {
        data_len = 0;
        msg_type = MSG_TYPE_WS_CLOSE;
    }
};
static_assert(sizeof(MsgOutboxEvent) == 2048, "MsgOutboxEvent must be 2048 bytes");

// ============================================================================
// ProcessId - Identifies each pipeline process for running flags
// ============================================================================

enum ProcessId : uint8_t {
    PROC_XDP_POLL   = 0,
    PROC_TRANSPORT  = 1,
    PROC_WEBSOCKET  = 2,
    PROC_APPCLIENT  = 3,
    PROC_COUNT      = 4
};

// ============================================================================
// PaddedRunning - Cache-line-padded running flag (avoids false sharing)
// ============================================================================

struct alignas(CACHE_LINE_SIZE) PaddedRunning {
    std::atomic<uint8_t> flag{1};  // 1=running, 0=shutdown
    char padding[CACHE_LINE_SIZE - sizeof(std::atomic<uint8_t>)];
};

// ============================================================================
// ConnStateShm - Shared pipeline state (renamed from ConnStateShm)
// Includes per-process running flags, target URL, TCP state, and TX frame state
// ============================================================================

struct alignas(CACHE_LINE_SIZE) ConnStateShm {
    // ========================================================================
    // Cache Lines 0-3: Per-process running flags (padded to avoid false sharing)
    // ========================================================================
    PaddedRunning running[PROC_COUNT];  // 4 × CACHE_LINE_SIZE bytes

    // ========================================================================
    // Cache Lines 4-7: Per-process ready flags (for startup synchronization)
    // Processes set their flag to 1 when ready. Others can wait_for_ready().
    // ========================================================================
    PaddedRunning ready[PROC_COUNT];    // 4 × CACHE_LINE_SIZE bytes

    // ========================================================================
    // Cache Line 4: Handshake Stage Flags (fork-first architecture)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) struct {
        std::atomic<uint8_t> xdp_ready;       // XDP Poll: XSK socket created, BPF attached
        std::atomic<uint8_t> tcp_ready;       // Transport: TCP ESTABLISHED
        std::atomic<uint8_t> tls_ready;       // Transport: TLS handshake complete
        std::atomic<uint8_t> ws_ready;        // Transport: WebSocket upgraded, subscription sent
        uint8_t _pad[60];                     // Pad to cache line
    } handshake_stage;

    // ========================================================================
    // Cache Line 5: Disconnect reason tracking (first writer wins)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) struct {
        std::atomic<uint8_t> reason;   // DisconnectReason
        uint16_t ws_close_code;        // WS CLOSE status code (if WS_CLOSE)
        char detail[57];               // Short reason text (null-terminated)
    } disconnect;

    // ========================================================================
    // Cache Line 6: Target URL + TSC frequency (set once, read-only after init)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) char target_host[64];  // e.g., "stream.binance.com"
    uint16_t target_port;                           // e.g., 443
    uint8_t  _pad_url[6];
    char target_path[128];                          // e.g., "/stream"
    uint64_t tsc_freq_hz;                           // TSC frequency for latency

    // ========================================================================
    // Extended Target Config (for fork-first architecture)
    // ========================================================================
    char subscription_json[4096];                   // Subscription message to send after WS upgrade
    char bpf_path[256];                             // Path to BPF object file
    char interface_name[64];                        // Network interface name

    // Exchange IPs for BPF filter (resolved by parent before forking)
    static constexpr size_t MAX_EXCHANGE_IPS = 8;
    uint32_t exchange_ips[MAX_EXCHANGE_IPS];        // Network byte order IPs
    uint8_t  exchange_ip_count;                     // Number of valid IPs
    uint8_t  _pad_exchange[7];

    // ========================================================================
    // Cache Line 5: TCP state (Transport process only - no atomics needed)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) uint32_t snd_nxt;  // Next send sequence
    uint32_t snd_una;                         // Oldest unacked sequence
    uint32_t rcv_nxt;                         // Next expected receive sequence
    uint32_t peer_recv_window;                // Peer advertised window
    uint8_t  window_scale;                    // Window scale factor
    uint8_t  tcp_conn_state;                   // TCP_ESTABLISHED, etc.
    uint8_t  _pad_tcp1[2];

    // Addressing (set during handshake, read-only after)
    uint32_t local_ip;                        // Local IP (network byte order)
    uint32_t remote_ip;                       // Remote IP (network byte order)
    uint16_t local_port;                      // Local port (host byte order)
    uint16_t remote_port;                     // Remote port (host byte order)
    uint8_t  local_mac[6];                    // Local MAC address
    uint8_t  remote_mac[6];                   // Remote (gateway) MAC address

    // MSS from SYN-ACK
    uint16_t peer_mss;

    // SACK support (RFC 2018)
    bool sack_enabled;         // True if peer advertised SACK_OK in SYN-ACK

    // TCP Timestamps support (RFC 7323)
    bool timestamp_enabled;    // True if peer advertised TS in SYN-ACK
    uint32_t peer_ts_val;      // Latest peer timestamp (for TSecr echo)

    // RTT tracking (Transport only)
    uint64_t last_ack_cycle;                  // TSC when last ACK sent
    uint64_t srtt_us;                         // Smoothed RTT in microseconds
    uint64_t rttvar_us;                       // RTT variance in microseconds

    // ========================================================================
    // Cache Line 6: TX Frame Allocation (hot path for XDP Poll + Transport)
    // Merged from TxFrameState
    // ========================================================================
    alignas(CACHE_LINE_SIZE) struct {
        // ACK pool (Transport allocates, XDP Poll releases)
        std::atomic<uint64_t> ack_alloc_pos;
        std::atomic<uint64_t> ack_release_pos;

        // PONG pool (Transport allocates, XDP Poll releases after ACK)
        std::atomic<uint64_t> pong_alloc_pos;
        std::atomic<uint64_t> pong_release_pos;
        std::atomic<uint64_t> pong_acked_pos;

        // MSG pool (Transport allocates, XDP Poll releases after ACK)
        std::atomic<uint64_t> msg_alloc_pos;
        std::atomic<uint64_t> msg_release_pos;
        std::atomic<uint64_t> msg_acked_pos;
        std::atomic<uint64_t> msg_sent_pos;    // XDP Poll increments after sending to NIC

        // Pad to 2 cache lines (10 × 8 = 80 bytes, need 128)
        char _pad[2 * CACHE_LINE_SIZE - 80];
    } tx_frame;

    // ========================================================================
    // Helper Methods
    // ========================================================================
    bool is_running(ProcessId proc) const {
        return running[proc].flag.load(std::memory_order_acquire) != 0;
    }

    void shutdown_all() {
        for (int i = 0; i < PROC_COUNT; ++i) {
            running[i].flag.store(0, std::memory_order_release);
        }
    }

    // Disconnect reason tracking (first writer wins — don't overwrite root cause)
    void set_disconnect(DisconnectReason r, uint16_t ws_code = 0, const char* detail_str = nullptr) {
        uint8_t expected = static_cast<uint8_t>(DisconnectReason::NONE);
        uint8_t desired = static_cast<uint8_t>(r);
        if (disconnect.reason.compare_exchange_strong(expected, desired,
                std::memory_order_acq_rel, std::memory_order_acquire)) {
            disconnect.ws_close_code = ws_code;
            if (detail_str) {
                std::strncpy(disconnect.detail, detail_str, sizeof(disconnect.detail) - 1);
                disconnect.detail[sizeof(disconnect.detail) - 1] = '\0';
            }
        }
    }

    DisconnectReason get_disconnect_reason() const {
        return static_cast<DisconnectReason>(disconnect.reason.load(std::memory_order_acquire));
    }

    // Ready flag methods for startup synchronization
    void set_ready(ProcessId proc) {
        ready[proc].flag.store(1, std::memory_order_release);
    }

    bool is_ready(ProcessId proc) const {
        return ready[proc].flag.load(std::memory_order_acquire) != 0;
    }

    void wait_for_ready(ProcessId proc) const {
        while (!is_ready(proc) && is_running(proc)) {
            __builtin_ia32_pause();  // Hint for spin-wait
        }
    }

    // Handshake stage methods (fork-first architecture)
    void set_handshake_xdp_ready() {
        handshake_stage.xdp_ready.store(1, std::memory_order_release);
    }

    void set_handshake_tcp_ready() {
        handshake_stage.tcp_ready.store(1, std::memory_order_release);
    }

    void set_handshake_tls_ready() {
        handshake_stage.tls_ready.store(1, std::memory_order_release);
    }

    void set_handshake_ws_ready() {
        handshake_stage.ws_ready.store(1, std::memory_order_release);
    }

    bool is_handshake_xdp_ready() const {
        return handshake_stage.xdp_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_tcp_ready() const {
        return handshake_stage.tcp_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_tls_ready() const {
        return handshake_stage.tls_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_ws_ready() const {
        return handshake_stage.ws_ready.load(std::memory_order_acquire) != 0;
    }

    // Wait for handshake stage with timeout (returns false on timeout)
    bool wait_for_handshake_xdp_ready(uint64_t timeout_us = 10000000) const {
        auto start = std::chrono::steady_clock::now();
        while (!is_handshake_xdp_ready()) {
            if (!is_running(PROC_XDP_POLL)) {
                return false;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (static_cast<uint64_t>(elapsed) > timeout_us) {
                return false;
            }
            __builtin_ia32_pause();
        }
        return true;
    }

    bool wait_for_handshake_tls_ready(uint64_t timeout_us = 15000000) const {
        auto start = std::chrono::steady_clock::now();
        while (!is_handshake_tls_ready()) {
            if (!is_running(PROC_TRANSPORT)) return false;
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (static_cast<uint64_t>(elapsed) > timeout_us) return false;
            __builtin_ia32_pause();
        }
        return true;
    }

    bool wait_for_handshake_ws_ready(uint64_t timeout_us = 30000000) const {
        auto start = std::chrono::steady_clock::now();
        while (!is_handshake_ws_ready()) {
            if (!is_running(PROC_TRANSPORT)) return false;
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (static_cast<uint64_t>(elapsed) > timeout_us) return false;
            __builtin_ia32_pause();
        }
        return true;
    }

    void init() {
        // Initialize running flags
        for (int i = 0; i < PROC_COUNT; ++i) {
            running[i].flag.store(1, std::memory_order_relaxed);
        }

        // Initialize ready flags (all not ready)
        for (int i = 0; i < PROC_COUNT; ++i) {
            ready[i].flag.store(0, std::memory_order_relaxed);
        }

        // Initialize handshake stage flags (fork-first architecture)
        handshake_stage.xdp_ready.store(0, std::memory_order_relaxed);
        handshake_stage.tcp_ready.store(0, std::memory_order_relaxed);
        handshake_stage.tls_ready.store(0, std::memory_order_relaxed);
        handshake_stage.ws_ready.store(0, std::memory_order_relaxed);

        // Disconnect reason
        disconnect.reason.store(static_cast<uint8_t>(DisconnectReason::NONE), std::memory_order_relaxed);
        disconnect.ws_close_code = 0;
        std::memset(disconnect.detail, 0, sizeof(disconnect.detail));

        // Target URL (set by handshake manager)
        std::memset(target_host, 0, sizeof(target_host));
        target_port = 0;
        std::memset(target_path, 0, sizeof(target_path));
        tsc_freq_hz = 0;

        // Extended target config (fork-first architecture)
        std::memset(subscription_json, 0, sizeof(subscription_json));
        std::memset(bpf_path, 0, sizeof(bpf_path));
        std::memset(interface_name, 0, sizeof(interface_name));

        // Exchange IPs (set by parent before forking)
        std::memset(exchange_ips, 0, sizeof(exchange_ips));
        exchange_ip_count = 0;

        // TCP state (plain assignments - Transport only)
        snd_nxt = 0;
        snd_una = 0;
        rcv_nxt = 0;
        peer_recv_window = 65535;
        window_scale = 0;
        tcp_conn_state = 0;
        local_ip = 0;
        remote_ip = 0;
        local_port = 0;
        remote_port = 0;
        std::memset(local_mac, 0, 6);
        std::memset(remote_mac, 0, 6);
        peer_mss = PIPELINE_TCP_MSS;  // From pipeline_config.hpp (NIC_MTU - 52 with TS)
        sack_enabled = false;         // Will be set true if peer sends SACK_OK in SYN-ACK
        timestamp_enabled = false;    // Will be set true if peer sends TS in SYN-ACK
        peer_ts_val = 0;              // Latest peer timestamp (for TSecr echo)
        last_ack_cycle = 0;
        srtt_us = 100000;   // Initial 100ms
        rttvar_us = 50000;  // Initial 50ms

        // TX frame allocation
        tx_frame.ack_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.ack_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_acked_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_acked_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_sent_pos.store(0, std::memory_order_relaxed);
    }
};


// TCP states
inline constexpr uint8_t TCP_CLOSED      = 0;
inline constexpr uint8_t TCP_SYN_SENT    = 1;
inline constexpr uint8_t TCP_ESTABLISHED = 2;
inline constexpr uint8_t TCP_FIN_WAIT_1  = 3;
inline constexpr uint8_t TCP_FIN_WAIT_2  = 4;
inline constexpr uint8_t TCP_CLOSING     = 5;
inline constexpr uint8_t TCP_TIME_WAIT   = 6;
inline constexpr uint8_t TCP_CLOSE_WAIT  = 7;
inline constexpr uint8_t TCP_LAST_ACK    = 8;

// ============================================================================
// IPC Ring Types (hftshm-backed disruptor rings)
// ============================================================================
// Note: ACK_OUTBOX and PONG_OUTBOX now use UMEMFrameDescriptor for type
// unification with XDPPollProcess. The frame_type field distinguishes them.

// IPC ring buffer using external storage (data in shared memory)
template<typename T, size_t SIZE>
using IPCRingBuffer = disruptor::ring_buffer<T, SIZE,
    disruptor::storage_policies::external_storage_policy,
    disruptor::padding_policies::no_padding>;

// IPC sequence using external atomic (sequence in shared memory header)
using IPCSequence = disruptor::sequence<
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release>;

// IPC sequence barrier
using IPCSequenceBarrier = disruptor::sequence_barrier<
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release,
    disruptor::wait_policies::busy_spin_wait_policy>;

// IPC event processor template
template<typename T, typename Handler>
using IPCEventProcessor = disruptor::event_processor<T, Handler,
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release,
    disruptor::wait_policies::busy_spin_wait_policy,
    disruptor::batch_policies::auto_batch,
    disruptor::error_policies::throw_on_error,
    disruptor::storage_policies::external_storage_policy,
    disruptor::padding_policies::no_padding>;

// Concrete IPC ring types
using MsgMetadataIPCRing = IPCRingBuffer<MsgMetadata, MSG_METADATA_SIZE>;
using WSFrameInfoIPCRing = IPCRingBuffer<WSFrameInfo, WS_FRAME_INFO_SIZE>;
using MsgOutboxIPCRing = IPCRingBuffer<MsgOutboxEvent, MSG_OUTBOX_SIZE>;

// ============================================================================
// IPC Ring Adapters
// Provide try_publish()/try_consume() interface over hftshm shared_region
// These wrap disruptor::ipc::shared_region for use with existing process classes
// ============================================================================

// IPC Ring Producer - wraps shared_region for try_publish() API
// Used by producers (XDP Poll for RAW_INBOX, Transport for MSG_METADATA, etc.)
template<typename T>
struct IPCRingProducer {
    disruptor::ipc::shared_region& region_;
    size_t element_count_;   // buffer_size / sizeof(T)
    size_t element_mask_;    // element_count - 1 (for element indexing)

    explicit IPCRingProducer(disruptor::ipc::shared_region& r) : region_(r) {
        // Compute element-based sizes (metadata stores bytes, we need element count)
        element_count_ = region_.buffer_size() / sizeof(T);
        element_mask_ = element_count_ - 1;
    }

    // Non-copyable but movable
    IPCRingProducer(const IPCRingProducer&) = delete;
    IPCRingProducer& operator=(const IPCRingProducer&) = delete;
    IPCRingProducer(IPCRingProducer&&) = default;
    IPCRingProducer& operator=(IPCRingProducer&&) = default;

    // Get consumer sequence (for producer to track what has been consumed)
    int64_t consumer_sequence() const {
        return region_.consumer_sequence(0)->load(std::memory_order_acquire);
    }

    // Get producer published sequence (for monitoring ring buffer fill level)
    int64_t published_sequence() const {
        return region_.producer_published()->load(std::memory_order_acquire);
    }

    // Get data pointer for direct access (used by XDP Poll for frame reclaim)
    T* data() { return region_.template data<T>(); }
    const T* data() const { return region_.template data<T>(); }

    // Get element mask for ring buffer indexing (NOT byte mask!)
    size_t index_mask() const { return element_mask_; }

    // ========================================================================
    // Two-step API: try_claim() + publish() for zero-copy writes
    // ========================================================================

    // Try to claim the next slot in the ring buffer
    // Returns sequence number >= 0 on success, -1 if buffer full
    // Note: Disruptor convention - cursor stores "last claimed", claim returns "next slot"
    int64_t try_claim() {
        auto* cursor = region_.producer_cursor();
        auto* consumer_seq = region_.consumer_sequence(0);

        // Claim next slot: fetch_add returns OLD value, we want NEW value
        int64_t old_cursor = cursor->fetch_add(1, std::memory_order_relaxed);
        int64_t next_seq = old_cursor + 1;  // The slot we just claimed
        int64_t cons = consumer_seq->load(std::memory_order_acquire);

        // Check if buffer full (producer wrapped around to consumer)
        if (next_seq - cons >= static_cast<int64_t>(element_count_)) {
            cursor->fetch_sub(1, std::memory_order_relaxed);  // Rollback
            return -1;
        }

        return next_seq;
    }

    // Access slot at claimed sequence (for zero-copy writes)
    T& operator[](int64_t seq) {
        T* data_ptr = region_.template data<T>();
        return data_ptr[seq & element_mask_];
    }

    // Publish the claimed sequence (makes it visible to consumers)
    void publish(int64_t seq) {
        auto* published = region_.producer_published();

        // Wait for in-order publishing (ensures no gaps in published sequence)
        int64_t expected = seq - 1;

        while (published->load(std::memory_order_acquire) != expected) {
            __builtin_ia32_pause();
        }

        // Publish
        published->store(seq, std::memory_order_release);
    }

    // ========================================================================
    // Batch API: claim_batch() + publish_batch() for XDP batch sending
    // ========================================================================

    // Claim context returned by claim_batch()
    struct ClaimContext {
        int64_t start;   // First sequence in batch (inclusive)
        int64_t end;     // Last sequence in batch (inclusive)
        size_t count;    // Number of slots claimed
    };

    // Try to claim a batch of slots in the ring buffer
    // Returns ClaimContext with start/end sequences, or {-1, -1, 0} if buffer full
    ClaimContext try_claim_batch(size_t requested_count) {
        if (requested_count == 0) {
            return {-1, -1, 0};
        }

        auto* cursor = region_.producer_cursor();
        auto* consumer_seq = region_.consumer_sequence(0);

        // Claim batch: fetch_add by requested count
        int64_t old_cursor = cursor->fetch_add(static_cast<int64_t>(requested_count), std::memory_order_relaxed);
        int64_t batch_start = old_cursor + 1;
        int64_t batch_end = old_cursor + static_cast<int64_t>(requested_count);
        int64_t cons = consumer_seq->load(std::memory_order_acquire);

        // Check if buffer has space for entire batch
        if (batch_end - cons >= static_cast<int64_t>(element_count_)) {
            cursor->fetch_sub(static_cast<int64_t>(requested_count), std::memory_order_relaxed);  // Rollback
            return {-1, -1, 0};
        }

        return {batch_start, batch_end, requested_count};
    }

    // Publish a batch of sequences (makes them visible to consumers)
    // lo and hi are inclusive: publishes sequences [lo, hi]
    void publish_batch(int64_t lo, int64_t hi) {
        auto* published = region_.producer_published();

        // Wait for in-order publishing (ensures no gaps before our batch)
        int64_t expected = lo - 1;
        while (published->load(std::memory_order_acquire) != expected) {
            __builtin_ia32_pause();
        }

        // Publish entire batch at once (only the end matters for consumers)
        published->store(hi, std::memory_order_release);
    }

    // ========================================================================
    // Single-step API: try_publish() for convenience (copies data)
    // ========================================================================

    bool try_publish(const T& item) {
        auto* cursor = region_.producer_cursor();
        auto* published = region_.producer_published();
        auto* consumer_seq = region_.consumer_sequence(0);

        // Claim next slot: fetch_add returns OLD value, we want NEW value
        int64_t old_cursor = cursor->fetch_add(1, std::memory_order_relaxed);
        int64_t seq = old_cursor + 1;  // The slot we just claimed
        int64_t cons = consumer_seq->load(std::memory_order_acquire);

        // Check if buffer full (producer wrapped around to consumer)
        if (seq - cons >= static_cast<int64_t>(element_count_)) {
            cursor->fetch_sub(1, std::memory_order_relaxed);  // Rollback
            return false;
        }

        // Write data to buffer
        T* data = region_.data<T>();
        data[seq & element_mask_] = item;

        // Wait for in-order publishing (ensures no gaps in published sequence)
        // This is required for correct disruptor semantics
        int64_t expected = seq - 1;
        while (published->load(std::memory_order_acquire) != expected) {
            __builtin_ia32_pause();
        }

        // Publish
        published->store(seq, std::memory_order_release);
        return true;
    }
};

// IPC Ring Consumer - wraps shared_region for try_consume() API
// Used by consumers (Transport for RAW_INBOX, WebSocket for MSG_METADATA, etc.)
//
// Two consumption patterns:
// 1. try_consume() - single-item consumption with immediate commit (simple, more atomics)
// 2. process_manually() + commit_manually() - batch processing with deferred commit (fewer atomics)
template<typename T>
struct IPCRingConsumer {
    disruptor::ipc::shared_region& region_;
    size_t element_count_;         // buffer_size / sizeof(T)
    size_t element_mask_;          // element_count - 1 (for element indexing)
    int64_t sequence_ = -1;        // Last committed sequence
    int64_t last_processed_ = -1;  // Last processed sequence (for deferred commit)
    uint8_t consumer_index_ = 0;   // Consumer index for multi-consumer support

    explicit IPCRingConsumer(disruptor::ipc::shared_region& r, uint8_t consumer_index = 0)
        : region_(r), consumer_index_(consumer_index) {
        // Compute element-based sizes (metadata stores bytes, we need element count)
        element_count_ = region_.buffer_size() / sizeof(T);
        element_mask_ = element_count_ - 1;

        // Read initial sequence from shared memory to resume from where previous consumer left off
        sequence_ = region_.consumer_sequence(consumer_index_)->load(std::memory_order_acquire);
        last_processed_ = sequence_;
    }

    // Non-copyable but movable
    IPCRingConsumer(const IPCRingConsumer&) = delete;
    IPCRingConsumer& operator=(const IPCRingConsumer&) = delete;
    IPCRingConsumer(IPCRingConsumer&&) = default;
    IPCRingConsumer& operator=(IPCRingConsumer&&) = default;

    // ========================================================================
    // Check if data is available (non-consuming peek)
    // ========================================================================

    bool has_data() const {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);
        return sequence_ < avail;
    }

    // ========================================================================
    // Pattern 1: Single-item consumption with immediate commit
    // ========================================================================

    bool try_consume(T& item, bool* end_of_batch = nullptr) {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);

        if (sequence_ >= avail) {
            return false;  // Nothing available
        }

        sequence_++;
        T* data = region_.data<T>();
        item = data[sequence_ & element_mask_];

        // Update consumer sequence (allows producer to reclaim slot)
        region_.consumer_sequence(consumer_index_)->store(sequence_, std::memory_order_release);

        if (end_of_batch) {
            *end_of_batch = (sequence_ >= avail);
        }
        return true;
    }

    // ========================================================================
    // Pattern 2: Batch processing with deferred commit
    // ========================================================================

    /**
     * Process available events in a batch without committing
     * @tparam F Callable with signature: void(T& event, int64_t sequence, bool end_of_batch)
     *           or bool(T& event, int64_t sequence, bool end_of_batch) - return false to stop
     * @param max_events Maximum events to process in this call
     * @return Number of events processed
     *
     * Call commit_manually() after processing to update consumer sequence.
     */
    template<typename F>
    size_t process_manually(F&& handler, size_t max_events = SIZE_MAX) {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);

        // FIX: When commit_up_to() cannot advance sequence_ (e.g., OOO buffer holds
        // frame references), last_processed_ is preserved but sequence_ stays unchanged.
        // Without this fix, next iteration would reprocess the same frames because
        // next = sequence_ + 1 ignores what was already processed.
        //
        // Example scenario (TCP OOO handling):
        //   - Frame 23 is OOO segment, stored in OOO buffer with ext_id=23
        //   - safe_commit_rx() calls commit_up_to(22) since min_ext_id-1 = 22
        //   - sequence_ stays at 22, but last_processed_ = 23
        //   - Without fix: next = 23, reprocesses frame 23 indefinitely
        //   - With fix: next = 24, skips already-processed frame 23
        //
        // See: issues/001_ipc_ring_reprocess_bug.md for detailed analysis
        int64_t next = (last_processed_ > sequence_)
                       ? last_processed_ + 1
                       : sequence_ + 1;

        if (avail < next) {
            return 0;  // No events available
        }

        // Limit to max_events (handle SIZE_MAX overflow by capping at avail)
        int64_t end;
        if (max_events >= static_cast<size_t>(INT64_MAX)) {
            end = avail;  // No limit effectively
        } else {
            end = std::min(avail, next + static_cast<int64_t>(max_events) - 1);
        }

        T* data = region_.data<T>();
        size_t count = 0;

        for (int64_t seq = next; seq <= end; ++seq) {
            T& event = data[seq & element_mask_];
            bool is_end = (seq == end);

            // Prefetch next ring element into L1
            if (seq + 1 <= end) {
                __builtin_prefetch(&data[(seq + 1) & element_mask_], 0, 3);
                if constexpr (sizeof(T) > 64) {
                    __builtin_prefetch(reinterpret_cast<const char*>(&data[(seq + 1) & element_mask_]) + 64, 0, 3);
                }
            }

            // Support multiple handler signatures:
            // 1. (T&, int64_t, bool) -> bool  (3-param with stop control)
            // 2. (T&, int64_t) -> bool        (2-param with stop control)
            // 3. (T&, int64_t, bool) -> void  (3-param, no stop)
            // 4. (T&, int64_t) -> void        (2-param, no stop)
            if constexpr (std::is_invocable_r_v<bool, F, T&, int64_t, bool>) {
                if (!handler(event, seq, is_end)) {
                    return count;  // Handler rejected this frame — stop, don't advance past it
                }
            } else if constexpr (std::is_invocable_r_v<bool, F, T&, int64_t>) {
                if (!handler(event, seq)) {
                    return count;  // Handler rejected this frame — stop, don't advance past it
                }
            } else if constexpr (std::is_invocable_v<F, T&, int64_t, bool>) {
                handler(event, seq, is_end);
            } else {
                handler(event, seq);
            }
            ++count;
            last_processed_ = seq;  // Track last successfully consumed frame
        }

        return count;
    }

    /**
     * Commit progress: mark all processed events as consumed
     * Updates consumer sequence so producer knows slots can be reused.
     * Call this after process_manually() when done with the batch.
     */
    void commit_manually() {
        if (last_processed_ > sequence_) {
            sequence_ = last_processed_;
            region_.consumer_sequence(consumer_index_)->store(sequence_, std::memory_order_release);
        }
        last_processed_ = -1;  // Reset for next batch
    }

    /**
     * Commit up to a specific sequence (for safe commit with OOO segments)
     * Use this when OOO buffer holds references to frames that shouldn't be released yet.
     * @param target_seq Maximum sequence to commit to (inclusive)
     *
     * NOTE: Does NOT reset last_processed_ - frames past safe point still tracked.
     */
    void commit_up_to(int64_t target_seq) {
        if (target_seq > sequence_) {
            int64_t commit_seq = std::min(target_seq, last_processed_);
            if (commit_seq > sequence_) {
                sequence_ = commit_seq;
                region_.consumer_sequence(consumer_index_)->store(sequence_, std::memory_order_release);
            }
        }
        // NOTE: Don't reset last_processed_ - still tracking frames past safe point
    }

    /**
     * Get number of events available without consuming
     */
    size_t available() const {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);
        return (avail > sequence_) ? static_cast<size_t>(avail - sequence_) : 0;
    }

    /**
     * Direct access to event at sequence (for zero-copy processing)
     * Only valid for sequences between (sequence_+1) and last available
     */
    T& operator[](int64_t seq) {
        T* data = region_.data<T>();
        return data[seq & element_mask_];
    }

    const T& operator[](int64_t seq) const {
        const T* data = region_.data<T>();
        return data[seq & element_mask_];
    }

    // Get current committed sequence (for debugging/stats)
    int64_t sequence() const { return sequence_; }

    // Get producer published sequence (for monitoring ring buffer fill level)
    int64_t published_sequence() const {
        return region_.producer_published()->load(std::memory_order_acquire);
    }

    // Get last processed sequence (for deferred commit tracking)
    int64_t last_processed() const { return last_processed_; }
};

// ============================================================================
// Profiling Data Structures
// For loop iteration profiling in XDP Poll and Transport processes
// ============================================================================

// Single loop iteration profiling record (64 bytes, cache-line aligned)
// Records CPU cycles and per-operation details for each main loop iteration
//
// Size: 88 bytes (84 data + 4 padding for uint64_t alignment)
// - uint64_t packet_nic_ns = 8 bytes
// - uint64_t nic_poll_cycle = 8 bytes
// - uint64_t transport_poll_cycle = 8 bytes
// - int32_t op_details[6] = 24 bytes
// - int32_t op_cycles[6] = 24 bytes
// - int16_t noop_ct[6] = 12 bytes
struct CycleSample {
    static constexpr size_t N = 6;  // Array size for op_details and op_cycles

    uint64_t packet_nic_ns;         // NIC hardware timestamp (ns) of oldest RX packet
    uint64_t nic_poll_cycle;        // XDP Poll rdtsc when packet retrieved from NIC
    uint64_t transport_poll_cycle;  // Transport rdtsc when packet processed (0 for XDP Poll)
    int32_t op_details[N];          // Per-operation details (counts, triggered flags)
    int32_t op_cycles[N];           // Per-operation CPU cycles
    int16_t noop_ct[N];            // cumulative zero-return count per op (saturates at INT16_MAX)

    void clear() {
        packet_nic_ns = 0;
        nic_poll_cycle = 0;
        transport_poll_cycle = 0;
        for (size_t i = 0; i < N; ++i) {
            op_details[i] = 0;
            op_cycles[i] = 0;
            noop_ct[i] = 0;
        }
    }
};
static_assert(sizeof(CycleSample) == 88, "CycleSample must be 88 bytes");

// Circular buffer for 4M samples per process
struct alignas(64) CycleSampleBuffer {
    static constexpr uint32_t SAMPLE_COUNT = 4 * 1024 * 1024;  // 4M samples
    static constexpr uint32_t MASK = SAMPLE_COUNT - 1;

    CycleSample samples[SAMPLE_COUNT];
    uint32_t write_idx;         // Next write position (committed samples only)
    uint32_t total_count;       // Total loop iterations (saturates at UINT32_MAX)

    // Get pointer to next write slot (for direct assignment, avoids stack copy)
    CycleSample* next_slot() {
        return &samples[write_idx & MASK];
    }

    // Commit after writing to slot — skips ring buffer write when all
    // "tracked" ops are suppressed and idle, preserving buffer space for
    // data-moved samples.  total_count always increments (total iterations).
    //
    // An op is "tracked" when noop_ct[i] > 0, meaning it has returned zero
    // at least once.  Ops that never return zero (maintenance ops like
    // Trickle, unused slots) have noop_ct == 0 and are ignored.
    void commit() {
        auto* cur = &samples[write_idx & MASK];
        if (total_count < UINT32_MAX) total_count++;

        // Skip commit when every tracked op is both suppressed and idle.
        bool any_tracked = false;
        bool all_suppressed_idle = true;
        for (size_t i = 0; i < CycleSample::N; ++i) {
            if (cur->noop_ct[i] == 0) continue;   // never-idle / unused — ignore
            any_tracked = true;
            if (cur->noop_ct[i] < 10000 || cur->op_details[i] != 0) {
                all_suppressed_idle = false;
                break;
            }
        }
        if (any_tracked && all_suppressed_idle) return;  // reuse slot

        write_idx++;
        auto* nxt = &samples[write_idx & MASK];
        for (size_t i = 0; i < CycleSample::N; ++i)
            nxt->noop_ct[i] = cur->noop_ct[i];
    }

    // Copy-based record (kept for compatibility)
    void record(const CycleSample& sample) {
        samples[write_idx & MASK] = sample;
        commit();
    }

    void init() {
        write_idx = 0;
        total_count = 0;
        for (size_t i = 0; i < CycleSample::N; ++i)
            samples[0].noop_ct[i] = 0;
    }
};

// ============================================================================
// profile_op — Zero-overhead operation profiler (compile-time gated)
//
// Wraps a callable with TSC timing. Records return value in op_details[idx]
// and elapsed cycles in op_cycles[idx]. Compiles away when Profiling=false.
// ============================================================================

template<bool Profiling, typename Func>
inline auto profile_op(Func&& func, CycleSample* slot, size_t idx, bool condition = true) {
    using ReturnType = decltype(func());
    if constexpr (Profiling) {
        if (!condition) {
            slot->op_details[idx] = 0;
            slot->op_cycles[idx] = 0;
            return ReturnType{};
        }

        // Fast path: after 10000 cumulative zero returns, skip timing
        if (slot->noop_ct[idx] >= 10000) {
            auto result = func();
            if (result == 0) {
                if (slot->noop_ct[idx] < INT16_MAX) ++slot->noop_ct[idx];
                slot->op_details[idx] = 0;
                slot->op_cycles[idx] = 0;
            } else {
                // Data arrived after long idle — reset to re-enable timing
                slot->noop_ct[idx] = 0;
                slot->op_details[idx] = static_cast<int32_t>(result);
                slot->op_cycles[idx] = 0;  // This iteration untimed; next will be timed
            }
            return result;
        }

        // Normal profiling path
        uint64_t start = rdtsc();
        auto result = func();
        uint64_t end = rdtsc();
        slot->op_details[idx] = static_cast<int32_t>(result);
        slot->op_cycles[idx] = static_cast<int32_t>(end - start);

        if (result == 0) {
            if (slot->noop_ct[idx] < INT16_MAX) ++slot->noop_ct[idx];
        }

        return result;
    } else {
        if (!condition) return ReturnType{};
        return func();
    }
}

// Per-RX-packet NIC latency record (40 bytes)
struct NicLatencySample {
    uint64_t nic_realtime_ns;         // HW timestamp from NIC (ns) - PHC (synced to CLOCK_REALTIME)
    uint64_t packet_bpf_timestamp_ns; // BPF entry bpf_ktime_get_ns() - CLOCK_MONOTONIC
    uint64_t poll_cycle;              // TSC cycle when XDP Poll retrieved packet
    uint64_t poll_timestamp_ns;       // XDP Poll clock_gettime(CLOCK_MONOTONIC)
    uint64_t poll_realtime_ns;        // XDP Poll clock_gettime(CLOCK_REALTIME) - matches NIC PHC
};
static_assert(sizeof(NicLatencySample) == 40, "NicLatencySample must be 40 bytes");

// Circular buffer for NIC latency samples (~160MB)
struct alignas(64) NicLatencyBuffer {
    static constexpr uint32_t SAMPLE_COUNT = 4 * 1024 * 1024;  // 4M samples
    static constexpr uint32_t MASK = SAMPLE_COUNT - 1;

    NicLatencySample samples[SAMPLE_COUNT];  // 4M * 40 = 160MB
    uint32_t write_idx;
    uint32_t total_count;

    void record(uint64_t nic_rt_ns, uint64_t bpf_ts_ns, uint64_t poll_cyc,
                uint64_t poll_ts_ns, uint64_t poll_rt_ns) {
        uint32_t idx = write_idx & MASK;
        samples[idx].nic_realtime_ns = nic_rt_ns;
        samples[idx].packet_bpf_timestamp_ns = bpf_ts_ns;
        samples[idx].poll_cycle = poll_cyc;
        samples[idx].poll_timestamp_ns = poll_ts_ns;
        samples[idx].poll_realtime_ns = poll_rt_ns;
        write_idx++;
        if (total_count < UINT32_MAX) total_count++;
    }

    void init() {
        write_idx = 0;
        total_count = 0;
    }
};

// Full profiling shared memory region (~1GB total)
struct ProfilingShm {
    CycleSampleBuffer xdp_poll;      // ~352MB - loop profiling
    CycleSampleBuffer transport;     // ~352MB - loop profiling
    CycleSampleBuffer ws_process;    // ~352MB - loop profiling
    NicLatencyBuffer nic_latency;    // ~160MB - per-packet NIC latency

    void init() {
        xdp_poll.init();
        transport.init();
        ws_process.init();
        nic_latency.init();
    }
};

}  // namespace websocket::pipeline
