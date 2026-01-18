// src/stack/tcp/tcp_state.hpp
// TCP Types, Constants, and Helpers (Internal)
//
// INTERNAL: Use UserspaceStack (userspace_stack.hpp) as the entry point.
//
// Provides:
//   - TCPState enum (CLOSED, SYN_SENT, ESTABLISHED, etc.)
//   - TCPParams struct (sequence numbers, ports, IPs)
//   - TCPTimers struct (RTO, timeouts)
//   - TCPHeader struct (20-byte TCP header)
//   - TCP flag constants (TCP_FLAG_SYN, TCP_FLAG_ACK, etc.)
//   - Sequence number helpers (seq_lt, seq_gt, seq_le, seq_ge)

#pragma once

#include <cstdint>
#include <string>

// NIC_MTU must be passed as a compile-time argument via -DNIC_MTU=<value>
#ifndef NIC_MTU
#error "NIC_MTU must be defined at compile time (e.g., -DNIC_MTU=1500)"
#endif

namespace userspace_stack {

// TCP states (simplified for client)
enum class TCPState {
    CLOSED,          // No connection
    SYN_SENT,        // SYN sent, waiting for SYN-ACK
    ESTABLISHED,     // Connection established
    FIN_WAIT_1,      // FIN sent, waiting for ACK
    FIN_WAIT_2,      // FIN ACK received, waiting for FIN
    TIME_WAIT,       // Waiting for 2MSL timeout
    CLOSE_WAIT,      // Remote FIN received, waiting for local close
    LAST_ACK,        // FIN sent after remote FIN, waiting for ACK
    CLOSING          // Simultaneous close
};

// TCP flags
constexpr uint8_t TCP_FLAG_FIN = 0x01;
constexpr uint8_t TCP_FLAG_SYN = 0x02;
constexpr uint8_t TCP_FLAG_RST = 0x04;
constexpr uint8_t TCP_FLAG_PSH = 0x08;
constexpr uint8_t TCP_FLAG_ACK = 0x10;
constexpr uint8_t TCP_FLAG_URG = 0x20;
constexpr uint8_t TCP_FLAG_ECE = 0x40;
constexpr uint8_t TCP_FLAG_CWR = 0x80;

// TCP header constants
constexpr size_t TCP_HEADER_MIN_LEN = 20;
constexpr size_t TCP_HEADER_MAX_LEN = 60;
constexpr uint16_t USERSPACE_TCP_MSS = NIC_MTU - 40;  // MSS = MTU - IP(20) - TCP(20)
constexpr uint32_t TCP_MAX_WINDOW = 65535;

// TCP options
constexpr uint8_t TCP_OPT_EOL = 0;       // End of option list
constexpr uint8_t TCP_OPT_NOP = 1;       // No operation
constexpr uint8_t TCP_OPT_MSS = 2;       // Maximum segment size
constexpr uint8_t TCP_OPT_WSCALE = 3;    // Window scale
constexpr uint8_t TCP_OPT_SACK_OK = 4;   // SACK permitted
constexpr uint8_t TCP_OPT_TIMESTAMP = 8; // Timestamp

// TCP header structure (20 bytes minimum)
struct __attribute__((packed)) TCPHeader {
    uint16_t source;         // Source port
    uint16_t dest;           // Destination port
    uint32_t seq;            // Sequence number
    uint32_t ack_seq;        // Acknowledgment number
    uint8_t  doff_reserved;  // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;          // TCP flags
    uint16_t window;         // Window size
    uint16_t check;          // Checksum
    uint16_t urg_ptr;        // Urgent pointer
};

// TCP connection parameters
struct TCPParams {
    // Sequence numbers
    uint32_t snd_una = 0;    // Send unacknowledged
    uint32_t snd_nxt = 0;    // Send next
    uint32_t snd_wnd = 0;    // Send window
    uint32_t rcv_nxt = 0;    // Receive next
    uint32_t rcv_wnd = TCP_MAX_WINDOW;  // Receive window

    // MSS
    uint16_t snd_mss = USERSPACE_TCP_MSS;  // Send MSS
    uint16_t rcv_mss = USERSPACE_TCP_MSS;  // Receive MSS

    // Ports
    uint16_t local_port = 0;
    uint16_t remote_port = 0;

    // IPs (host byte order)
    uint32_t local_ip = 0;
    uint32_t remote_ip = 0;
};

// TCP timers (in milliseconds)
struct TCPTimers {
    uint32_t rto = 1000;           // Retransmission timeout (1 second initially)
    uint32_t rto_min = 200;        // Minimum RTO (200ms)
    uint32_t rto_max = 60000;      // Maximum RTO (60 seconds)

    uint32_t time_wait = 60000;    // TIME_WAIT timeout (60 seconds / 2MSL)
    uint32_t connect_timeout = 5000; // Connection timeout (5 seconds)

    uint64_t last_send_time_us = 0;  // Last send time (microseconds)
    uint64_t last_recv_time_us = 0;  // Last receive time (microseconds)
};

// Helper: Get state name as string
inline const char* tcp_state_name(TCPState state) {
    switch (state) {
        case TCPState::CLOSED: return "CLOSED";
        case TCPState::SYN_SENT: return "SYN_SENT";
        case TCPState::ESTABLISHED: return "ESTABLISHED";
        case TCPState::FIN_WAIT_1: return "FIN_WAIT_1";
        case TCPState::FIN_WAIT_2: return "FIN_WAIT_2";
        case TCPState::TIME_WAIT: return "TIME_WAIT";
        case TCPState::CLOSE_WAIT: return "CLOSE_WAIT";
        case TCPState::LAST_ACK: return "LAST_ACK";
        case TCPState::CLOSING: return "CLOSING";
        default: return "UNKNOWN";
    }
}

// Helper: Get TCP flags as string
inline std::string tcp_flags_string(uint8_t flags) {
    std::string result;
    if (flags & TCP_FLAG_FIN) result += "FIN ";
    if (flags & TCP_FLAG_SYN) result += "SYN ";
    if (flags & TCP_FLAG_RST) result += "RST ";
    if (flags & TCP_FLAG_PSH) result += "PSH ";
    if (flags & TCP_FLAG_ACK) result += "ACK ";
    if (flags & TCP_FLAG_URG) result += "URG ";
    if (!result.empty()) result.pop_back();  // Remove trailing space
    return result;
}

// Helper: Sequence number comparison (handles wraparound)
inline bool seq_lt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
}

inline bool seq_gt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) > 0;
}

inline bool seq_le(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
}

inline bool seq_ge(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) >= 0;
}

} // namespace userspace_stack
