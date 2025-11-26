// src/stack/tcp/tcp_connection.hpp
// TCP Connection Implementation
// Minimal TCP client for WebSocket HFT

#pragma once

#include "tcp_state.hpp"
#include "tcp_retransmit.hpp"
#include "../ip/ip_layer.hpp"
#include "../ip/checksum.hpp"
#include <stdexcept>
#include <chrono>
#include <cstdlib>

namespace userspace_stack {

class TCPConnection {
private:
    IPLayer* ip_ = nullptr;
    TCPState state_ = TCPState::CLOSED;
    TCPParams params_;
    TCPTimers timers_;
    RetransmitQueue retransmit_queue_;
    ReceiveBuffer recv_buffer_;

    // Connection state
    bool is_connected_ = false;
    bool has_error_ = false;
    std::string error_msg_;

public:
    TCPConnection() = default;
    ~TCPConnection() {
        if (state_ != TCPState::CLOSED) {
            try {
                close();
            } catch (...) {
                // Ignore errors in destructor
            }
        }
    }

    // Initialize TCP connection
    void init(IPLayer* ip, uint32_t local_ip) {
        if (!ip) {
            throw std::runtime_error("TCPConnection: IP layer is null");
        }

        ip_ = ip;
        params_.local_ip = local_ip;
        params_.local_port = generate_random_port();
        state_ = TCPState::CLOSED;
    }

    // Connect to remote host (3-way handshake)
    // remote_ip: Destination IP (host byte order)
    // remote_port: Destination port
    // timeout_ms: Connection timeout
    void connect(uint32_t remote_ip, uint16_t remote_port, uint32_t timeout_ms = 5000) {
        if (!ip_) {
            throw std::runtime_error("TCPConnection: Not initialized");
        }

        if (state_ != TCPState::CLOSED) {
            throw std::runtime_error("TCPConnection: Already connected or connecting");
        }

        // Set connection parameters
        params_.remote_ip = remote_ip;
        params_.remote_port = remote_port;

        // Generate random initial sequence number
        params_.snd_una = params_.snd_nxt = generate_isn();
        params_.rcv_nxt = 0;
        params_.snd_wnd = TCP_MAX_WINDOW;
        params_.rcv_wnd = TCP_MAX_WINDOW;

        // Send SYN
        printf("[TCP-DEBUG] Sending SYN to %s:%u (local port %u, seq=%u)\n",
               ip_to_string(remote_ip).c_str(), remote_port, params_.local_port, params_.snd_nxt);
        send_tcp_segment(TCP_FLAG_SYN, nullptr, 0);
        state_ = TCPState::SYN_SENT;
        printf("[TCP-DEBUG] State changed to SYN_SENT\n");

        // Add SYN to retransmit queue
        retransmit_queue_.add_segment(params_.snd_nxt, TCP_FLAG_SYN, nullptr, 0);
        params_.snd_nxt++;  // SYN consumes one sequence number

        // Wait for SYN-ACK
        auto start = std::chrono::steady_clock::now();
        int poll_count = 0;
        while (state_ == TCPState::SYN_SENT) {
            // Check timeout
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - start).count();

            if (elapsed_ms >= timeout_ms) {
                state_ = TCPState::CLOSED;
                throw std::runtime_error("TCPConnection: Connection timeout");
            }

            // Process incoming packets
            process_rx();
            poll_count++;

            // Print debug every 2000 iterations (~200ms)
            if (poll_count % 2000 == 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start).count();
                printf("[TCP-DEBUG] Waiting for SYN-ACK... (%ld ms, %d polls, state=%d)\n",
                       elapsed_ms, poll_count, static_cast<int>(state_));
            }

            // Check for errors
            if (has_error_) {
                state_ = TCPState::CLOSED;
                throw std::runtime_error("TCPConnection: " + error_msg_);
            }

            // Check retransmissions
            check_retransmit();

            // Brief sleep to avoid busy loop
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        if (state_ != TCPState::ESTABLISHED) {
            throw std::runtime_error("TCPConnection: Failed to establish connection");
        }

        is_connected_ = true;
    }

    // Send data
    ssize_t send(const uint8_t* data, size_t len) {
        if (state_ != TCPState::ESTABLISHED) {
            return -1;  // Not connected
        }

        if (!data || len == 0) {
            return 0;
        }

        size_t sent = 0;

        while (sent < len) {
            // Calculate chunk size (MSS limit)
            size_t remaining = len - sent;
            size_t chunk_size = std::min(remaining, static_cast<size_t>(params_.snd_mss));

            // Send segment
            send_tcp_segment(TCP_FLAG_ACK | TCP_FLAG_PSH,
                           data + sent, static_cast<uint16_t>(chunk_size));

            // Add to retransmit queue
            retransmit_queue_.add_segment(params_.snd_nxt, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                         data + sent, static_cast<uint16_t>(chunk_size));

            params_.snd_nxt += chunk_size;
            sent += chunk_size;
        }

        return static_cast<ssize_t>(sent);
    }

    // Receive data
    ssize_t recv(uint8_t* buffer, size_t len) {
        if (state_ != TCPState::ESTABLISHED && state_ != TCPState::CLOSE_WAIT) {
            return -1;  // Not in receiving state
        }

        if (!buffer || len == 0) {
            return 0;
        }

        // Process incoming packets first
        process_rx();

        // Read from receive buffer
        return recv_buffer_.read(buffer, len);
    }

    // Close connection (graceful shutdown)
    void close() {
        if (state_ == TCPState::CLOSED) {
            return;  // Already closed
        }

        if (state_ == TCPState::ESTABLISHED) {
            // Send FIN
            send_tcp_segment(TCP_FLAG_FIN | TCP_FLAG_ACK, nullptr, 0);
            retransmit_queue_.add_segment(params_.snd_nxt, TCP_FLAG_FIN | TCP_FLAG_ACK,
                                         nullptr, 0);
            params_.snd_nxt++;  // FIN consumes one sequence number
            state_ = TCPState::FIN_WAIT_1;

            // Wait for FIN-ACK (simplified, no full state machine)
            auto start = std::chrono::steady_clock::now();
            while (state_ != TCPState::CLOSED && state_ != TCPState::TIME_WAIT) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start).count();

                if (elapsed_ms >= 2000) {  // 2 second timeout
                    break;  // Force close
                }

                process_rx();
                check_retransmit();
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }

        // Clean up
        state_ = TCPState::CLOSED;
        is_connected_ = false;
        retransmit_queue_.clear();
        recv_buffer_.clear();
    }

    // Poll for incoming packets (must be called periodically)
    void poll() {
        if (state_ == TCPState::CLOSED) {
            return;
        }

        process_rx();
        check_retransmit();
    }

    // Get connection state
    TCPState get_state() const {
        return state_;
    }

    // Check if connected
    bool is_connected() const {
        return is_connected_;
    }

    // Get local port
    uint16_t get_local_port() const {
        return params_.local_port;
    }

    // Get remote IP/port
    uint32_t get_remote_ip() const {
        return params_.remote_ip;
    }

    uint16_t get_remote_port() const {
        return params_.remote_port;
    }

private:
    // Send TCP segment
    void send_tcp_segment(uint8_t flags, const uint8_t* data, uint16_t len) {
        if (!ip_) {
            throw std::runtime_error("TCPConnection: IP layer not initialized");
        }

        printf("[TCP-DEBUG] Sending TCP segment: flags=0x%02x, seq=%u, ack=%u, len=%u\n",
               flags, params_.snd_nxt, params_.rcv_nxt, len);

        // Build TCP header
        uint8_t packet[1500];
        TCPHeader* tcp = reinterpret_cast<TCPHeader*>(packet);

        tcp->source = htons(params_.local_port);
        tcp->dest = htons(params_.remote_port);
        tcp->seq = htonl(params_.snd_nxt);

        if (flags & TCP_FLAG_ACK) {
            tcp->ack_seq = htonl(params_.rcv_nxt);
        } else {
            tcp->ack_seq = 0;
        }

        // Determine TCP header length based on flags
        size_t tcp_header_len = TCP_HEADER_MIN_LEN;

        // Add TCP options for SYN packets
        if (flags & TCP_FLAG_SYN) {
            // Data offset = 6 (24 bytes: 20-byte header + 4-byte MSS option)
            tcp->doff_reserved = 0x60;  // 6 << 4

            // Add MSS option (4 bytes) - CRITICAL for modern TCP
            uint8_t* options = packet + TCP_HEADER_MIN_LEN;
            options[0] = 2;    // MSS option kind
            options[1] = 4;    // MSS option length
            options[2] = (USERSPACE_TCP_MSS >> 8) & 0xFF;  // MSS high byte (1460 >> 8 = 5)
            options[3] = USERSPACE_TCP_MSS & 0xFF;         // MSS low byte (1460 & 0xFF = 180)

            tcp_header_len = 24;  // 20 + 4 bytes MSS option

            printf("[TCP-DEBUG] Added MSS option: %u bytes\n", USERSPACE_TCP_MSS);
        } else {
            // Data offset = 5 (20 bytes, no options)
            tcp->doff_reserved = 0x50;  // 5 << 4
        }

        tcp->flags = flags;
        tcp->window = htons(static_cast<uint16_t>(params_.rcv_wnd));
        tcp->check = 0;  // Calculate later
        tcp->urg_ptr = 0;

        // Copy data if present
        if (data && len > 0) {
            std::memcpy(packet + tcp_header_len, data, len);
        }

        // Calculate TCP checksum (includes options if present)
        // Note: tcp_checksum expects IPs in HOST byte order, not network byte order
        // Function returns checksum in host byte order, convert to network byte order
        tcp->check = htons(tcp_checksum(params_.local_ip, params_.remote_ip,
                                       tcp, tcp_header_len, data, len));

        // Send via IP layer
        ip_->send_packet(params_.remote_ip, IP_PROTO_TCP, packet,
                        tcp_header_len + len);

        timers_.last_send_time_us = get_time_us();
    }

    // Process received packets
    void process_rx() {
        uint8_t protocol;
        uint8_t* payload;
        size_t len;
        uint32_t src_ip;

        if (!ip_->recv_packet(&protocol, &payload, &len, &src_ip)) {
            return;  // No packet
        }

        printf("[TCP-DEBUG] Received IP packet: proto=%u, len=%zu, src=%s\n",
               protocol, len, ip_to_string(src_ip).c_str());

        // Check if TCP packet
        if (protocol != IP_PROTO_TCP) {
            ip_->release_rx_packet();
            return;
        }

        // Validate TCP packet size
        if (len < TCP_HEADER_MIN_LEN) {
            ip_->release_rx_packet();
            return;
        }

        // Parse TCP header
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(payload);

        // Check if packet is for this connection
        if (ntohs(tcp->dest) != params_.local_port ||
            ntohs(tcp->source) != params_.remote_port ||
            src_ip != params_.remote_ip) {
            ip_->release_rx_packet();
            return;  // Not for us
        }

        // Verify TCP checksum
        size_t header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (header_len < TCP_HEADER_MIN_LEN || header_len > len) {
            ip_->release_rx_packet();
            return;
        }

        size_t data_len = len - header_len;
        const uint8_t* data = payload + header_len;

        // Verify TCP checksum (expects IPs in host byte order)
        if (verify_tcp_checksum(params_.remote_ip, params_.local_ip,
                               tcp, header_len, data, data_len) != 0) {
            ip_->release_rx_packet();
            return;  // Invalid checksum
        }

        // Extract TCP fields
        uint32_t seq = ntohl(tcp->seq);
        uint32_t ack = ntohl(tcp->ack_seq);
        uint8_t flags = tcp->flags;
        uint16_t window = ntohs(tcp->window);

        // Update send window
        params_.snd_wnd = window;

        // Process based on state
        process_tcp_segment(seq, ack, flags, data, data_len);

        ip_->release_rx_packet();
        timers_.last_recv_time_us = get_time_us();
    }

    // Process TCP segment based on state
    void process_tcp_segment(uint32_t seq, uint32_t ack, uint8_t flags,
                            const uint8_t* data, size_t len) {
        // Handle RST
        if (flags & TCP_FLAG_RST) {
            has_error_ = true;
            error_msg_ = "Connection reset by peer";
            state_ = TCPState::CLOSED;
            return;
        }

        switch (state_) {
        case TCPState::SYN_SENT:
            handle_syn_sent(seq, ack, flags);
            break;

        case TCPState::ESTABLISHED:
            handle_established(seq, ack, flags, data, len);
            break;

        case TCPState::FIN_WAIT_1:
        case TCPState::FIN_WAIT_2:
            handle_fin_wait(seq, ack, flags);
            break;

        case TCPState::CLOSE_WAIT:
            handle_close_wait(seq, ack, flags);
            break;

        default:
            break;
        }
    }

    // Handle SYN_SENT state
    void handle_syn_sent(uint32_t seq, uint32_t ack, uint8_t flags) {
        printf("[TCP-DEBUG] In SYN_SENT state: seq=%u, ack=%u, flags=0x%02x\n",
               seq, ack, flags);

        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            printf("[TCP-DEBUG] Received SYN-ACK! (expected ack=%u, got=%u)\n",
                   params_.snd_nxt, ack);

            // Got SYN-ACK
            if (ack != params_.snd_nxt) {
                printf("[TCP-DEBUG] ACK mismatch! Ignoring.\n");
                return;  // Invalid ACK
            }

            // Remove SYN from retransmit queue
            retransmit_queue_.remove_acked(ack);

            // Update receive sequence
            params_.rcv_nxt = seq + 1;
            params_.snd_una = ack;

            // Send final ACK to complete handshake
            printf("[TCP-DEBUG] Sending final ACK to complete handshake\n");
            send_tcp_segment(TCP_FLAG_ACK, nullptr, 0);

            state_ = TCPState::ESTABLISHED;
            printf("[TCP-DEBUG] Connection ESTABLISHED!\n");
        } else {
            printf("[TCP-DEBUG] Not a SYN-ACK (flags=0x%02x), ignoring\n", flags);
        }
    }

    // Handle ESTABLISHED state
    void handle_established(uint32_t seq, uint32_t ack, uint8_t flags,
                           const uint8_t* data, size_t len) {
        // Process ACK
        if (flags & TCP_FLAG_ACK) {
            if (seq_gt(ack, params_.snd_una)) {
                // Remove acknowledged segments
                retransmit_queue_.remove_acked(ack);
                params_.snd_una = ack;
            }
        }

        // Process data
        if (len > 0) {
            if (seq == params_.rcv_nxt) {
                // In-order data
                recv_buffer_.append(data, len);
                params_.rcv_nxt += len;

                // Send ACK
                send_tcp_segment(TCP_FLAG_ACK, nullptr, 0);
            } else if (seq_gt(seq, params_.rcv_nxt)) {
                // Out-of-order (future) data - send duplicate ACK
                send_tcp_segment(TCP_FLAG_ACK, nullptr, 0);
            }
            // If seq < rcv_nxt, it's old data (already received), ignore
        }

        // Handle FIN
        if (flags & TCP_FLAG_FIN) {
            params_.rcv_nxt++;
            send_tcp_segment(TCP_FLAG_ACK, nullptr, 0);
            state_ = TCPState::CLOSE_WAIT;
        }
    }

    // Handle FIN_WAIT states
    void handle_fin_wait(uint32_t seq, uint32_t ack, uint8_t flags) {
        (void)seq;

        // Process ACK
        if (flags & TCP_FLAG_ACK) {
            if (seq_ge(ack, params_.snd_una)) {
                retransmit_queue_.remove_acked(ack);
                params_.snd_una = ack;
            }

            if (state_ == TCPState::FIN_WAIT_1) {
                // Our FIN was acknowledged
                state_ = TCPState::FIN_WAIT_2;
            }
        }

        // Handle FIN
        if (flags & TCP_FLAG_FIN) {
            params_.rcv_nxt++;
            send_tcp_segment(TCP_FLAG_ACK, nullptr, 0);
            state_ = TCPState::TIME_WAIT;

            // Simplified: Don't actually wait 2MSL, just close
            state_ = TCPState::CLOSED;
        }
    }

    // Handle CLOSE_WAIT state
    void handle_close_wait(uint32_t seq, uint32_t ack, uint8_t flags) {
        (void)seq;
        (void)flags;

        // Process ACK
        if (seq_ge(ack, params_.snd_una)) {
            retransmit_queue_.remove_acked(ack);
            params_.snd_una = ack;
        }
    }

    // Check and perform retransmissions
    void check_retransmit() {
        auto segments = retransmit_queue_.get_retransmit_segments(timers_.rto);

        for (auto* seg : segments) {
            // Retransmit segment
            send_tcp_segment(seg->flags, seg->data, seg->len);
            retransmit_queue_.mark_retransmitted(seg->seq);
        }

        // Check if connection is dead (too many retransmits)
        if (retransmit_queue_.has_failed_segment()) {
            has_error_ = true;
            error_msg_ = "Connection timed out (too many retransmits)";
            state_ = TCPState::CLOSED;
        }
    }

    // Generate random port number (ephemeral range)
    static uint16_t generate_random_port() {
        // Seed random on first call
        static bool seeded = false;
        if (!seeded) {
            std::srand(static_cast<unsigned>(std::time(nullptr)));
            seeded = true;
        }
        return static_cast<uint16_t>(32768 + (std::rand() % 28232));  // 32768-60999
    }

    // Generate initial sequence number
    static uint32_t generate_isn() {
        // Seed random on first call
        static bool seeded = false;
        if (!seeded) {
            std::srand(static_cast<unsigned>(std::time(nullptr)));
            seeded = true;
        }
        return static_cast<uint32_t>(std::rand());
    }

    // Get current time in microseconds
    static uint64_t get_time_us() {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
    }

    // Helper: Convert IP to string (for debugging)
    static std::string ip_to_string(uint32_t ip_host_order) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                (ip_host_order >> 24) & 0xFF,
                (ip_host_order >> 16) & 0xFF,
                (ip_host_order >> 8) & 0xFF,
                ip_host_order & 0xFF);
        return std::string(buf);
    }
};

} // namespace userspace_stack
