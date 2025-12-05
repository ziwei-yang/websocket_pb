// src/stack/tcp/tcp_packet.hpp
// Pure TCP Packet Building and Parsing (Internal)
//
// INTERNAL: Use UserspaceStack (userspace_stack.hpp) as the entry point.
//
// Provides:
//   - TCPPacket::build()   - Build TCP/IP/Ethernet frame into buffer
//   - TCPPacket::parse()   - Parse raw frame into TCPParseResult
//   - TCPPacket::process() - Pure state machine (state + input → action + new_state)
//
// Design:
//   - PURE FUNCTIONS: No side effects, no I/O
//   - STATELESS: No internal state, all state passed as parameters
//   - ZERO-COPY: Writes directly into provided buffer (UMEM)

#pragma once

#include "tcp_state.hpp"
#include "../ip/ip_layer.hpp"
#include "../ip/checksum.hpp"
#include "../mac/ethernet.hpp"
#include <cstring>
#include <cstdio>

namespace userspace_stack {

// Result of parsing an incoming TCP segment
struct TCPParseResult {
    bool valid = false;           // Was parsing successful?
    uint32_t seq = 0;             // Sequence number
    uint32_t ack = 0;             // Acknowledgment number
    uint8_t flags = 0;            // TCP flags
    uint16_t window = 0;          // Window size
    const uint8_t* payload = nullptr;  // Pointer to payload data
    size_t payload_len = 0;       // Payload length
    uint16_t src_port = 0;        // Source port
    uint16_t dst_port = 0;        // Destination port
    uint32_t src_ip = 0;          // Source IP (host byte order)
};

// Action to take after processing a TCP segment
enum class TCPAction {
    NONE,           // No action needed
    SEND_SYN,       // Send SYN packet
    SEND_ACK,       // Send ACK packet
    SEND_DATA,      // Send data packet
    SEND_FIN,       // Send FIN packet
    SEND_RST,       // Send RST packet
    CONNECTED,      // Connection established
    DATA_RECEIVED,  // Data received (in payload)
    CLOSED,         // Connection closed
    ERROR           // Error occurred
};

// Result of processing a TCP segment through state machine
struct TCPProcessResult {
    TCPAction action = TCPAction::NONE;
    TCPState new_state = TCPState::CLOSED;
    bool state_changed = false;
    const uint8_t* data = nullptr;  // For DATA_RECEIVED: pointer to received data
    size_t data_len = 0;            // For DATA_RECEIVED: length of data
};

/**
 * Pure TCP Packet Builder/Parser
 *
 * Stateless operations only - builds and parses TCP packets.
 * All state management and control flow belongs in transport policy.
 */
struct TCPPacket {
    /**
     * Build a TCP segment into the provided buffer
     *
     * Layout: [Ethernet 14B][IP 20B][TCP 20-24B][Data]
     *
     * @param buffer Output buffer (must be large enough)
     * @param capacity Buffer capacity
     * @param params TCP connection parameters
     * @param flags TCP flags to set
     * @param data Payload data (can be nullptr)
     * @param data_len Payload length
     * @param local_mac Source MAC address
     * @param gateway_mac Destination MAC address
     * @param ip_id IP identification field
     * @return Total frame length, or 0 on error
     */
    static size_t build(
        uint8_t* buffer,
        size_t capacity,
        const TCPParams& params,
        uint8_t flags,
        const uint8_t* data,
        size_t data_len,
        const uint8_t* local_mac,
        const uint8_t* gateway_mac,
        uint16_t ip_id
    ) {
        if (!buffer || !local_mac || !gateway_mac) {
            return 0;
        }

        // Calculate TCP header length
        size_t tcp_header_len = TCP_HEADER_MIN_LEN;
        if (flags & TCP_FLAG_SYN) {
            tcp_header_len = 24;  // 20 + 4 bytes MSS option
        }

        size_t total_len = ETH_HEADER_LEN + IP_HEADER_LEN + tcp_header_len + data_len;
        if (total_len > capacity) {
            return 0;
        }

        // Offsets
        constexpr size_t eth_offset = 0;
        constexpr size_t ip_offset = ETH_HEADER_LEN;
        constexpr size_t tcp_offset = ETH_HEADER_LEN + IP_HEADER_LEN;
        size_t data_offset = tcp_offset + tcp_header_len;

        // === Build TCP header ===
        TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buffer + tcp_offset);
        tcp->source = htons(params.local_port);
        tcp->dest = htons(params.remote_port);
        tcp->seq = htonl(params.snd_nxt);
        tcp->ack_seq = (flags & TCP_FLAG_ACK) ? htonl(params.rcv_nxt) : 0;

        if (flags & TCP_FLAG_SYN) {
            tcp->doff_reserved = 0x60;  // 6 << 4 (24 bytes header)
            // Add MSS option
            uint8_t* options = buffer + tcp_offset + TCP_HEADER_MIN_LEN;
            options[0] = TCP_OPT_MSS;
            options[1] = 4;
            options[2] = (USERSPACE_TCP_MSS >> 8) & 0xFF;
            options[3] = USERSPACE_TCP_MSS & 0xFF;
        } else {
            tcp->doff_reserved = 0x50;  // 5 << 4 (20 bytes header)
        }

        tcp->flags = flags;
        tcp->window = htons(static_cast<uint16_t>(params.rcv_wnd));
        tcp->check = 0;
        tcp->urg_ptr = 0;

        // Copy payload
        if (data && data_len > 0) {
            std::memcpy(buffer + data_offset, data, data_len);
        }

        // Calculate TCP checksum
        const uint8_t* tcp_data = (data_len > 0) ? (buffer + data_offset) : nullptr;
        tcp->check = htons(tcp_checksum(params.local_ip, params.remote_ip,
                                        tcp, tcp_header_len, tcp_data, data_len));

        // === Build IP header ===
        IPv4Header* ip_hdr = reinterpret_cast<IPv4Header*>(buffer + ip_offset);
        size_t ip_payload_len = tcp_header_len + data_len;
        ip_hdr->version_ihl = 0x45;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = htons(static_cast<uint16_t>(IP_HEADER_LEN + ip_payload_len));
        ip_hdr->id = htons(ip_id);
        ip_hdr->frag_off = htons(0x4000);  // Don't fragment
        ip_hdr->ttl = IP_DEFAULT_TTL;
        ip_hdr->protocol = IP_PROTO_TCP;
        ip_hdr->check = 0;
        ip_hdr->saddr = htonl(params.local_ip);
        ip_hdr->daddr = htonl(params.remote_ip);
        ip_hdr->check = htons(ip_checksum(ip_hdr));

        // === Build Ethernet header ===
        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer + eth_offset);
        std::memcpy(eth->dst_mac, gateway_mac, ETH_ADDR_LEN);
        std::memcpy(eth->src_mac, local_mac, ETH_ADDR_LEN);
        eth->ethertype = htons(ETH_TYPE_IP);

        return total_len;
    }

    /**
     * Parse a raw Ethernet frame containing TCP
     *
     * @param frame Raw Ethernet frame data
     * @param frame_len Frame length
     * @param expected_local_ip Expected destination IP (host byte order)
     * @param expected_local_port Expected destination port
     * @param expected_remote_ip Expected source IP (host byte order), 0 to skip check
     * @param expected_remote_port Expected source port, 0 to skip check
     * @return Parse result with extracted fields
     */
    static TCPParseResult parse(
        const uint8_t* frame,
        size_t frame_len,
        uint32_t expected_local_ip,
        uint16_t expected_local_port,
        uint32_t expected_remote_ip = 0,
        uint16_t expected_remote_port = 0
    ) {
        TCPParseResult result;

        // Minimum frame size check
        if (!frame || frame_len < ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_MIN_LEN) {
            return result;
        }

        // Parse Ethernet header
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(frame);
        if (ntohs(eth->ethertype) != ETH_TYPE_IP) {
            return result;  // Not IPv4
        }

        // Parse IP header
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(frame + ETH_HEADER_LEN);

        // Validate IP version and header length
        uint8_t version = (ip->version_ihl >> 4) & 0x0F;
        uint8_t ihl = ip->version_ihl & 0x0F;
        if (version != 4 || ihl < 5) {
            return result;
        }

        // Check protocol
        if (ip->protocol != IP_PROTO_TCP) {
            return result;
        }

        // Extract IPs
        result.src_ip = ntohl(ip->saddr);
        uint32_t dst_ip = ntohl(ip->daddr);

        // Validate destination IP
        if (dst_ip != expected_local_ip) {
            return result;
        }

        // Validate source IP if specified
        if (expected_remote_ip != 0 && result.src_ip != expected_remote_ip) {
            return result;
        }

        // Calculate IP header length and payload offset
        size_t ip_header_len = ihl * 4;
        size_t tcp_offset = ETH_HEADER_LEN + ip_header_len;

        // Get IP total length
        uint16_t ip_total_len = ntohs(ip->tot_len);
        size_t ip_payload_len = ip_total_len - ip_header_len;

        // Validate TCP header fits
        if (frame_len < tcp_offset + TCP_HEADER_MIN_LEN) {
            return result;
        }

        // Parse TCP header
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(frame + tcp_offset);

        result.src_port = ntohs(tcp->source);
        result.dst_port = ntohs(tcp->dest);

        // Validate ports
        if (result.dst_port != expected_local_port) {
            return result;
        }
        if (expected_remote_port != 0 && result.src_port != expected_remote_port) {
            return result;
        }

        // Get TCP header length
        size_t tcp_header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (tcp_header_len < TCP_HEADER_MIN_LEN || tcp_header_len > ip_payload_len) {
            return result;
        }

        // Verify TCP checksum
        size_t tcp_data_len = ip_payload_len - tcp_header_len;
        const uint8_t* tcp_data = (tcp_data_len > 0) ? (frame + tcp_offset + tcp_header_len) : nullptr;

        if (verify_tcp_checksum(result.src_ip, expected_local_ip,
                               tcp, tcp_header_len, tcp_data, tcp_data_len) != 0) {
            return result;  // Invalid checksum
        }

        // Extract TCP fields
        result.seq = ntohl(tcp->seq);
        result.ack = ntohl(tcp->ack_seq);
        result.flags = tcp->flags;
        result.window = ntohs(tcp->window);
        result.payload = tcp_data;
        result.payload_len = tcp_data_len;
        result.valid = true;

        return result;
    }

    /**
     * Process a parsed TCP segment through the state machine
     *
     * This is a PURE function: given current state + input → output action + new state
     * No side effects, no I/O.
     *
     * @param current_state Current TCP state
     * @param params Current TCP parameters (for validation)
     * @param parsed Parsed TCP segment
     * @return Processing result with action to take and new state
     */
    static TCPProcessResult process(
        TCPState current_state,
        const TCPParams& params,
        const TCPParseResult& parsed
    ) {
        TCPProcessResult result;
        result.new_state = current_state;

        if (!parsed.valid) {
            return result;
        }

        // Handle RST
        if (parsed.flags & TCP_FLAG_RST) {
            result.action = TCPAction::CLOSED;
            result.new_state = TCPState::CLOSED;
            result.state_changed = true;
            return result;
        }

        switch (current_state) {
        case TCPState::SYN_SENT:
            return process_syn_sent(params, parsed);

        case TCPState::ESTABLISHED:
            return process_established(params, parsed);

        case TCPState::FIN_WAIT_1:
        case TCPState::FIN_WAIT_2:
            return process_fin_wait(current_state, params, parsed);

        case TCPState::CLOSE_WAIT:
            return process_close_wait(params, parsed);

        default:
            return result;
        }
    }

private:
    static TCPProcessResult process_syn_sent(const TCPParams& params, const TCPParseResult& parsed) {
        TCPProcessResult result;
        result.new_state = TCPState::SYN_SENT;

        // Expecting SYN-ACK
        if ((parsed.flags & TCP_FLAG_SYN) && (parsed.flags & TCP_FLAG_ACK)) {
            // Validate ACK
            if (parsed.ack != params.snd_nxt) {
                return result;  // Invalid ACK, ignore
            }

            // SYN-ACK received, need to send ACK
            result.action = TCPAction::SEND_ACK;
            result.new_state = TCPState::ESTABLISHED;
            result.state_changed = true;
        }

        return result;
    }

    static TCPProcessResult process_established(const TCPParams& params, const TCPParseResult& parsed) {
        TCPProcessResult result;
        result.new_state = TCPState::ESTABLISHED;

        // Check for FIN
        if (parsed.flags & TCP_FLAG_FIN) {
            result.action = TCPAction::SEND_ACK;
            result.new_state = TCPState::CLOSE_WAIT;
            result.state_changed = true;
            return result;
        }

        // Check for data
        if (parsed.payload_len > 0) {
            // Validate sequence number (in-order delivery only for HFT)
            if (parsed.seq == params.rcv_nxt) {
                result.action = TCPAction::DATA_RECEIVED;
                result.data = parsed.payload;
                result.data_len = parsed.payload_len;
            } else {
                // Out of order - send duplicate ACK
                result.action = TCPAction::SEND_ACK;
            }
        }
        // Pure ACK with no data - no action needed from state machine perspective
        // (ACK processing is done by transport to update snd_una)

        return result;
    }

    static TCPProcessResult process_fin_wait(TCPState current_state, const TCPParams& params, const TCPParseResult& parsed) {
        (void)params;
        TCPProcessResult result;
        result.new_state = current_state;

        if (parsed.flags & TCP_FLAG_ACK) {
            if (current_state == TCPState::FIN_WAIT_1) {
                result.new_state = TCPState::FIN_WAIT_2;
                result.state_changed = true;
            }
        }

        if (parsed.flags & TCP_FLAG_FIN) {
            result.action = TCPAction::SEND_ACK;
            result.new_state = TCPState::CLOSED;  // Simplified: skip TIME_WAIT
            result.state_changed = true;
        }

        return result;
    }

    static TCPProcessResult process_close_wait(const TCPParams& params, const TCPParseResult& parsed) {
        (void)params;
        (void)parsed;
        TCPProcessResult result;
        result.new_state = TCPState::CLOSE_WAIT;
        // In CLOSE_WAIT, we're waiting for application to close
        // Just process ACKs (handled by transport)
        return result;
    }
};

} // namespace userspace_stack
