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
    size_t payload_len = 0;       // Payload length (actual available data)
    size_t orig_payload_len = 0;  // Original payload length from IP header (for rcv_nxt)
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
        // Timestamps enabled if ts_val is set (caller controls this)
        bool include_timestamp = (params.ts_val != 0);
        size_t tcp_header_len = TCP_HEADER_MIN_LEN;
        if (flags & TCP_FLAG_SYN) {
            // SYN options order (matches Linux kernel):
            //   MSS(4) + SACK_OK(2) + TS(10) + NOP(1) + WS(3) = 20 bytes (40 byte header)
            //   MSS(4) + SACK_OK(2) + NOP(1) + WS(3) + NOP(2) = 12 bytes (32 byte header, no TS)
            tcp_header_len = include_timestamp ? 40 : 32;
        } else if (include_timestamp) {
            // Non-SYN with timestamps: 20 + 12 (NOP+NOP+TS)
            tcp_header_len = 32;
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
            // SYN header: 32 bytes (no TS) or 40 bytes (with TS)
            // Options order matches Linux kernel: MSS + SACK_OK + TS + NOP + WS
            tcp->doff_reserved = static_cast<uint8_t>((tcp_header_len / 4) << 4);
            uint8_t* options = buffer + tcp_offset + TCP_HEADER_MIN_LEN;
            // MSS option (4 bytes)
            options[0] = TCP_OPT_MSS;
            options[1] = 4;
            options[2] = (USERSPACE_TCP_MSS >> 8) & 0xFF;
            options[3] = USERSPACE_TCP_MSS & 0xFF;
            // SACK Permitted (2 bytes)
            options[4] = TCP_OPT_SACK_OK;  // SACK Permitted (RFC 2018)
            options[5] = 2;                // Length = 2
            if (include_timestamp) {
                // Timestamp option (10 bytes) - placed before WS to match kernel
                options[6] = TCP_OPT_TIMESTAMP;
                options[7] = TCP_TIMESTAMP_OPT_LEN;  // 10 bytes
                uint32_t ts_val_n = htonl(params.ts_val);
                std::memcpy(&options[8], &ts_val_n, 4);
                uint32_t ts_ecr_n = htonl(params.ts_ecr);
                std::memcpy(&options[12], &ts_ecr_n, 4);
                // NOP padding (1 byte)
                options[16] = TCP_OPT_NOP;
                // Window Scale (3 bytes) - RFC 7323
                options[17] = TCP_OPT_WSCALE;
                options[18] = TCP_OPT_WSCALE_LEN;  // Length = 3
                options[19] = TCP_WSCALE_CLIENT;   // Shift = 12 (2^12 = 4096x scaling)
                // Total: 4 + 2 + 10 + 1 + 3 = 20 bytes options (40 byte header)
            } else {
                // NOP padding (1 byte)
                options[6] = TCP_OPT_NOP;
                // Window Scale (3 bytes) - RFC 7323
                options[7] = TCP_OPT_WSCALE;
                options[8] = TCP_OPT_WSCALE_LEN;  // Length = 3
                options[9] = TCP_WSCALE_CLIENT;   // Shift = 12 (2^12 = 4096x scaling)
                // NOP padding to 12 bytes options (32 byte header)
                options[10] = TCP_OPT_NOP;
                options[11] = TCP_OPT_NOP;
                // Total: 4 + 2 + 1 + 3 + 2 = 12 bytes options (32 byte header)
            }
        } else if (include_timestamp) {
            // Non-SYN with timestamps: 32 bytes header
            tcp->doff_reserved = 0x80;  // 8 << 4 (32 bytes header)
            uint8_t* options = buffer + tcp_offset + TCP_HEADER_MIN_LEN;
            // Timestamp option (12 bytes: NOP + NOP + TS)
            options[0] = TCP_OPT_NOP;
            options[1] = TCP_OPT_NOP;
            options[2] = TCP_OPT_TIMESTAMP;
            options[3] = TCP_TIMESTAMP_OPT_LEN;  // 10 bytes
            uint32_t ts_val_n = htonl(params.ts_val);
            std::memcpy(&options[4], &ts_val_n, 4);
            uint32_t ts_ecr_n = htonl(params.ts_ecr);
            std::memcpy(&options[8], &ts_ecr_n, 4);
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
     * Build a TCP ACK segment with SACK blocks
     *
     * Layout: [Ethernet 14B][IP 20B][TCP 20-56B][No Data]
     *
     * Header sizes by block count:
     *   0 blocks: 20 bytes (use regular build() instead)
     *   1 block:  32 bytes (20 + 10 option + 2 padding)
     *   2 blocks: 40 bytes (20 + 18 option + 2 padding)
     *   3 blocks: 48 bytes (20 + 26 option + 2 padding)
     *   4 blocks: 56 bytes (20 + 34 option + 2 padding)
     *
     * @param buffer Output buffer
     * @param capacity Buffer capacity
     * @param params TCP connection parameters
     * @param sack_blocks SACK blocks to include
     * @param local_mac Source MAC address
     * @param gateway_mac Destination MAC address
     * @param ip_id IP identification field
     * @return Total frame length, or 0 on error
     */
    static size_t build_ack_with_sack(
        uint8_t* buffer,
        size_t capacity,
        const TCPParams& params,
        const SACKBlockArray& sack_blocks,
        const uint8_t* local_mac,
        const uint8_t* gateway_mac,
        uint16_t ip_id
    ) {
        if (!buffer || !local_mac || !gateway_mac) {
            return 0;
        }

        // If no SACK blocks, caller should use regular build()
        if (sack_blocks.count == 0) {
            return 0;
        }

        // Check if timestamps enabled
        bool include_timestamp = (params.ts_val != 0);

        // Cap SACK blocks: 4 without TS, 3 with TS (per RFC 7323)
        uint8_t max_blocks = include_timestamp ? SACK_MAX_BLOCKS_WITH_TS : SACK_MAX_BLOCKS;
        uint8_t block_count = (sack_blocks.count > max_blocks) ? max_blocks : sack_blocks.count;

        // Calculate TCP header length
        // With TS: NOP(1) + NOP(1) + TS(10) + SACK header(2) + blocks(8*n) + padding
        // Without TS: SACK header(2) + blocks(8*n) + padding
        size_t ts_opt_len = include_timestamp ? TCP_TIMESTAMP_PADDED_LEN : 0;
        size_t sack_opt_len = 2 + (block_count * SACK_BLOCK_SIZE);
        size_t options_len = ts_opt_len + sack_opt_len;
        // Padding to 4-byte alignment
        size_t padding = (4 - (options_len % 4)) % 4;
        size_t tcp_header_len = TCP_HEADER_MIN_LEN + options_len + padding;

        size_t total_len = ETH_HEADER_LEN + IP_HEADER_LEN + tcp_header_len;
        if (total_len > capacity) {
            return 0;
        }

        // Offsets
        constexpr size_t eth_offset = 0;
        constexpr size_t ip_offset = ETH_HEADER_LEN;
        constexpr size_t tcp_offset = ETH_HEADER_LEN + IP_HEADER_LEN;

        // === Build TCP header ===
        TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buffer + tcp_offset);
        tcp->source = htons(params.local_port);
        tcp->dest = htons(params.remote_port);
        tcp->seq = htonl(params.snd_nxt);
        tcp->ack_seq = htonl(params.rcv_nxt);
        tcp->doff_reserved = static_cast<uint8_t>((tcp_header_len / 4) << 4);
        tcp->flags = TCP_FLAG_ACK;
        tcp->window = htons(static_cast<uint16_t>(params.rcv_wnd));
        tcp->check = 0;
        tcp->urg_ptr = 0;

        uint8_t* opt = buffer + tcp_offset + TCP_HEADER_MIN_LEN;

        // Write timestamp option first (if enabled)
        if (include_timestamp) {
            *opt++ = TCP_OPT_NOP;
            *opt++ = TCP_OPT_NOP;
            *opt++ = TCP_OPT_TIMESTAMP;
            *opt++ = TCP_TIMESTAMP_OPT_LEN;  // 10 bytes
            uint32_t ts_val_n = htonl(params.ts_val);
            std::memcpy(opt, &ts_val_n, 4);
            opt += 4;
            uint32_t ts_ecr_n = htonl(params.ts_ecr);
            std::memcpy(opt, &ts_ecr_n, 4);
            opt += 4;
        }

        // Write SACK option: [kind=5, length, blocks...]
        *opt++ = TCP_OPT_SACK;                           // kind = 5
        *opt++ = static_cast<uint8_t>(2 + block_count * SACK_BLOCK_SIZE);  // length

        for (uint8_t i = 0; i < block_count; i++) {
            uint32_t left = htonl(sack_blocks.blocks[i].left_edge);
            uint32_t right = htonl(sack_blocks.blocks[i].right_edge);
            std::memcpy(opt, &left, 4);
            opt += 4;
            std::memcpy(opt, &right, 4);
            opt += 4;
        }

        // NOP padding to 4-byte boundary
        while ((opt - (buffer + tcp_offset)) % 4 != 0) {
            *opt++ = TCP_OPT_NOP;
        }

        // Calculate TCP checksum (no payload)
        tcp->check = htons(tcp_checksum(params.local_ip, params.remote_ip,
                                        tcp, tcp_header_len, nullptr, 0));

        // === Build IP header ===
        IPv4Header* ip_hdr = reinterpret_cast<IPv4Header*>(buffer + ip_offset);
        ip_hdr->version_ihl = 0x45;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = htons(static_cast<uint16_t>(IP_HEADER_LEN + tcp_header_len));
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
     * Build ETH/IP/TCP headers in-place, assuming payload is already at data_offset.
     * ZERO-COPY: Does NOT copy or touch payload data.
     *
     * Data offset depends on timestamp configuration:
     *   - Without timestamps: offset 54 (ETH 14 + IP 20 + TCP 20)
     *   - With timestamps:    offset 66 (ETH 14 + IP 20 + TCP 32)
     *
     * Timestamps are included if params.ts_val != 0. Caller must write payload
     * at the correct offset based on this.
     *
     * @param buffer      Destination buffer (UMEM frame)
     * @param capacity    Buffer capacity
     * @param params      TCP parameters (IPs, ports, seq/ack numbers, timestamps)
     * @param flags       TCP flags (ACK, PSH, etc.)
     * @param payload_len Length of payload already at data_offset (for checksums)
     * @param local_mac   Local MAC address
     * @param gateway_mac Gateway MAC address
     * @param ip_id       IP identification field
     * @return Total frame length (headers + payload), 0 on error
     */
    static size_t build_headers(
        uint8_t* buffer,
        size_t capacity,
        const TCPParams& params,
        uint8_t flags,
        size_t payload_len,
        const uint8_t* local_mac,
        const uint8_t* gateway_mac,
        uint16_t ip_id
    ) {
        if (!buffer || !local_mac || !gateway_mac) {
            return 0;
        }

        // TCP header size depends on timestamp option
        bool include_timestamp = (params.ts_val != 0);
        size_t tcp_header_len = include_timestamp
            ? (TCP_HEADER_MIN_LEN + TCP_TIMESTAMP_PADDED_LEN)  // 32 bytes
            : TCP_HEADER_MIN_LEN;                              // 20 bytes
        size_t data_offset = ETH_HEADER_LEN + IP_HEADER_LEN + tcp_header_len;

        size_t total_len = data_offset + payload_len;
        if (total_len > capacity) {
            return 0;
        }

        // Offsets
        constexpr size_t eth_offset = 0;
        constexpr size_t ip_offset = ETH_HEADER_LEN;
        constexpr size_t tcp_offset = ETH_HEADER_LEN + IP_HEADER_LEN;

        // === Build TCP header ===
        TCPHeader* tcp = reinterpret_cast<TCPHeader*>(buffer + tcp_offset);
        tcp->source = htons(params.local_port);
        tcp->dest = htons(params.remote_port);
        tcp->seq = htonl(params.snd_nxt);
        tcp->ack_seq = (flags & TCP_FLAG_ACK) ? htonl(params.rcv_nxt) : 0;
        tcp->doff_reserved = static_cast<uint8_t>((tcp_header_len / 4) << 4);
        tcp->flags = flags;
        tcp->window = htons(static_cast<uint16_t>(params.rcv_wnd));
        tcp->check = 0;
        tcp->urg_ptr = 0;

        // Write timestamp option if enabled
        if (include_timestamp) {
            uint8_t* opt = buffer + tcp_offset + TCP_HEADER_MIN_LEN;
            opt[0] = TCP_OPT_NOP;
            opt[1] = TCP_OPT_NOP;
            opt[2] = TCP_OPT_TIMESTAMP;
            opt[3] = TCP_TIMESTAMP_OPT_LEN;  // 10 bytes
            uint32_t ts_val_n = htonl(params.ts_val);
            std::memcpy(&opt[4], &ts_val_n, 4);
            uint32_t ts_ecr_n = htonl(params.ts_ecr);
            std::memcpy(&opt[8], &ts_ecr_n, 4);
        }

        // Calculate TCP checksum (payload is already in place at data_offset)
        const uint8_t* tcp_data = (payload_len > 0) ? (buffer + data_offset) : nullptr;
        tcp->check = htons(tcp_checksum(params.local_ip, params.remote_ip,
                                        tcp, tcp_header_len, tcp_data, payload_len));

        // === Build IP header ===
        IPv4Header* ip_hdr = reinterpret_cast<IPv4Header*>(buffer + ip_offset);
        size_t ip_payload_len = tcp_header_len + payload_len;
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

        // Calculate TCP data length from IP header (original, un-truncated)
        size_t orig_tcp_data_len = ip_payload_len - tcp_header_len;

        // Verify frame contains full payload declared by IP header
        size_t actual_data_offset = tcp_offset + tcp_header_len;
        size_t actual_data_available = (frame_len > actual_data_offset) ?
                                        (frame_len - actual_data_offset) : 0;
        if (orig_tcp_data_len > actual_data_available) {
            fprintf(stderr, "[TCP] FATAL: frame truncated - IP header declares %zu bytes payload "
                    "but frame only has %zu bytes (frame_len=%u, ip_total=%u, UMEM frame_size too small?)\n",
                    orig_tcp_data_len, actual_data_available,
                    static_cast<unsigned>(frame_len), ip_total_len);
            abort();
        }
        size_t tcp_data_len = orig_tcp_data_len;

        const uint8_t* tcp_data = (tcp_data_len > 0) ? (frame + actual_data_offset) : nullptr;

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
        result.orig_payload_len = orig_tcp_data_len;  // For rcv_nxt update
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
            if (parsed.seq == params.rcv_nxt) {
                // In-order delivery
                result.action = TCPAction::DATA_RECEIVED;
                result.data = parsed.payload;
                result.data_len = parsed.payload_len;
            } else if (seq_lt(parsed.seq, params.rcv_nxt) &&
                       seq_gt(parsed.seq + static_cast<uint32_t>(parsed.orig_payload_len),
                              params.rcv_nxt)) {
                // Overlapping retransmit: starts before rcv_nxt, extends past it.
                // Trim already-received prefix, deliver the new suffix.
                uint32_t skip = params.rcv_nxt - parsed.seq;
                if (skip < parsed.payload_len) {
                    result.action = TCPAction::DATA_RECEIVED;
                    result.data = parsed.payload + skip;
                    result.data_len = parsed.payload_len - skip;
                } else {
                    // Actual frame data doesn't reach past rcv_nxt (truncated frame)
                    result.action = TCPAction::SEND_ACK;
                }
            } else {
                // Future data (OOO) or pure duplicate - send duplicate ACK
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
