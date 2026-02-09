// src/xdp/bpf/exchange_filter.bpf.c
// eBPF program to filter exchange traffic to AF_XDP socket with NIC hardware timestamps
//
// This program runs in the kernel at the XDP hook (earliest possible point).
// It parses packets and redirects exchange traffic to AF_XDP socket while
// passing other traffic (SSH, DNS, HTTP) to the kernel network stack.
//
// NIC Hardware Timestamps:
// - Uses bpf_xdp_metadata_rx_timestamp() kfunc to get NIC RX timestamp
// - Requires BPF_F_XDP_DEV_BOUND_ONLY flag when loading (kernel 6.3+, igc support 6.5+)
// - Stores timestamp in XDP metadata area before packet data
//
// Compile with:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/bpf -c exchange_filter.bpf.c -o exchange_filter.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XDP metadata kfunc (kernel 6.3+)
// Requires BPF_F_XDP_DEV_BOUND_ONLY flag when loading
extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx, __u64 *timestamp) __ksym;

// XDP metadata structure stored before packet data (16 bytes)
// After bpf_xdp_adjust_meta(), this structure is placed in the metadata area.
// Layout in UMEM: [xdp_user_metadata (16 bytes)][packet data]
//                 ^                              ^
//                 data_meta                      data
struct xdp_user_metadata {
    __u64 rx_timestamp_ns;   // Hardware RX timestamp (nanoseconds, 0 if unavailable)
    __u64 bpf_entry_ns;      // bpf_ktime_get_ns() at XDP program entry
};

// BPF Map: AF_XDP socket map for XDP_REDIRECT
// Key: queue_id, Value: xsk file descriptor
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// BPF Map: Exchange IP addresses (dynamic configuration)
// Key: IP address (network byte order), Value: 1 (enabled)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u8);
} exchange_ips SEC(".maps");

// BPF Map: Exchange ports (dynamic configuration)
// Key: Port number (host byte order), Value: 1 (enabled)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);
    __type(value, __u8);
} exchange_ports SEC(".maps");

// BPF Map: Statistics (for monitoring)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// BPF Map: Local IP address (for destination-based filtering)
// Key: 0, Value: Local IP address in network byte order
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} local_ip SEC(".maps");

// Statistics indices
#define STAT_TOTAL_PACKETS      0
#define STAT_EXCHANGE_PACKETS   1
#define STAT_KERNEL_PACKETS     2
#define STAT_DROPPED_PACKETS    3
#define STAT_PARSE_ERRORS       4
#define STAT_IPV4_PACKETS       5
#define STAT_TCP_PACKETS        6
#define STAT_NON_TCP_PACKETS    7
#define STAT_INCOMING_CHECK     8  // Incoming packets (dst_ip = local_ip)
#define STAT_IP_MATCH           9  // Exchange IP+port matched
#define STAT_TIMESTAMP_OK      10  // HW timestamp extracted successfully
#define STAT_TIMESTAMP_FAIL    11  // HW timestamp extraction failed

// Helper to increment statistics
static __always_inline void inc_stat(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// Helper to extract NIC hardware timestamp and BPF entry time into XDP metadata area
// Returns 0 on success (redirect should proceed), -1 on failure (pass to kernel)
static __always_inline int extract_hw_timestamp(struct xdp_md *ctx, __u64 bpf_entry_ns) {
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_user_metadata));
    if (ret != 0) {
        // adjust_meta failed - likely no headroom
        return -1;
    }

    void *data = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct xdp_user_metadata *meta = data_meta;

    // Verify metadata fits before data
    if ((void *)(meta + 1) > data) {
        return -1;
    }

    // Store BPF entry timestamp (always available)
    meta->bpf_entry_ns = bpf_entry_ns;

    // Extract NIC hardware timestamp
    __u64 timestamp = 0;
    ret = bpf_xdp_metadata_rx_timestamp(ctx, &timestamp);
    if (ret == 0 && timestamp != 0) {
        meta->rx_timestamp_ns = timestamp;
        inc_stat(STAT_TIMESTAMP_OK);
    } else {
        meta->rx_timestamp_ns = 0;
        inc_stat(STAT_TIMESTAMP_FAIL);
    }

    return 0;
}

// Packet parsing context
struct parse_ctx {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 ip_src;
    __u32 ip_dst;
    __u16 tcp_sport;
    __u16 tcp_dport;
};

// Parse Ethernet header
static __always_inline int parse_ethernet(struct xdp_md *ctx, struct parse_ctx *pctx) {
    pctx->data = (void *)(long)ctx->data;
    pctx->data_end = (void *)(long)ctx->data_end;

    // Check if we have enough space for Ethernet header
    if (pctx->data + sizeof(struct ethhdr) > pctx->data_end) {
        return -1;
    }

    pctx->eth = (struct ethhdr *)pctx->data;
    return 0;
}

// Parse IPv4 header
static __always_inline int parse_ipv4(struct parse_ctx *pctx) {
    void *data = (void *)pctx->eth + sizeof(struct ethhdr);

    // Check if we have enough space for IP header
    if (data + sizeof(struct iphdr) > pctx->data_end) {
        return -1;
    }

    struct iphdr *ip = (struct iphdr *)data;

    // Validate IP header length (IHL must be >= 5)
    if (ip->ihl < 5) {
        return -1;  // Reject packets with invalid IHL
    }

    // Check if we have the full IP header (including any IP options)
    if (data + (ip->ihl * 4) > pctx->data_end) {
        return -1;
    }

    pctx->ip = ip;
    pctx->ip_src = ip->saddr;  // Network byte order
    pctx->ip_dst = ip->daddr;  // Network byte order

    return 0;
}

// Parse TCP header
static __always_inline int parse_tcp(struct parse_ctx *pctx) {
    // TCP header starts after IP header (accounting for IP options)
    void *data = (void *)pctx->ip + (pctx->ip->ihl * 4);

    // Check if we have enough space for TCP header
    if (data + sizeof(struct tcphdr) > pctx->data_end) {
        return -1;
    }

    struct tcphdr *tcp = (struct tcphdr *)data;

    pctx->tcp = tcp;
    pctx->tcp_sport = bpf_ntohs(tcp->source);  // Convert to host byte order
    pctx->tcp_dport = bpf_ntohs(tcp->dest);    // Convert to host byte order

    return 0;
}

// Check if packet is exchange traffic (INCOMING ONLY)
// NOTE: We ONLY redirect incoming responses, NOT outgoing requests.
//       Outgoing packets go through kernel normally (for routing, NAT, etc.)
//
// Matching criteria:
//   - Destination IP = our local IP (incoming packet)
//   - Source IP is in exchange_ips map (e.g., Binance server)
//   - Source port is in exchange_ports map (e.g., 443)
static __always_inline int is_exchange_packet(struct parse_ctx *pctx) {
    // ONLY check INCOMING packets: destination IP = our local IP
    __u32 key = 0;
    __u32 *our_ip = bpf_map_lookup_elem(&local_ip, &key);

    if (!our_ip || pctx->ip_dst != *our_ip) {
        // Not destined to us - this is an outgoing packet or packet for someone else
        return 0;
    }

    inc_stat(STAT_INCOMING_CHECK);  // Debug: Checked incoming path

    // Check if source is from exchange (IP + port must both match)
    __u8 *src_ip_val = bpf_map_lookup_elem(&exchange_ips, &pctx->ip_src);
    __u8 *src_port_val = bpf_map_lookup_elem(&exchange_ports, &pctx->tcp_sport);

    if (src_ip_val && *src_ip_val != 0 && src_port_val && *src_port_val != 0) {
        inc_stat(STAT_IP_MATCH);
        return 1;
    }

    return 0;  // Not exchange traffic
}

SEC("xdp")
int exchange_packet_filter(struct xdp_md *ctx) {
    // Capture BPF entry timestamp immediately (kernel monotonic clock)
    __u64 bpf_entry_ns = bpf_ktime_get_ns();

    struct parse_ctx pctx = {};
    int ret;

    // Increment total packet counter
    inc_stat(STAT_TOTAL_PACKETS);

    // Parse Ethernet header
    ret = parse_ethernet(ctx, &pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;  // Pass malformed packets to kernel
    }

    // Check if IPv4 (we only handle IPv4)
    if (pctx.eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Not IPv4 (could be ARP, IPv6, etc.)
        return XDP_PASS;  // Pass to kernel stack
    }

    inc_stat(STAT_IPV4_PACKETS);

    // Parse IPv4 header
    ret = parse_ipv4(&pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;  // Pass malformed packets to kernel
    }

    // Check if TCP (we only filter TCP traffic)
    if (pctx.ip->protocol != IPPROTO_TCP) {
        // Redirect trickle packets (UDP to 127.0.0.1) to XSK to preserve FILL ring frames
        // Trickle packets are self-addressed L2 packets used for NAPI polling workaround
        // We redirect instead of drop so frames are properly returned to FILL ring
        if (pctx.ip->protocol == IPPROTO_UDP &&
            pctx.ip->saddr == bpf_htonl(0x7f000001) &&  // 127.0.0.1
            pctx.ip->daddr == bpf_htonl(0x7f000001)) {
            inc_stat(STAT_NON_TCP_PACKETS);
            // Redirect to XSK - frame will be properly refilled when processed
            return bpf_redirect_map(&xsks_map, 0, 0);
        }

        // Redirect ICMP Echo Reply from exchange IPs (for ping-based testing)
        if (pctx.ip->protocol == IPPROTO_ICMP) {
            // Check if from exchange IP and destined to us
            __u32 key = 0;
            __u32 *our_ip = bpf_map_lookup_elem(&local_ip, &key);
            if (our_ip && pctx.ip_dst == *our_ip) {
                __u8 *src_ip_val = bpf_map_lookup_elem(&exchange_ips, &pctx.ip_src);
                if (src_ip_val && *src_ip_val != 0) {
                    inc_stat(STAT_EXCHANGE_PACKETS);

                    // Extract HW timestamp and BPF entry time into metadata area
                    extract_hw_timestamp(ctx, bpf_entry_ns);

                    // Redirect ICMP from exchange to XSK
                    return bpf_redirect_map(&xsks_map, 0, 0);
                }
            }
        }

        inc_stat(STAT_NON_TCP_PACKETS);
        return XDP_PASS;  // Pass non-TCP (UDP, ICMP, etc.) to kernel
    }

    inc_stat(STAT_TCP_PACKETS);

    // Parse TCP header
    ret = parse_tcp(&pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;  // Pass malformed packets to kernel
    }

    // Check if this is exchange traffic
    if (is_exchange_packet(&pctx)) {
        // Drop truncated frames: IP header declares more bytes than the frame contains.
        // This catches NIC/driver bugs where rx_desc->len < ETH + ip->tot_len.
        // Without this check, userspace abort()s on the mismatch.
        // Compare as scalars (data_end - data) to avoid pkt pointer + unbounded var.
        __u16 ip_total = bpf_ntohs(pctx.ip->tot_len);
        __u32 frame_len = (__u32)(pctx.data_end - pctx.data);
        if (frame_len < sizeof(struct ethhdr) + ip_total) {
            inc_stat(STAT_DROPPED_PACKETS);
            return XDP_DROP;
        }

        inc_stat(STAT_EXCHANGE_PACKETS);

        // Extract NIC hardware RX timestamp and BPF entry time into metadata area
        extract_hw_timestamp(ctx, bpf_entry_ns);

        // Redirect to AF_XDP socket on queue 0
        return bpf_redirect_map(&xsks_map, 0, 0);
    }

    // Not exchange traffic - pass to kernel stack
    inc_stat(STAT_KERNEL_PACKETS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
