// src/xdp/bpf/exchange_filter.bpf.c
// eBPF program to filter exchange traffic to AF_XDP socket
//
// This program runs in the kernel at the XDP hook (earliest possible point).
// It parses packets and redirects exchange traffic to AF_XDP socket while
// passing other traffic (SSH, DNS, HTTP) to the kernel network stack.
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
#define STAT_INCOMING_CHECK     8  // Phase 1 debug: checked incoming path
#define STAT_IP_MATCH           9  // Phase 1 debug: destination IP matched
#define STAT_PORT_MATCH        10  // Phase 1 debug: destination port matched

// Helper to increment statistics
static __always_inline void inc_stat(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
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
        bpf_printk("IP parse FAILED: ihl=%d < 5", ip->ihl);
        return -1;  // Reject packets with invalid IHL
    }

    // Log if packet has IP options
    if (ip->ihl > 5) {
        bpf_printk("IP has options: ihl=%d (len=%d bytes)", ip->ihl, ip->ihl * 4);
    }

    // Check if we have the full IP header
    if (data + (ip->ihl * 4) > pctx->data_end) {
        bpf_printk("IP bounds check FAILED: need %d bytes", ip->ihl * 4);
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
// PHASE 1: Destination-based filtering to handle load-balanced backends
// NOTE: We ONLY redirect incoming responses, NOT outgoing requests.
//       Outgoing packets go through kernel normally (for routing, NAT, etc.)
static __always_inline int is_exchange_packet(struct parse_ctx *pctx) {
    // ONLY Check INCOMING packets: destination IP = our local IP
    __u32 key = 0;
    __u32 *our_ip = bpf_map_lookup_elem(&local_ip, &key);

    if (!our_ip || pctx->ip_dst != *our_ip) {
        // Not destined to us - this is an outgoing packet or packet for someone else
        return 0;
    }

    inc_stat(STAT_INCOMING_CHECK);  // Debug: Checked incoming path
    inc_stat(STAT_IP_MATCH);  // Debug: Destination IP matched

    // Log incoming packet details
    bpf_printk("INCOMING: src=%pI4:%d dst=%pI4:%d", &pctx->ip_src, pctx->tcp_sport, &pctx->ip_dst, pctx->tcp_dport);

    // Check if destination port is in ephemeral range
    // Ephemeral ports: 60000-65535 (used by client connections)
    if (pctx->tcp_dport >= 60000) {
        inc_stat(STAT_PORT_MATCH);  // Debug: Port matched too!
        bpf_printk("MATCH: ephemeral port %d -> REDIRECT", pctx->tcp_dport);
        // Incoming to our IP on ephemeral port - exchange response
        return 1;
    }

    // Also check if source is from exchange (for established connections)
    __u8 *src_ip_val = bpf_map_lookup_elem(&exchange_ips, &pctx->ip_src);
    __u8 *src_port_val = bpf_map_lookup_elem(&exchange_ports, &pctx->tcp_sport);

    if (src_ip_val && *src_ip_val != 0 && src_port_val && *src_port_val != 0) {
        // Incoming from exchange: src_ip=exchange AND src_port=exchange_port
        bpf_printk("MATCH: exchange IP+port -> REDIRECT");
        return 1;
    }

    bpf_printk("NO MATCH: port %d not ephemeral, exchange lookup failed", pctx->tcp_dport);
    return 0;  // Not exchange traffic
}

SEC("xdp")
int exchange_packet_filter(struct xdp_md *ctx) {
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
        inc_stat(STAT_NON_TCP_PACKETS);
        return XDP_PASS;  // Pass non-TCP (UDP, ICMP, etc.) to kernel
    }

    inc_stat(STAT_TCP_PACKETS);

    // Parse TCP header
    ret = parse_tcp(&pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        bpf_printk("TCP parse FAILED - passing to kernel");
        return XDP_PASS;  // Pass malformed packets to kernel
    }

    // Check if this is exchange traffic
    if (is_exchange_packet(&pctx)) {
        inc_stat(STAT_EXCHANGE_PACKETS);

        // Redirect to AF_XDP socket on queue 0
        // We always use queue 0 regardless of which queue the packet arrived on,
        // since we only have one AF_XDP socket registered on queue 0.
        // This avoids issues with RSS (Receive Side Scaling) distributing packets
        // across multiple queues.
        __u32 queue_id = 0;
        int redirect_ret = bpf_redirect_map(&xsks_map, queue_id, 0);
        bpf_printk("REDIRECT to XSK queue 0, ret=%d", redirect_ret);
        return redirect_ret;
    }

    // Not exchange traffic - pass to kernel stack
    inc_stat(STAT_KERNEL_PACKETS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
