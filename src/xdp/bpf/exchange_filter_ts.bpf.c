// src/xdp/bpf/exchange_filter_ts.bpf.c
// eBPF program with XDP RX metadata timestamp extraction
//
// This program extracts hardware timestamps from the NIC via XDP metadata.
// Requires: Linux kernel 6.3+ and NIC driver with XDP RX metadata support
//
// Compile with:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -c exchange_filter_ts.bpf.c -o exchange_filter_ts.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XDP metadata kfuncs (kernel 6.3+)
// These are kernel functions (kfuncs), not traditional BPF helpers
// They must be declared with the extern __ksym attribute
//
// Available XDP metadata kfuncs:
// - bpf_xdp_metadata_rx_timestamp() - Get hardware RX timestamp
// - bpf_xdp_metadata_rx_hash() - Get packet hash
// - bpf_xdp_metadata_rx_vlan_tag() - Get VLAN tag
//
// Returns:
//   0 on success
//  -EOPNOTSUPP if driver doesn't support this metadata
//  -ENODATA if metadata is not available for this packet

// Declare XDP metadata kfuncs as external kernel symbols
extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx, __u64 *timestamp) __ksym;
extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash, __u32 *hash_type) __ksym;

// Metadata structure stored before packet data
struct xdp_meta_data {
    __u64 rx_timestamp;  // Hardware timestamp from NIC (nanoseconds)
    __u32 timestamp_valid;  // 1 if timestamp is valid, 0 otherwise
};

// BPF Map: AF_XDP socket map for XDP_REDIRECT
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// BPF Map: Exchange IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u8);
} exchange_ips SEC(".maps");

// BPF Map: Exchange ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);
    __type(value, __u8);
} exchange_ports SEC(".maps");

// BPF Map: Statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Statistics indices
#define STAT_TOTAL_PACKETS      0
#define STAT_EXCHANGE_PACKETS   1
#define STAT_KERNEL_PACKETS     2
#define STAT_DROPPED_PACKETS    3
#define STAT_PARSE_ERRORS       4
#define STAT_IPV4_PACKETS       5
#define STAT_TCP_PACKETS        6
#define STAT_NON_TCP_PACKETS    7
#define STAT_TIMESTAMP_SUCCESS  8  // Successful timestamp extractions
#define STAT_TIMESTAMP_FAILED   9  // Failed timestamp extractions

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

    if (pctx->data + sizeof(struct ethhdr) > pctx->data_end) {
        return -1;
    }

    pctx->eth = (struct ethhdr *)pctx->data;
    return 0;
}

// Parse IPv4 header
static __always_inline int parse_ipv4(struct parse_ctx *pctx) {
    void *data = (void *)pctx->eth + sizeof(struct ethhdr);

    if (data + sizeof(struct iphdr) > pctx->data_end) {
        return -1;
    }

    struct iphdr *ip = (struct iphdr *)data;

    if (ip->ihl != 5) {
        return -1;
    }

    if (data + (ip->ihl * 4) > pctx->data_end) {
        return -1;
    }

    pctx->ip = ip;
    pctx->ip_src = ip->saddr;
    pctx->ip_dst = ip->daddr;

    return 0;
}

// Parse TCP header
static __always_inline int parse_tcp(struct parse_ctx *pctx) {
    void *data = (void *)pctx->ip + sizeof(struct iphdr);

    if (data + sizeof(struct tcphdr) > pctx->data_end) {
        return -1;
    }

    struct tcphdr *tcp = (struct tcphdr *)data;

    pctx->tcp = tcp;
    pctx->tcp_sport = bpf_ntohs(tcp->source);
    pctx->tcp_dport = bpf_ntohs(tcp->dest);

    return 0;
}

// Check if packet is exchange traffic
static __always_inline int is_exchange_packet(struct parse_ctx *pctx) {
    __u8 *ip_val = bpf_map_lookup_elem(&exchange_ips, &pctx->ip_dst);
    if (!ip_val || *ip_val == 0) {
        return 0;
    }

    __u8 *port_val = bpf_map_lookup_elem(&exchange_ports, &pctx->tcp_dport);
    if (!port_val || *port_val == 0) {
        return 0;
    }

    return 1;
}

SEC("xdp")
int exchange_packet_filter_ts(struct xdp_md *ctx) {
    struct parse_ctx pctx = {};
    int ret;

    // Increment total packet counter
    inc_stat(STAT_TOTAL_PACKETS);

    // Step 1: Try to reserve space for metadata before packet
    // This allows us to store the hardware timestamp
    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta_data));
    if (ret < 0) {
        // Metadata adjustment failed - continue without timestamp
        // This is not fatal, just means we can't store timestamp
    }

    // Update pointers after potential meta adjustment
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Step 2: Try to extract hardware timestamp from NIC
    struct xdp_meta_data *meta = data_meta;
    if ((void *)(meta + 1) <= data) {
        // We have valid metadata space
        __u64 timestamp = 0;

        // Attempt to get hardware RX timestamp
        // This BPF helper was added in kernel 6.3
        // Returns 0 on success, negative on failure
        ret = bpf_xdp_metadata_rx_timestamp(ctx, &timestamp);

        if (ret == 0 && timestamp != 0) {
            // Success! Store the hardware timestamp
            meta->rx_timestamp = timestamp;
            meta->timestamp_valid = 1;
            inc_stat(STAT_TIMESTAMP_SUCCESS);
        } else {
            // Timestamp not available (driver doesn't support it)
            meta->rx_timestamp = 0;
            meta->timestamp_valid = 0;
            inc_stat(STAT_TIMESTAMP_FAILED);
        }
    } else {
        // No metadata space - continue without timestamp
        inc_stat(STAT_TIMESTAMP_FAILED);
    }

    // Step 3: Parse Ethernet header
    ret = parse_ethernet(ctx, &pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;
    }

    // Step 4: Check if IPv4
    if (pctx.eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    inc_stat(STAT_IPV4_PACKETS);

    // Step 5: Parse IPv4 header
    ret = parse_ipv4(&pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;
    }

    // Step 6: Check if TCP
    if (pctx.ip->protocol != IPPROTO_TCP) {
        inc_stat(STAT_NON_TCP_PACKETS);
        return XDP_PASS;
    }

    inc_stat(STAT_TCP_PACKETS);

    // Step 7: Parse TCP header
    ret = parse_tcp(&pctx);
    if (ret < 0) {
        inc_stat(STAT_PARSE_ERRORS);
        return XDP_PASS;
    }

    // Step 8: Check if this is exchange traffic
    if (is_exchange_packet(&pctx)) {
        inc_stat(STAT_EXCHANGE_PACKETS);

        // Redirect to AF_XDP socket
        __u32 queue_id = ctx->rx_queue_index;
        return bpf_redirect_map(&xsks_map, queue_id, 0);
    }

    // Not exchange traffic - pass to kernel stack
    inc_stat(STAT_KERNEL_PACKETS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
