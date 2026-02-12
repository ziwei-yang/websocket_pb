// net/ip_probe.hpp
// Standalone IP probe library for DNS resolution, RTT measurement, and IP ranking.
// Header-only, no pipeline dependencies. C++20, return-code error handling (no exceptions).
//
// Usage:
//   auto result = websocket::net::probe("stream.binance.com");
//   if (result.ok()) {
//       for (const auto& e : result.entries)
//           printf("%s  rtt=%ldus\n", e.ip_str, e.rtt_us);
//   }
//
//   websocket::net::IpSelector sel;
//   sel.build(result);
//   const auto* fastest = sel.fastest();
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>
#include <numeric>
#include <cmath>
#include <cstdio>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <net/if.h>
#include <errno.h>
#include <time.h>

namespace websocket::net {

// ============================================================================
// Status and Error Reporting
// ============================================================================

/// Status code for the overall probe operation.
enum class ProbeStatus : uint8_t {
    OK           = 0,  // All resolved IPs probed successfully
    PARTIAL      = 1,  // Some IPs reachable, some timed out or refused
    DNS_FAILURE  = 2,  // getaddrinfo() failed entirely
    ALL_TIMEOUT  = 3,  // DNS succeeded but every probe timed out
    NO_RESULT    = 4,  // DNS returned zero addresses
    NO_INTERFACE = 5,  // Could not detect a suitable probe interface
};

inline const char* probe_status_str(ProbeStatus s) {
    switch (s) {
        case ProbeStatus::OK:           return "OK";
        case ProbeStatus::PARTIAL:      return "PARTIAL";
        case ProbeStatus::DNS_FAILURE:  return "DNS_FAILURE";
        case ProbeStatus::ALL_TIMEOUT:  return "ALL_TIMEOUT";
        case ProbeStatus::NO_RESULT:    return "NO_RESULT";
        case ProbeStatus::NO_INTERFACE: return "NO_INTERFACE";
    }
    return "UNKNOWN";
}

// ============================================================================
// Data Structures
// ============================================================================

/// Per-IP probe entry with full metadata.
struct ProbeEntry {
    // Address storage (dual-stack)
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } addr{};
    int family = 0;                         // AF_INET or AF_INET6
    char ip_str[INET6_ADDRSTRLEN] = {};     // Human-readable

    // Probe results
    int64_t rtt_us      = -1;   // Median RTT in microseconds (-1 = unreachable)
    int64_t min_rtt_us  = -1;   // Best RTT observed
    int64_t max_rtt_us  = -1;   // Worst RTT observed
    int     probes_sent = 0;    // Number of probes attempted
    int     probes_ok   = 0;    // Number of successful probes
    int     error_code  = 0;    // Last errno on failure (0 = no error)

    // Convenience accessors (IPv4)
    uint32_t ipv4_net()  const { return (family == AF_INET) ? addr.v4.s_addr : 0; }
    uint32_t ipv4_host() const { return (family == AF_INET) ? ntohl(addr.v4.s_addr) : 0; }
    bool     reachable() const { return rtt_us >= 0; }
};

/// Aggregate probe result for an entire domain.
struct ProbeResult {
    ProbeStatus            status = ProbeStatus::NO_RESULT;
    std::vector<ProbeEntry> entries;          // Sorted: reachable by rtt_us asc, unreachable at end
    std::string            probe_interface;   // Interface used for SO_BINDTODEVICE

    // Summary statistics
    int  dns_resolved = 0;   // Total IPs from DNS
    int  reachable    = 0;   // IPs with at least one successful probe
    char error[256]   = {};  // Human-readable error message (for DNS_FAILURE etc.)

    // Convenience
    bool ok()        const { return status == ProbeStatus::OK || status == ProbeStatus::PARTIAL; }
    int  ip_count()  const { return static_cast<int>(entries.size()); }
};

/// Configuration for a probe operation.
struct ProbeConfig {
    uint16_t    port            = 443;         // TCP port to probe
    uint32_t    probe_count     = 3;           // Probes per IP (use median)
    uint32_t    timeout_ms      = 200;         // Per-probe timeout in ms
    const char* bind_interface  = nullptr;     // SO_BINDTODEVICE target (nullptr = OS default)
    int         family          = AF_UNSPEC;   // AF_INET, AF_INET6, or AF_UNSPEC (both)
};

// ============================================================================
// 1. DNS Resolution
// ============================================================================

/// Find the first non-loopback nameserver from /etc/resolv.conf (or resolvconf chain).
/// Returns "" if only 127.0.0.53 / 127.0.0.1 found.
inline std::string find_upstream_nameserver() {
    // systemd-resolved exposes the real upstream via its runtime config
    FILE* fp = fopen("/run/systemd/resolve/resolv.conf", "r");
    if (!fp) fp = fopen("/etc/resolv.conf", "r");
    if (!fp) return "";

    std::string upstream;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char ns[128];
        if (sscanf(line, "nameserver %127s", ns) == 1) {
            // Skip loopback stubs
            if (strncmp(ns, "127.", 4) == 0 || strcmp(ns, "::1") == 0) continue;
            upstream = ns;
            break;
        }
    }
    fclose(fp);
    return upstream;
}

/// Build a DNS A-record query packet. Returns length, or -1 on error.
inline int build_dns_query(const char* hostname, uint8_t* buf, size_t buf_len) {
    if (buf_len < 512) return -1;
    size_t off = 0;

    // Header: ID=0x1234, flags=RD, QDCOUNT=1
    buf[off++] = 0x12; buf[off++] = 0x34;  // Transaction ID
    buf[off++] = 0x01; buf[off++] = 0x00;  // Flags: RD=1 (recursion desired)
    buf[off++] = 0x00; buf[off++] = 0x01;  // QDCOUNT = 1
    buf[off++] = 0x00; buf[off++] = 0x00;  // ANCOUNT = 0
    buf[off++] = 0x00; buf[off++] = 0x00;  // NSCOUNT = 0
    buf[off++] = 0x00; buf[off++] = 0x00;  // ARCOUNT = 0

    // Question: encode hostname as DNS labels
    const char* p = hostname;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t label_len = dot ? static_cast<size_t>(dot - p) : strlen(p);
        if (label_len > 63 || off + 1 + label_len >= buf_len - 5) return -1;
        buf[off++] = static_cast<uint8_t>(label_len);
        std::memcpy(buf + off, p, label_len);
        off += label_len;
        p += label_len + (dot ? 1 : 0);
        if (!dot) break;
    }
    buf[off++] = 0x00;  // Root label

    // QTYPE = A (1), QCLASS = IN (1)
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x01;

    return static_cast<int>(off);
}

/// Skip a DNS name (handles compression pointers). Returns new offset, or -1.
inline int skip_dns_name(const uint8_t* buf, int len, int off) {
    while (off < len) {
        uint8_t label_len = buf[off];
        if (label_len == 0) return off + 1;                 // Root label
        if ((label_len & 0xC0) == 0xC0) return off + 2;     // Compression pointer
        off += 1 + label_len;
    }
    return -1;
}

/// Send raw DNS A-record query via UDP to a specific nameserver.
/// Bypasses systemd-resolved stub which may truncate results.
/// Returns 0 on success, -1 on failure.
inline int resolve_via_udp(const char* hostname, const char* nameserver,
                           std::vector<ProbeEntry>& out) {
    // Build DNS query
    uint8_t query[512];
    int qlen = build_dns_query(hostname, query, sizeof(query));
    if (qlen < 0) return -1;

    // Create UDP socket to nameserver
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_in ns_addr = {};
    ns_addr.sin_family = AF_INET;
    ns_addr.sin_port = htons(53);
    inet_pton(AF_INET, nameserver, &ns_addr.sin_addr);

    // Send query
    if (sendto(fd, query, qlen, 0,
               reinterpret_cast<struct sockaddr*>(&ns_addr), sizeof(ns_addr)) < 0) {
        close(fd);
        return -1;
    }

    // Wait for response (2s timeout)
    struct pollfd pfd = {fd, POLLIN, 0};
    if (poll(&pfd, 1, 2000) <= 0) {
        close(fd);
        return -1;
    }

    uint8_t resp[4096];
    ssize_t rlen = recvfrom(fd, resp, sizeof(resp), 0, nullptr, nullptr);
    close(fd);
    if (rlen < 12) return -1;

    // Parse DNS response header
    int flags = (resp[2] << 8) | resp[3];
    if ((flags & 0x8000) == 0) return -1;  // Not a response
    int rcode = flags & 0x0F;
    if (rcode != 0) return -1;  // DNS error

    int qdcount = (resp[4] << 8) | resp[5];
    int ancount = (resp[6] << 8) | resp[7];

    // Skip question section
    int off = 12;
    for (int i = 0; i < qdcount && off < rlen; i++) {
        off = skip_dns_name(resp, static_cast<int>(rlen), off);
        if (off < 0) return -1;
        off += 4;  // QTYPE + QCLASS
    }

    // Parse answer section — extract A records
    for (int i = 0; i < ancount && off + 12 <= rlen; i++) {
        off = skip_dns_name(resp, static_cast<int>(rlen), off);
        if (off < 0 || off + 10 > rlen) break;

        uint16_t rtype  = (resp[off] << 8) | resp[off + 1];
        // uint16_t rclass = (resp[off + 2] << 8) | resp[off + 3];
        // uint32_t ttl = ...
        uint16_t rdlen  = (resp[off + 8] << 8) | resp[off + 9];
        off += 10;

        if (rtype == 1 && rdlen == 4 && off + 4 <= rlen) {
            // A record: 4-byte IPv4 address
            ProbeEntry entry;
            entry.family = AF_INET;
            std::memcpy(&entry.addr.v4, resp + off, 4);
            inet_ntop(AF_INET, &entry.addr.v4, entry.ip_str, sizeof(entry.ip_str));

            // Deduplicate by binary address
            bool dup = false;
            for (const auto& existing : out) {
                if (existing.family == AF_INET &&
                    existing.addr.v4.s_addr == entry.addr.v4.s_addr) {
                    dup = true; break;
                }
            }
            if (!dup) out.push_back(entry);
        }
        off += rdlen;
    }

    return out.empty() ? -1 : 0;
}

/// Resolve all unique IPs for hostname.
/// Tries direct UDP query to upstream nameserver first (bypasses systemd-resolved),
/// then falls back to getaddrinfo().
/// Returns 0 on success, -1 on DNS failure.
inline int resolve_all(const char* hostname, int family, std::vector<ProbeEntry>& out) {
    // Try direct UDP DNS to bypass systemd-resolved stub (which may return only 1 IP)
    if (family == AF_INET || family == AF_UNSPEC) {
        std::string upstream = find_upstream_nameserver();
        if (!upstream.empty()) {
            if (resolve_via_udp(hostname, upstream.c_str(), out) == 0) {
                fprintf(stderr, "[IP-PROBE] DNS via %s: %zu IPs resolved\n",
                        upstream.c_str(), out.size());
                return 0;
            }
            fprintf(stderr, "[IP-PROBE] Direct DNS via %s failed, falling back to getaddrinfo\n",
                    upstream.c_str());
        }
    }

    // Fallback: standard getaddrinfo (may go through systemd-resolved)
    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, nullptr, &hints, &result);
    if (ret != 0 || !result) {
        if (result) freeaddrinfo(result);
        return -1;
    }

    for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
        ProbeEntry entry;
        entry.family = p->ai_family;

        if (p->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            entry.addr.v4 = sa->sin_addr;
            inet_ntop(AF_INET, &sa->sin_addr, entry.ip_str, sizeof(entry.ip_str));
        } else if (p->ai_family == AF_INET6) {
            auto* sa = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            entry.addr.v6 = sa->sin6_addr;
            inet_ntop(AF_INET6, &sa->sin6_addr, entry.ip_str, sizeof(entry.ip_str));
        } else {
            continue;
        }

        // Deduplicate
        bool dup = false;
        for (const auto& existing : out) {
            if (strcmp(existing.ip_str, entry.ip_str) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            out.push_back(entry);
        }
    }

    freeaddrinfo(result);
    return 0;
}

// ============================================================================
// 2. Interface Detection (Linux)
// ============================================================================

/// Find a network interface with a default route, excluding exclude_interface.
/// Linux: parses /proc/net/route
inline std::string detect_probe_interface(const char* exclude_interface) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return "";

    char line[256];
    // Skip header
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return ""; }

    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned int dest, gateway;
        if (sscanf(line, "%31s %x %x", iface, &dest, &gateway) >= 3) {
            // Default route: Destination == 0, Gateway != 0
            if (dest == 0 && gateway != 0) {
                if (exclude_interface && strcmp(iface, exclude_interface) == 0) {
                    continue;  // Skip the XDP interface
                }
                fclose(fp);
                return iface;
            }
        }
    }

    fclose(fp);
    return "";
}

// ============================================================================
// 3. Single IP Probe
// ============================================================================

/// TCP SYN probe a single IP. Returns RTT in microseconds, or -1 on failure.
inline int64_t probe_one(ProbeEntry& entry, uint16_t port,
                         const char* bind_interface, uint32_t timeout_ms) {
    int fd = socket(entry.family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        entry.error_code = errno;
        return -1;
    }

    // Bind to interface if requested
    if (bind_interface && bind_interface[0]) {
#ifdef __linux__
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                       bind_interface, strlen(bind_interface) + 1) < 0) {
            // Non-fatal: proceed without binding (may go via wrong interface)
            fprintf(stderr, "[IP-PROBE] WARNING: SO_BINDTODEVICE(%s) failed: %s\n",
                    bind_interface, strerror(errno));
        }
#elif defined(__APPLE__)
        unsigned int ifindex = if_nametoindex(bind_interface);
        if (ifindex > 0) {
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
        }
#endif
    }

    // Build sockaddr
    struct sockaddr_storage ss = {};
    socklen_t ss_len = 0;

    if (entry.family == AF_INET) {
        auto* sa = reinterpret_cast<struct sockaddr_in*>(&ss);
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        sa->sin_addr = entry.addr.v4;
        ss_len = sizeof(struct sockaddr_in);
    } else {
        auto* sa = reinterpret_cast<struct sockaddr_in6*>(&ss);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        sa->sin6_addr = entry.addr.v6;
        ss_len = sizeof(struct sockaddr_in6);
    }

    // Measure connect RTT
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&ss), ss_len);
    if (rc == 0) {
        // Immediate connect (loopback)
        clock_gettime(CLOCK_MONOTONIC, &t1);
        close(fd);
        int64_t rtt = (t1.tv_sec - t0.tv_sec) * 1000000LL +
                      (t1.tv_nsec - t0.tv_nsec) / 1000LL;
        return rtt;
    }

    if (errno != EINPROGRESS) {
        entry.error_code = errno;
        close(fd);
        return -1;
    }

    // Wait for connect completion
    struct pollfd pfd = {fd, POLLOUT, 0};
    int poll_rc = poll(&pfd, 1, static_cast<int>(timeout_ms));

    if (poll_rc <= 0) {
        // Timeout or error
        entry.error_code = (poll_rc == 0) ? ETIMEDOUT : errno;
        close(fd);
        return -1;
    }

    // Check connect result
    int err = 0;
    socklen_t err_len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);

    if (err != 0) {
        entry.error_code = err;
        close(fd);
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(fd);

    int64_t rtt = (t1.tv_sec - t0.tv_sec) * 1000000LL +
                  (t1.tv_nsec - t0.tv_nsec) / 1000LL;
    return rtt;
}

// ============================================================================
// 4. Probe All IPs + Rank
// ============================================================================

/// Probe all entries, fill in RTT fields, sort by median RTT ascending.
inline void probe_and_rank(std::vector<ProbeEntry>& entries,
                           uint16_t port, const char* bind_interface,
                           uint32_t probe_count, uint32_t timeout_ms) {
    for (auto& entry : entries) {
        std::vector<int64_t> rtts;
        rtts.reserve(probe_count);

        for (uint32_t i = 0; i < probe_count; i++) {
            int64_t rtt = probe_one(entry, port, bind_interface, timeout_ms);
            entry.probes_sent++;
            if (rtt >= 0) {
                rtts.push_back(rtt);
                entry.probes_ok++;
            }
        }

        if (!rtts.empty()) {
            std::sort(rtts.begin(), rtts.end());
            entry.rtt_us = rtts[rtts.size() / 2];  // Median
            entry.min_rtt_us = rtts.front();
            entry.max_rtt_us = rtts.back();
        }
        // else: rtt_us stays -1 (unreachable)
    }

    // Sort: reachable first by rtt_us ascending, unreachable at end
    std::sort(entries.begin(), entries.end(), [](const ProbeEntry& a, const ProbeEntry& b) {
        if (a.reachable() != b.reachable()) return a.reachable();
        if (a.reachable() && b.reachable()) return a.rtt_us < b.rtt_us;
        return false;
    });
}

// ============================================================================
// 5. Top-Level: Full Probe Pipeline
// ============================================================================

/// Complete probe: resolve DNS -> probe all -> rank -> set status.
inline ProbeResult probe(const char* hostname, const ProbeConfig& config = {}) {
    ProbeResult result;

    // 1. DNS resolve
    if (resolve_all(hostname, config.family, result.entries) != 0) {
        result.status = ProbeStatus::DNS_FAILURE;
        snprintf(result.error, sizeof(result.error), "getaddrinfo(%s) failed", hostname);
        return result;
    }

    if (result.entries.empty()) {
        result.status = ProbeStatus::NO_RESULT;
        snprintf(result.error, sizeof(result.error), "DNS returned 0 addresses for %s", hostname);
        return result;
    }

    result.dns_resolved = static_cast<int>(result.entries.size());

    // 2. Determine bind interface
    const char* bind_iface = config.bind_interface;
    if (bind_iface) {
        result.probe_interface = bind_iface;
    }

    // 3. Probe and rank
    probe_and_rank(result.entries, config.port, bind_iface,
                   config.probe_count, config.timeout_ms);

    // 4. Count reachable
    result.reachable = 0;
    for (const auto& e : result.entries) {
        if (e.reachable()) result.reachable++;
    }

    // 5. Set status
    if (result.reachable == result.dns_resolved) {
        result.status = ProbeStatus::OK;
    } else if (result.reachable > 0) {
        result.status = ProbeStatus::PARTIAL;
    } else {
        result.status = ProbeStatus::ALL_TIMEOUT;
        snprintf(result.error, sizeof(result.error),
                 "All %d IPs timed out for %s", result.dns_resolved, hostname);
    }

    return result;
}

// ============================================================================
// IpSelector — Latency-aware IP selector with rotation and dual-connection support
// ============================================================================

struct IpSelector {
    std::vector<ProbeEntry> preferred;   // Filtered, sorted by RTT ascending
    size_t rotation_index = 0;           // For sequential rotation

    /// Build from ProbeResult with latency filtering.
    /// Returns 0 on success, -1 if no reachable IPs.
    int build(const ProbeResult& result) {
        preferred.clear();
        rotation_index = 0;

        // Collect reachable entries
        for (const auto& e : result.entries) {
            if (e.reachable()) preferred.push_back(e);
        }
        if (preferred.empty()) return -1;

        // Already sorted by RTT from probe_and_rank()

        // If <=2 IPs: keep all, no filtering needed
        if (preferred.size() <= 2) return 0;

        // Compute mean + stddev of RTTs
        double sum = 0, sum_sq = 0;
        for (const auto& e : preferred) {
            sum += static_cast<double>(e.rtt_us);
            sum_sq += static_cast<double>(e.rtt_us) * static_cast<double>(e.rtt_us);
        }
        double n = static_cast<double>(preferred.size());
        double mean = sum / n;
        double stddev = std::sqrt((sum_sq / n) - (mean * mean));
        double threshold = mean + stddev;

        // Filter: keep entries within threshold, but always keep >=2
        size_t keep = 0;
        for (size_t i = 0; i < preferred.size(); i++) {
            if (static_cast<double>(preferred[i].rtt_us) <= threshold || keep < 2) {
                keep = i + 1;
            } else {
                break;  // Sorted, so remaining are all above threshold
            }
        }
        preferred.resize(keep);
        return 0;
    }

    /// Number of preferred IPs.
    size_t count() const { return preferred.size(); }

    // ── Single Connection Mode ──

    /// Get the fastest IP. Returns nullptr if empty.
    const ProbeEntry* fastest() const {
        return preferred.empty() ? nullptr : &preferred[0];
    }

    /// Get next IP in rotation (wraps around). Returns nullptr if empty.
    const ProbeEntry* next() {
        if (preferred.empty()) return nullptr;
        const ProbeEntry* e = &preferred[rotation_index % preferred.size()];
        rotation_index++;
        return e;
    }

    /// Reset rotation to start from fastest again.
    void reset_rotation() { rotation_index = 0; }

    // ── Dual Connection Mode ──

    /// Initial assignment: a = fastest, b = second fastest.
    /// Returns false if fewer than 2 preferred IPs.
    bool assign_dual(const ProbeEntry*& a, const ProbeEntry*& b) const {
        if (preferred.empty()) { a = nullptr; b = nullptr; return false; }
        a = &preferred[0];
        if (preferred.size() < 2) { b = nullptr; return false; }
        b = &preferred[1];
        return true;
    }

    /// Choose reconnect IP for one connection, avoiding other_ip if possible.
    const ProbeEntry* next_for_reconnect(uint32_t other_ip_net) {
        if (preferred.empty()) return nullptr;
        // Find lowest-latency IP that differs from other connection
        for (const auto& e : preferred) {
            if (e.ipv4_net() != other_ip_net) return &e;
        }
        // All IPs are the same (single IP from DNS) — use rotation
        return next();
    }
};

// ============================================================================
// Logging Helper
// ============================================================================

inline void print_probe_result(const ProbeResult& result) {
    fprintf(stderr, "[IP-PROBE] Status: %s  (resolved=%d, reachable=%d",
            probe_status_str(result.status), result.dns_resolved, result.reachable);
    if (!result.probe_interface.empty()) {
        fprintf(stderr, ", iface=%s", result.probe_interface.c_str());
    }
    fprintf(stderr, ")\n");

    for (const auto& e : result.entries) {
        if (e.reachable()) {
            fprintf(stderr, "[IP-PROBE]   %-40s  rtt=%4ld us  (min=%ld, max=%ld, ok=%d/%d)\n",
                    e.ip_str, e.rtt_us, e.min_rtt_us, e.max_rtt_us, e.probes_ok, e.probes_sent);
        } else {
            fprintf(stderr, "[IP-PROBE]   %-40s  UNREACHABLE  (err=%d: %s, ok=%d/%d)\n",
                    e.ip_str, e.error_code, strerror(e.error_code), e.probes_ok, e.probes_sent);
        }
    }
}

}  // namespace websocket::net
