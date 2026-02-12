// test/unittest/test_ip_probe.cpp
// Unit test for IP probe library — DNS resolution, probing, and IpSelector
// Requires network access (queries real DNS + TCP probes to stream.binance.com)

#include "../../src/net/ip_probe.hpp"
#include <cstdio>
#include <cstdlib>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("  %-55s", name); \
    fflush(stdout); \
    {

#define END_TEST \
    } \
    printf("PASS\n"); \
    tests_passed++;

#define ASSERT(cond, msg) \
    if (!(cond)) { \
        printf("FAIL: %s\n", msg); \
        tests_failed++; \
        goto next; \
    }

// ============================================================================
// Tests
// ============================================================================

void test_find_upstream_nameserver() {
    TEST("find_upstream_nameserver()")
        auto ns = websocket::net::find_upstream_nameserver();
        ASSERT(!ns.empty(), "No upstream nameserver found")
        ASSERT(ns.find("127.") == std::string::npos, "Should not return loopback stub")
        printf("[%s] ", ns.c_str());
    END_TEST
    next:;
}

void test_resolve_via_udp() {
    TEST("resolve_via_udp(stream.binance.com)")
        auto ns = websocket::net::find_upstream_nameserver();
        ASSERT(!ns.empty(), "No upstream nameserver")
        std::vector<websocket::net::ProbeEntry> entries;
        int rc = websocket::net::resolve_via_udp("stream.binance.com", ns.c_str(), entries);
        ASSERT(rc == 0, "resolve_via_udp failed")
        ASSERT(entries.size() > 5, "Expected >5 IPs from stream.binance.com")
        printf("[%zu IPs] ", entries.size());
    END_TEST
    next:;
}

void test_resolve_all_bypasses_stub() {
    TEST("resolve_all() bypasses systemd-resolved")
        std::vector<websocket::net::ProbeEntry> entries;
        int rc = websocket::net::resolve_all("stream.binance.com", AF_INET, entries);
        ASSERT(rc == 0, "resolve_all failed")
        ASSERT(entries.size() > 5, "Expected >5 IPs (systemd-resolved returns only 1)")
        printf("[%zu IPs] ", entries.size());
    END_TEST
    next:;
}

void test_detect_probe_interface() {
    TEST("detect_probe_interface()")
        auto iface = websocket::net::detect_probe_interface("enp108s0");
        ASSERT(!iface.empty(), "No probe interface found")
        ASSERT(iface != "enp108s0", "Should exclude XDP interface")
        printf("[%s] ", iface.c_str());
    END_TEST
    next:;
}

void test_probe_full_pipeline() {
    TEST("probe(stream.binance.com) full pipeline")
        websocket::net::ProbeConfig cfg;
        cfg.port = 443;
        cfg.probe_count = 2;
        cfg.timeout_ms = 500;
        cfg.family = AF_INET;

        auto iface = websocket::net::detect_probe_interface("enp108s0");
        if (!iface.empty()) cfg.bind_interface = iface.c_str();

        auto result = websocket::net::probe("stream.binance.com", cfg);
        ASSERT(result.ok(), "Probe failed")
        ASSERT(result.dns_resolved > 5, "Expected >5 IPs resolved")
        ASSERT(result.reachable > 0, "Expected at least 1 reachable IP")
        printf("[resolved=%d reachable=%d] ", result.dns_resolved, result.reachable);
    END_TEST
    next:;
}

void test_ip_selector_build() {
    TEST("IpSelector::build() with latency filtering")
        websocket::net::ProbeConfig cfg;
        cfg.port = 443;
        cfg.probe_count = 2;
        cfg.timeout_ms = 500;
        cfg.family = AF_INET;

        auto iface = websocket::net::detect_probe_interface("enp108s0");
        if (!iface.empty()) cfg.bind_interface = iface.c_str();

        auto result = websocket::net::probe("stream.binance.com", cfg);
        ASSERT(result.ok(), "Probe failed")

        websocket::net::IpSelector sel;
        int rc = sel.build(result);
        ASSERT(rc == 0, "IpSelector build failed")
        ASSERT(sel.count() >= 2, "Expected >=2 preferred IPs")
        printf("[%zu preferred] ", sel.count());
    END_TEST
    next:;
}

void test_ip_selector_dual_assign() {
    TEST("IpSelector::assign_dual() returns different IPs")
        websocket::net::ProbeConfig cfg;
        cfg.port = 443;
        cfg.probe_count = 2;
        cfg.timeout_ms = 500;
        cfg.family = AF_INET;

        auto iface = websocket::net::detect_probe_interface("enp108s0");
        if (!iface.empty()) cfg.bind_interface = iface.c_str();

        auto result = websocket::net::probe("stream.binance.com", cfg);
        ASSERT(result.ok(), "Probe failed")

        websocket::net::IpSelector sel;
        sel.build(result);
        ASSERT(sel.count() >= 2, "Need >=2 IPs for dual assign")

        const websocket::net::ProbeEntry* a = nullptr;
        const websocket::net::ProbeEntry* b = nullptr;
        bool ok = sel.assign_dual(a, b);
        ASSERT(ok, "assign_dual failed")
        ASSERT(a && b, "Both pointers must be set")
        ASSERT(a->ipv4_net() != b->ipv4_net(), "A and B should be different IPs")
        printf("[A=%s B=%s] ", a->ip_str, b->ip_str);
    END_TEST
    next:;
}

void test_ip_selector_next_for_reconnect() {
    TEST("IpSelector::next_for_reconnect() avoids other IP")
        websocket::net::ProbeConfig cfg;
        cfg.port = 443;
        cfg.probe_count = 2;
        cfg.timeout_ms = 500;
        cfg.family = AF_INET;

        auto iface = websocket::net::detect_probe_interface("enp108s0");
        if (!iface.empty()) cfg.bind_interface = iface.c_str();

        auto result = websocket::net::probe("stream.binance.com", cfg);
        ASSERT(result.ok(), "Probe failed")

        websocket::net::IpSelector sel;
        sel.build(result);
        ASSERT(sel.count() >= 2, "Need >=2 IPs")

        const websocket::net::ProbeEntry* a = nullptr;
        const websocket::net::ProbeEntry* b = nullptr;
        sel.assign_dual(a, b);
        ASSERT(a && b, "assign_dual failed")

        // Reconnect conn A, avoiding B's IP
        const auto* new_a = sel.next_for_reconnect(b->ipv4_net());
        ASSERT(new_a != nullptr, "next_for_reconnect returned null")
        ASSERT(new_a->ipv4_net() != b->ipv4_net(), "Should avoid other conn's IP")
        printf("[reconnect=%s != %s] ", new_a->ip_str, b->ip_str);
    END_TEST
    next:;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("\n=== IP Probe Library Tests ===\n\n");

    test_find_upstream_nameserver();
    test_resolve_via_udp();
    test_resolve_all_bypasses_stub();
    test_detect_probe_interface();
    test_probe_full_pipeline();
    test_ip_selector_build();
    test_ip_selector_dual_assign();
    test_ip_selector_next_for_reconnect();

    printf("\n=== Results: %d passed, %d failed ===\n\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
