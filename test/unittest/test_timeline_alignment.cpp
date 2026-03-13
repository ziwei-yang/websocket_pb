// test/unittest/test_timeline_alignment.cpp
// Unit test for WSFrameInfo↔MktEvent column alignment
// Verifies "WS" column in print_timeline() aligns with flush_id conn char in MktEvent::print()

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include "pipeline/pipeline_data.hpp"

using namespace websocket::pipeline;
using namespace websocket::msg;

// ============================================================================
// Minimal test framework (same as test_mkt_event_bitfields.cpp)
// ============================================================================

static int tests_run = 0, tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        std::fprintf(stderr, "  [%d] %-55s", tests_run, name); \
    } while(0)

#define PASS() \
    do { \
        tests_passed++; \
        std::fprintf(stderr, " \033[32mPASS\033[0m\n"); \
    } while(0)

// ============================================================================
// ANSI escape sequence stripper: skip from \033[ to next 'm'
// ============================================================================

static std::string strip_ansi(const char* s) {
    std::string out;
    while (*s) {
        if (s[0] == '\033' && s[1] == '[') {
            s += 2;
            while (*s && *s != 'm') ++s;
            if (*s == 'm') ++s;
        } else {
            out += *s++;
        }
    }
    return out;
}

// ============================================================================
// Test 1: WS column aligns with MktEvent flush_id connection char
// ============================================================================

static void test_ws_column_alignment() {
    TEST("WS column aligns with MktEvent flush_id conn char");

    // --- WSFrameInfo setup (DPDK mode, deterministic values) ---
    WSFrameInfo info;
    info.clear();
    uint64_t tsc_freq = 2000000000ULL;  // 2 GHz for clean arithmetic
    uint64_t pub_cycle = 1000000;
    info.ws_frame_publish_cycle = pub_cycle;
    info.first_poll_cycle = pub_cycle - 600;
    info.latest_poll_cycle = pub_cycle - 14;
    info.first_ssl_read_start_cycle = pub_cycle - 500;
    info.latest_ssl_read_end_cycle = pub_cycle - 6;
    info.ws_parse_cycle = pub_cycle - 4;
    info.publish_time_ts = 1000000000ULL;  // 1s MONO
    info.first_bpf_entry_ns = info.publish_time_ts - 7000;
    info.latest_bpf_entry_ns = info.first_bpf_entry_ns;
    info.ssl_read_batch_num = 1;
    info.transport_mode = static_cast<uint8_t>(TransportMode::DPDK);
    info.connection_id = 0;
    info.nic_packet_ct = 3;
    info.ssl_read_ct = 1;
    info.last_pkt_mem_idx = 100;
    info.ssl_read_total_bytes = 1500;
    info.payload_len = 1400;
    info.opcode = 0x02;
    info.mkt_event_type = 0;   // BOOK_DELTA
    info.mkt_event_count = 20;
    info.mkt_event_seq = 12345678;
    info.tx_pool_avail = 48;
    info.set_active_conn(true);

    // --- MktEvent setup (matching fields) ---
    MktEvent mkt;
    mkt.clear();
    mkt.set_event_type(0);       // BOOK_DELTA
    mkt.set_depth_channel(1);
    mkt.set_connection_id(0);
    mkt.count = 20;
    mkt.count2 = 3;
    mkt.src_seq = 12345678;
    mkt.nic_ts_ns = 1000;
    mkt.recv_local_latency_ns = 500;
    mkt.event_ts_ns = 0;

    // --- Capture stderr output ---
    FILE* tmp = tmpfile();
    assert(tmp);
    int saved_fd = dup(fileno(stderr));
    dup2(fileno(tmp), fileno(stderr));

    info.print_timeline(tsc_freq);
    mkt.print(100);

    fflush(stderr);
    dup2(saved_fd, fileno(stderr));
    close(saved_fd);

    // --- Read both lines ---
    rewind(tmp);
    char buf[4096];
    std::string timeline_raw, mkt_raw;
    if (fgets(buf, sizeof(buf), tmp)) timeline_raw = buf;
    if (fgets(buf, sizeof(buf), tmp)) mkt_raw = buf;
    fclose(tmp);

    std::string tl = strip_ansi(timeline_raw.c_str());
    std::string ml = strip_ansi(mkt_raw.c_str());

    // --- Assert "WS" position matches connection char position ---
    // Timeline: conn_prefix(2) + bpf_prefix(19) + pkt(33) + ssl(32) + "WS" → "W" at col 86
    // MktEvent: padding(84 spaces) + flush_id "  0 ..." → '0' at col 86
    size_t ws_pos = tl.find("WS");
    assert(ws_pos != std::string::npos);
    assert(ws_pos < ml.size());
    assert(ml[ws_pos] == '0');  // connection_id=0 → char '0'

    // --- mkt_cnt column alignment: both lines have "20" at the same position ---
    // Timeline tail starts right after WS column; MktEvent tail starts right after flush_id
    // Both use %3s for mkt_cnt, so find the mkt_cnt "20" after the WS/flush_id region
    {
        // In timeline, mkt_cnt appears in tail after WS column (position 100+)
        // Search for " 20 " pattern after ws_pos
        size_t tl_cnt = tl.find(" 20 ", ws_pos);
        size_t ml_cnt = ml.find(" 20 ", ws_pos);
        assert(tl_cnt != std::string::npos);
        assert(ml_cnt != std::string::npos);
        assert(tl_cnt == ml_cnt);  // mkt_cnt must align
    }

    // --- Both lines contain same seq number ---
    // Byte positions differ (Σ is 2 UTF-8 bytes vs @ is 1, and exch_diff is
    // conditional in timeline but always present in MktEvent), but display
    // columns align when exch_diff is set. mkt_cnt alignment above anchors this.
    assert(tl.find("#12345678") != std::string::npos);
    assert(ml.find("#12345678") != std::string::npos);

    PASS();
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::fprintf(stderr, "\n=== Timeline Alignment Unit Tests ===\n\n");

    test_ws_column_alignment();

    std::fprintf(stderr, "\n  %d/%d tests passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
