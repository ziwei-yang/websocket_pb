// tools/mkt_sampling.cpp
// Samples WSFrameInfo + raw MSG_INBOX payload + MktEvents from a live pipeline.
// Outputs wsframes.txt and mktevents.txt for offline verification.
//
// Usage:
//   ./build/mkt_sampling Binance BTC-USDT [count=1024]

#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <string>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "pipeline/pipeline_data.hpp"
#include "pipeline/pipeline_config.hpp"
#include "pipeline/msg_inbox.hpp"
#include "msg/mkt_event.hpp"

using namespace websocket::msg;
using namespace websocket::pipeline;

static volatile bool running = true;
static void sighandler(int) { running = false; }

// ============================================================================
// Ring discovery: find newest pipeline directory in /dev/shm/hft/
// ============================================================================

static std::string find_newest_pipeline_dir() {
    const char* base = "/dev/shm/hft";
    DIR* dir = opendir(base);
    if (!dir) return "";

    std::string newest;
    time_t newest_mtime = 0;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        // Pipeline dirs contain "_pipeline_" or match *_YYYYMMDD_HHMMSS pattern
        // Just look for dirs that contain ws_frame_info.hdr
        std::string candidate = std::string(base) + "/" + ent->d_name;
        std::string hdr = candidate + "/ws_frame_info.hdr";
        struct stat st;
        if (stat(hdr.c_str(), &st) == 0) {
            if (st.st_mtime >= newest_mtime) {
                newest_mtime = st.st_mtime;
                newest = ent->d_name;  // relative to /dev/shm/hft/
            }
        }
    }
    closedir(dir);
    return newest;
}

// ============================================================================
// mmap MSG_INBOX file read-only
// ============================================================================

static const MsgInbox* mmap_msg_inbox(size_t conn_id) {
    char path[128];
    snprintf(path, sizeof(path), "%s/msg_inbox_%zu.dat", shm_paths::PIPELINE_DIR, conn_id);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "WARN: Cannot open %s: %s\n", path, strerror(errno));
        return nullptr;
    }
    void* ptr = mmap(nullptr, sizeof(MsgInbox), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) return nullptr;
    return static_cast<const MsgInbox*>(ptr);
}

// ============================================================================
// Captured frame: WSFrameInfo metadata + raw payload bytes
// ============================================================================

struct CapturedFrame {
    uint8_t  conn_id;
    uint8_t  opcode;
    uint8_t  flags;
    std::vector<uint8_t> payload;
};

// ============================================================================
// MktEvent JSON serialization
// ============================================================================

static void write_mkt_event_json(FILE* f, const MktEvent& evt) {
    uint8_t conn_id = evt.connection_id();

    if (evt.is_system_status()) {
        fprintf(f, "{\"type\":\"SYSTEM_STATUS\",\"status_type\":%u,\"connection_id\":%u}\n",
                evt.payload.status.status_type, evt.payload.status.connection_id);
        return;
    }

    if (evt.is_trade_array()) {
        fprintf(f, "{\"type\":\"TRADE_ARRAY\",\"seq\":%ld,\"event_ts_ns\":%ld,"
                "\"count\":%u,\"conn_id\":%u,\"flags\":%u,\"trades\":[",
                evt.src_seq, evt.event_ts_ns, evt.count, conn_id, evt.flags);
        for (uint8_t i = 0; i < evt.count; i++) {
            auto& t = evt.payload.trades.entries[i];
            if (i > 0) fputc(',', f);
            fprintf(f, "{\"price\":%ld,\"qty\":%ld,\"trade_time_ns\":%ld,"
                    "\"trade_id\":%ld,\"flags\":%u}",
                    t.price, t.qty, t.trade_time_ns, t.trade_id, t.flags);
        }
        fprintf(f, "]}\n");
        return;
    }

    if (evt.is_book_delta()) {
        fprintf(f, "{\"type\":\"BOOK_DELTA\",\"seq\":%ld,\"event_ts_ns\":%ld,"
                "\"count\":%u,\"count2\":%u,\"conn_id\":%u,\"flags\":%u,\"deltas\":[",
                evt.src_seq, evt.event_ts_ns, evt.count, evt.count2, conn_id, evt.flags);
        for (uint8_t i = 0; i < evt.count; i++) {
            auto& d = evt.payload.deltas.entries[i];
            if (i > 0) fputc(',', f);
            fprintf(f, "{\"price\":%ld,\"qty\":%ld,\"action\":%u,\"flags\":%u}",
                    d.price, d.qty, d.action, d.flags);
        }
        fprintf(f, "]}\n");
        return;
    }

    if (evt.is_book_snapshot()) {
        auto b = evt.bids(), a = evt.asks();
        fprintf(f, "{\"type\":\"BOOK_SNAPSHOT\",\"seq\":%ld,\"event_ts_ns\":%ld,"
                "\"count\":%u,\"count2\":%u,\"conn_id\":%u,\"flags\":%u,\"bids\":[",
                evt.src_seq, evt.event_ts_ns, evt.count, evt.count2, conn_id, evt.flags);
        for (uint8_t i = 0; i < b.count; i++) {
            if (i > 0) fputc(',', f);
            fprintf(f, "{\"price\":%ld,\"qty\":%ld}", b.data[i].price, b.data[i].qty);
        }
        fprintf(f, "],\"asks\":[");
        for (uint8_t i = 0; i < a.count; i++) {
            if (i > 0) fputc(',', f);
            fprintf(f, "{\"price\":%ld,\"qty\":%ld}", a.data[i].price, a.data[i].qty);
        }
        fprintf(f, "]}\n");
        return;
    }

    if (evt.is_bbo_array()) {
        fprintf(f, "{\"type\":\"BBO_ARRAY\",\"seq\":%ld,\"event_ts_ns\":%ld,"
                "\"count\":%u,\"conn_id\":%u,\"flags\":%u,\"bbos\":[",
                evt.src_seq, evt.event_ts_ns, evt.count, conn_id, evt.flags);
        for (uint8_t i = 0; i < evt.count; i++) {
            auto& b = evt.payload.bbo_array.entries[i];
            if (i > 0) fputc(',', f);
            fprintf(f, "{\"bid_price\":%ld,\"bid_qty\":%ld,\"ask_price\":%ld,"
                    "\"ask_qty\":%ld,\"event_time_ns\":%ld,\"book_update_id\":%ld}",
                    b.bid_price, b.bid_qty, b.ask_price, b.ask_qty,
                    b.event_time_ns, b.book_update_id);
        }
        fprintf(f, "]}\n");
        return;
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <exchange> <symbol> [count=1024]\n", argv[0]);
        fprintf(stderr, "  e.g.: %s Binance BTC-USDT 1024\n", argv[0]);
        return 1;
    }

    const char* exchange = argv[1];
    const char* symbol = argv[2];
    size_t target_count = (argc >= 4) ? static_cast<size_t>(atoi(argv[3])) : 1024;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    // 1. Discover ws_frame_info ring
    std::string pipeline_dir = find_newest_pipeline_dir();
    if (pipeline_dir.empty()) {
        fprintf(stderr, "ERROR: No pipeline directory with ws_frame_info found in /dev/shm/hft/\n");
        return 1;
    }
    std::string ws_ring_name = pipeline_dir + "/ws_frame_info";
    printf("Opening ws_frame_info ring: %s\n", ws_ring_name.c_str());

    disruptor::ipc::shared_region ws_region(ws_ring_name);
    IPCRingConsumer<WSFrameInfo> ws_consumer(ws_region);

    // 2. Open mkt_event ring
    std::string mkt_ring_name = std::string("mkt_event.") + exchange + "." + symbol;
    printf("Opening mkt_event ring: %s\n", mkt_ring_name.c_str());

    disruptor::ipc::shared_region mkt_region(mkt_ring_name);
    IPCRingConsumer<MktEvent> mkt_consumer(mkt_region);

    // 3. mmap MSG_INBOX files (try up to 8 connections)
    static constexpr size_t MAX_INBOX = 8;
    const MsgInbox* inboxes[MAX_INBOX] = {};
    size_t inbox_count = 0;
    for (size_t i = 0; i < MAX_INBOX; i++) {
        inboxes[i] = mmap_msg_inbox(i);
        if (inboxes[i]) inbox_count = i + 1;
    }
    printf("Opened %zu MSG_INBOX files\n", inbox_count);
    if (inbox_count == 0) {
        fprintf(stderr, "ERROR: No MSG_INBOX files found in %s\n", shm_paths::PIPELINE_DIR);
        return 1;
    }

    // 4. Collect frames and events
    std::vector<CapturedFrame> frames;
    std::vector<MktEvent> events;
    frames.reserve(target_count);
    events.reserve(target_count * 2);

    printf("Sampling %zu WSFrameInfos...\n", target_count);

    while (running && frames.size() < target_count) {
        WSFrameInfo info;
        bool eob;
        while (ws_consumer.try_consume(info, &eob)) {
            CapturedFrame cf;
            cf.conn_id = info.connection_id;
            cf.opcode = info.opcode;
            cf.flags = info.flags;

            // Copy payload from MSG_INBOX
            if (info.payload_len > 0 && cf.conn_id < inbox_count && inboxes[cf.conn_id]) {
                cf.payload.resize(info.payload_len);
                const MsgInbox* inbox = inboxes[cf.conn_id];
                // Handle potential wrap-around
                const uint8_t* seg1;
                uint32_t seg1_len;
                const uint8_t* seg2;
                uint32_t seg2_len;
                inbox->get_wrapped_segments(info.msg_inbox_offset, info.payload_len,
                                            seg1, seg1_len, seg2, seg2_len);
                memcpy(cf.payload.data(), seg1, seg1_len);
                if (seg2_len > 0) {
                    memcpy(cf.payload.data() + seg1_len, seg2, seg2_len);
                }
            }

            frames.push_back(std::move(cf));
            if (frames.size() >= target_count) break;
        }

        // Also consume available MktEvents
        MktEvent evt;
        while (mkt_consumer.try_consume(evt, &eob)) {
            events.push_back(evt);
        }

        if (frames.size() < target_count) {
            usleep(1000);  // 1ms idle sleep
        }
    }

    // 5. Drain remaining MktEvents (allow some time for processing pipeline lag)
    printf("Collected %zu frames, draining MktEvents...\n", frames.size());
    for (int drain = 0; drain < 100 && running; drain++) {
        MktEvent evt;
        bool eob;
        bool got_any = false;
        while (mkt_consumer.try_consume(evt, &eob)) {
            events.push_back(evt);
            got_any = true;
        }
        if (!got_any) {
            usleep(10000);  // 10ms
        } else {
            usleep(1000);
        }
    }
    printf("Collected %zu MktEvents\n", events.size());

    // 6. Write wsframes.txt
    {
        FILE* f = fopen("wsframes.txt", "w");
        if (!f) { perror("fopen wsframes.txt"); return 1; }
        for (auto& cf : frames) {
            fprintf(f, "%u\t%u\t0x%02x\t", cf.conn_id, cf.opcode, cf.flags);
            // Write raw payload as-is (binary safe via escaping control chars)
            // Actually write base64 or hex would be safer, but for JSON text frames
            // we can write the payload directly (replace \t and \n with escapes)
            for (size_t i = 0; i < cf.payload.size(); i++) {
                uint8_t c = cf.payload[i];
                if (c == '\t') {
                    fputs("\\t", f);
                } else if (c == '\n') {
                    fputs("\\n", f);
                } else if (c == '\\') {
                    fputs("\\\\", f);
                } else if (c == '\r') {
                    fputs("\\r", f);
                } else if (c < 0x20 || c == 0x7f) {
                    fprintf(f, "\\x%02x", c);
                } else {
                    fputc(c, f);
                }
            }
            fputc('\n', f);
        }
        fclose(f);
        printf("Wrote wsframes.txt (%zu frames)\n", frames.size());
    }

    // 7. Write mktevents.txt
    {
        FILE* f = fopen("mktevents.txt", "w");
        if (!f) { perror("fopen mktevents.txt"); return 1; }
        for (auto& evt : events) {
            write_mkt_event_json(f, evt);
        }
        fclose(f);
        printf("Wrote mktevents.txt (%zu events)\n", events.size());
    }

    // Cleanup inboxes
    for (size_t i = 0; i < MAX_INBOX; i++) {
        if (inboxes[i]) {
            munmap(const_cast<MsgInbox*>(inboxes[i]), sizeof(MsgInbox));
        }
    }

    return 0;
}
