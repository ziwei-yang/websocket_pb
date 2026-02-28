// tools/mkt_event_reader.cpp
// Standalone MktEvent ring reader — attaches to an existing shared memory ring
// and continuously prints event details with monotonicity checks.
//
// Usage:
//   ./build/mkt_event_reader Binance BTC-USDT
//   Opens /dev/shm/hft/mkt_event.Binance.BTC-USDT.{hdr,dat}

#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <string>
#include <unistd.h>

#include "pipeline/pipeline_data.hpp"
#include "msg/mkt_event.hpp"

using namespace websocket::msg;
using namespace websocket::pipeline;

static volatile bool running = true;
static void sighandler(int) { running = false; }

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <exchange> <symbol>\n", argv[0]);
        fprintf(stderr, "  e.g.: %s Binance BTC-USDT\n", argv[0]);
        return 1;
    }

    std::string ring_name = std::string("mkt_event.") + argv[1] + "." + argv[2];
    printf("Opening ring: %s\n", ring_name.c_str());

    disruptor::ipc::shared_region region(ring_name);
    IPCRingConsumer<MktEvent> consumer(region);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    uint64_t count = 0;
    int64_t last_book_seq = 0, last_trade_seq = 0;

    while (running) {
        MktEvent evt;
        bool eob;
        while (consumer.try_consume(evt, &eob)) {
            count++;

            const char* type_str =
                evt.is_book_snapshot() ? "SNAPSHOT" :
                evt.is_book_delta()    ? "DELTA" :
                evt.is_trade_array()   ? "TRADE" :
                evt.is_bbo_array()     ? "BBO" :
                evt.is_system_status() ? "STATUS" : "?";

            // Compute delays
            double local_us = 0;
            int64_t svr_ms = 0;
            if (evt.nic_ts_ns > 0)
                local_us = static_cast<double>(evt.recv_ts_ns - evt.nic_ts_ns) / 1000.0;
            if (evt.event_ts_ns > 0)
                svr_ms = (evt.recv_ts_ns - evt.event_ts_ns) / 1000000;

            printf("[%lu] type=%s seq=%ld local=%.1fus svr=%ldms recv=%ld evt=%ld nic=%ld flags=0x%04x",
                   count, type_str, evt.src_seq,
                   local_us, svr_ms,
                   evt.recv_ts_ns, evt.event_ts_ns, evt.nic_ts_ns, evt.flags);

            // Monotonicity check per domain
            if (evt.is_book_snapshot() || evt.is_book_delta() || evt.is_bbo_array()) {
                bool ok = evt.src_seq > last_book_seq;
                printf(" book_mono=%s", ok ? "OK" : "FAIL");
                if (!ok) printf(" (prev=%ld)", last_book_seq);
                last_book_seq = evt.src_seq;
            } else if (evt.is_trade_array()) {
                bool ok = evt.src_seq > last_trade_seq;
                printf(" trade_mono=%s", ok ? "OK" : "FAIL");
                if (!ok) printf(" (prev=%ld)", last_trade_seq);
                last_trade_seq = evt.src_seq;
            }

            // Print payload details per type
            if (evt.is_book_snapshot()) {
                auto b = evt.bids(), a = evt.asks();
                printf(" bids=%u asks=%u", b.count, a.count);
                if (b.count > 0) printf(" best_bid=%ld@%ld", b.data[0].price, b.data[0].qty);
                if (a.count > 0) printf(" best_ask=%ld@%ld", a.data[0].price, a.data[0].qty);
            } else if (evt.is_book_delta()) {
                printf(" deltas=%u", evt.count);
                for (uint8_t i = 0; i < evt.count && i < 3; i++) {
                    auto& d = evt.payload.deltas.entries[i];
                    printf(" [%s %s %ld@%ld]",
                           d.is_bid() ? "BID" : "ASK",
                           d.action == 0 ? "NEW" : d.action == 1 ? "UPD" : "DEL",
                           d.price, d.qty);
                }
                if (evt.count > 3) printf(" ...");
            } else if (evt.is_trade_array()) {
                printf(" trades=%u", evt.count);
                for (uint8_t i = 0; i < evt.count && i < 3; i++) {
                    auto& t = evt.payload.trades.entries[i];
                    printf(" [%s %ld@%ld id=%ld]",
                           t.is_buyer() ? "BUY" : "SELL",
                           t.price, t.qty, t.trade_id);
                }
                if (evt.count > 3) printf(" ...");
            } else if (evt.is_bbo_array()) {
                printf(" bbos=%u", evt.count);
                for (uint8_t i = 0; i < evt.count && i < 3; i++) {
                    auto& b = evt.payload.bbo_array.entries[i];
                    printf(" [bid=%ld@%ld ask=%ld@%ld seq=%ld]",
                           b.bid_price, b.bid_qty, b.ask_price, b.ask_qty, b.book_update_id);
                }
                if (evt.count > 3) printf(" ...");
            } else if (evt.is_system_status()) {
                auto& st = evt.payload.status;
                const char* st_name =
                    st.status_type == 0 ? "HEARTBEAT" :
                    st.status_type == 1 ? "DISCONNECTED" :
                    st.status_type == 2 ? "RECONNECTED" : "UNKNOWN";
                printf(" status=%s conn=%u detail=%ld",
                       st_name, st.connection_id, st.detail_code);
                if (st.message[0] != '\0')
                    printf(" msg=\"%s\"", st.message);
            }
            printf("\n");
        }
        usleep(1000);  // 1ms idle sleep
    }

    printf("\nTotal events: %lu (book_seq=%ld, trade_seq=%ld)\n", count, last_book_seq, last_trade_seq);
    return 0;
}
