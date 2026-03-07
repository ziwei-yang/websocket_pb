// msg/orderbook.hpp
// Header-only OrderBook utility for consumers to reconcile BBO with OB/Dp state.
// Maintains sorted book levels + latest BBO, applies snapshots/deltas/BBO updates.
#pragma once

#include <cstdint>
#include <cstring>
#include <algorithm>
#include "mkt_event.hpp"

namespace websocket::msg {

static constexpr int OB_MAX_LEVELS = 29;  // matches MAX_BOOK_LEVELS

struct OrderBook {
    BookLevel bids[OB_MAX_LEVELS], asks[OB_MAX_LEVELS];
    uint8_t bid_count = 0, ask_count = 0;
    int64_t book_seq = 0;   // highest OB/Dp seq applied

    int64_t bbo_seq = 0;    // highest BBO seq applied
    int64_t bbo_bid_price = 0, bbo_bid_qty = 0;
    int64_t bbo_ask_price = 0, bbo_ask_qty = 0;
    uint8_t max_bid_depth = OB_MAX_LEVELS;  // set by apply_snapshot
    uint8_t max_ask_depth = OB_MAX_LEVELS;

    void apply_snapshot(const MktEvent& evt) {
        auto b = evt.bids(), a = evt.asks();
        bid_count = std::min<uint8_t>(b.count, OB_MAX_LEVELS);
        ask_count = std::min<uint8_t>(a.count, OB_MAX_LEVELS);
        std::memcpy(bids, b.data, bid_count * sizeof(BookLevel));
        std::memcpy(asks, a.data, ask_count * sizeof(BookLevel));
        max_bid_depth = bid_count;
        max_ask_depth = ask_count;
        book_seq = evt.src_seq;
        reconcile_bbo();
    }

    void apply_one_delta(const DeltaEntry& d) {
        if (d.is_bid())
            apply_side_delta(d, bids, bid_count, true);
        else
            apply_side_delta(d, asks, ask_count, false);
    }

    void apply_deltas(const MktEvent& evt) {
        for (uint8_t i = 0; i < evt.count; i++)
            apply_one_delta(evt.payload.deltas.entries[i]);
        book_seq = evt.src_seq;
        reconcile_bbo();
    }

    bool apply_bbo(const MktEvent& evt) {
        auto entries = evt.bbo_entries();
        if (entries.count == 0) return false;
        auto& last = entries.data[entries.count - 1];
        int64_t seq = last.book_update_id;
        // Reject BBO that is stale relative to book or previous BBO
        if (seq <= bbo_seq || seq <= book_seq) return false;
        bbo_seq = seq;
        bbo_bid_price = last.bid_price;
        bbo_bid_qty = last.bid_qty;
        bbo_ask_price = last.ask_price;
        bbo_ask_qty = last.ask_qty;
        reconcile_bbo();
        return true;
    }

    // Unified dispatcher — returns true if the book was modified
    bool apply(const MktEvent& evt) {
        if (evt.is_book_snapshot()) { apply_snapshot(evt); return true; }
        if (evt.is_book_delta())    { apply_deltas(evt);   return true; }
        if (evt.is_bbo_array())     return apply_bbo(evt);
        return false;
    }

    uint8_t book_depth() const {
        return std::max(bid_count, ask_count);
    }

    void reconcile_bbo() {
        if (bbo_seq <= book_seq) return;  // book is newer, BBO is stale
        if (bid_count == 0 && ask_count == 0) {
            bid_count = 1;
            bids[0] = { bbo_bid_price, bbo_bid_qty };
            ask_count = 1;
            asks[0] = { bbo_ask_price, bbo_ask_qty };
            return;
        }

        // --- Bids: trim stale levels (price > BBO bid), then set bid1 ---
        uint8_t bid_trim = 0;
        while (bid_trim < bid_count && bids[bid_trim].price > bbo_bid_price)
            bid_trim++;
        if (bid_trim > 0) {
            bid_count -= bid_trim;
            if (bid_count > 0)
                std::memmove(&bids[0], &bids[bid_trim], bid_count * sizeof(BookLevel));
        }
        if (bid_count > 0 && bids[0].price == bbo_bid_price) {
            bids[0].qty = bbo_bid_qty;
        } else {
            if (bid_count < max_bid_depth) {
                std::memmove(&bids[1], &bids[0], bid_count * sizeof(BookLevel));
                bid_count++;
            } else {
                std::memmove(&bids[1], &bids[0], (max_bid_depth - 1) * sizeof(BookLevel));
            }
            bids[0] = { bbo_bid_price, bbo_bid_qty };
        }

        // --- Asks: trim stale levels (price < BBO ask), then set ask1 ---
        uint8_t ask_trim = 0;
        while (ask_trim < ask_count && asks[ask_trim].price < bbo_ask_price)
            ask_trim++;
        if (ask_trim > 0) {
            ask_count -= ask_trim;
            if (ask_count > 0)
                std::memmove(&asks[0], &asks[ask_trim], ask_count * sizeof(BookLevel));
        }
        if (ask_count > 0 && asks[0].price == bbo_ask_price) {
            asks[0].qty = bbo_ask_qty;
        } else {
            if (ask_count < max_ask_depth) {
                std::memmove(&asks[1], &asks[0], ask_count * sizeof(BookLevel));
                ask_count++;
            } else {
                std::memmove(&asks[1], &asks[0], (max_ask_depth - 1) * sizeof(BookLevel));
            }
            asks[0] = { bbo_ask_price, bbo_ask_qty };
        }
    }

private:
    void apply_side_delta(const DeltaEntry& d, BookLevel* levels, uint8_t& count, bool is_bid) {
        for (uint8_t i = 0; i < count; i++) {
            if (levels[i].price == d.price) {
                if (d.qty == 0) {
                    if (i + 1 < count)
                        std::memmove(&levels[i], &levels[i + 1], (count - i - 1) * sizeof(BookLevel));
                    count--;
                } else {
                    levels[i].qty = d.qty;
                }
                return;
            }
        }
        uint8_t max_depth = is_bid ? max_bid_depth : max_ask_depth;
        if (d.qty > 0 && count < max_depth) {
            uint8_t pos = count;
            for (uint8_t i = 0; i < count; i++) {
                if (is_bid ? (d.price > levels[i].price) : (d.price < levels[i].price)) {
                    pos = i;
                    break;
                }
            }
            if (pos < count)
                std::memmove(&levels[pos + 1], &levels[pos], (count - pos) * sizeof(BookLevel));
            levels[pos] = { d.price, d.qty };
            count++;
        }
    }
};  // struct OrderBook

}  // namespace websocket::msg
