// msg/01_binance_usdm_json.hpp
// Binance USD-M Futures JSON market data: position-aware field extractors + handler
//
// websocket::json — Fast forward-only JSON parsers for Binance futures streams.
//   All fields extracted by known position (no generic key search).
//   Supported streams:
//     aggTrade        → TRADE_ARRAY
//     depth5/10/20    → BOOK_SNAPSHOT
//     depth@100ms/etc → BOOK_DELTA
//
//   BinanceUSDMJsonParser — Handler struct for pipeline integration
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>

// ============================================================================
// Part 1: JSON Skip/Parse Primitives + Type-Specific Field Parsers
// ============================================================================

namespace websocket::json {

// ── JSON skip/parse primitives ─────────────────────────────────────────────

// p at '"', returns pointer past closing '"' (handles backslash escapes)
inline const uint8_t* skip_string(const uint8_t* p, const uint8_t* end) {
    if (p >= end || *p != '"') return p;
    ++p;  // skip opening '"'
    while (p < end) {
        if (*p == '\\') { p += 2; continue; }  // skip escaped char
        if (*p == '"') return p + 1;            // past closing '"'
        ++p;
    }
    return end;
}

// p at first digit/'-', returns pointer past last digit/'.'/etc
inline const uint8_t* skip_number(const uint8_t* p, const uint8_t* end) {
    while (p < end && ((*p >= '0' && *p <= '9') || *p == '-' || *p == '.' || *p == 'e' || *p == 'E' || *p == '+'))
        ++p;
    return p;
}

// p at start of any JSON value, returns pointer past it
inline const uint8_t* skip_value(const uint8_t* p, const uint8_t* end) {
    if (p >= end) return end;
    switch (*p) {
    case '"': return skip_string(p, end);
    case '{': {
        ++p;
        int depth = 1;
        while (p < end && depth > 0) {
            if (*p == '"') { p = skip_string(p, end); continue; }
            if (*p == '{') ++depth;
            else if (*p == '}') --depth;
            ++p;
        }
        return p;
    }
    case '[': {
        ++p;
        int depth = 1;
        while (p < end && depth > 0) {
            if (*p == '"') { p = skip_string(p, end); continue; }
            if (*p == '[') ++depth;
            else if (*p == ']') --depth;
            ++p;
        }
        return p;
    }
    case 't': return p + 4;  // true
    case 'f': return p + 5;  // false
    case 'n': return p + 4;  // null
    default:  return skip_number(p, end);  // number
    }
}

// Skip one full "key":value field. p at '"' of key, returns past value+comma
inline const uint8_t* skip_field(const uint8_t* p, const uint8_t* end) {
    p = skip_string(p, end);   // skip key
    while (p < end && *p != ':') ++p;
    if (p < end) ++p;          // skip ':'
    while (p < end && *p == ' ') ++p;
    p = skip_value(p, end);    // skip value
    while (p < end && (*p == ',' || *p == ' ')) ++p;
    return p;
}

// Skip "key": prefix. p at '"' of key, returns at value start
inline const uint8_t* to_value(const uint8_t* p, const uint8_t* end) {
    p = skip_string(p, end);   // skip key
    while (p < end && *p != ':') ++p;
    if (p < end) ++p;          // skip ':'
    while (p < end && *p == ' ') ++p;
    return p;
}

// Parse int64, p at first digit/'-'. Advances p past number.
inline int64_t parse_int64_fast(const uint8_t*& p, const uint8_t* end) {
    bool neg = false;
    if (p < end && *p == '-') { neg = true; ++p; }
    int64_t v = 0;
    while (p < end && *p >= '0' && *p <= '9')
        v = v * 10 + (*p++ - '0');
    return neg ? -v : v;
}

// Parse quoted decimal "50123.40" -> int64 mantissa 5012340.
// p at opening '"'. Advances past closing '"'.
// Reads all digits, ignoring the decimal point.
inline int64_t parse_decimal_string(const uint8_t*& p, const uint8_t* end) {
    if (p >= end || *p != '"') return 0;
    ++p;  // skip opening '"'
    bool neg = false;
    if (p < end && *p == '-') { neg = true; ++p; }
    int64_t v = 0;
    while (p < end && *p != '"') {
        if (*p == '.') { ++p; continue; }
        if (*p >= '0' && *p <= '9')
            v = v * 10 + (*p - '0');
        ++p;
    }
    if (p < end) ++p;  // skip closing '"'
    return neg ? -v : v;
}

// Parse bool (p at 't' or 'f'). Advances p.
inline bool parse_bool_fast(const uint8_t*& p, const uint8_t* end) {
    if (p >= end) return false;
    if (*p == 't') { p += 4; return true; }   // true
    if (*p == 'f') { p += 5; return false; }   // false
    return false;
}

// ── Stream Type Classification ─────────────────────────────────────────────

enum class UsdmStreamType : uint8_t {
    UNKNOWN = 0, AGG_TRADE = 1, DEPTH_PARTIAL = 2, DEPTH_DIFF = 3
};

// Classify by suffix of stream name.
// "btcusdt@aggTrade" -> AGG_TRADE
// "btcusdt@depth5" / "depth10" / "depth20" -> DEPTH_PARTIAL
// "btcusdt@depth@100ms" / "depth@250ms" -> DEPTH_DIFF
inline UsdmStreamType classify_stream(const uint8_t* name, uint32_t len) {
    if (len < 5) return UsdmStreamType::UNKNOWN;
    // Check suffix for "aggTrade" (8 chars)
    if (len >= 8 && std::memcmp(name + len - 8, "aggTrade", 8) == 0)
        return UsdmStreamType::AGG_TRADE;
    // Check for "depth@" pattern (diff depth: contains "@depth@")
    // depth@100ms / depth@250ms etc — the @ before ms distinguishes from partial
    // Pattern: has "@depth@" substring
    for (uint32_t i = 0; i + 6 <= len; i++) {
        if (name[i] == '@' && name[i+1] == 'd' && name[i+2] == 'e' &&
            name[i+3] == 'p' && name[i+4] == 't' && name[i+5] == 'h') {
            // Check if next char is '@' (diff) or digit (partial)
            if (i + 6 < len && name[i+6] == '@')
                return UsdmStreamType::DEPTH_DIFF;
            if (i + 6 < len && name[i+6] >= '0' && name[i+6] <= '9')
                return UsdmStreamType::DEPTH_PARTIAL;
        }
    }
    return UsdmStreamType::UNKNOWN;
}

// ── Combined Stream Wrapper Parser ─────────────────────────────────────────

struct CombinedStreamHeader {
    UsdmStreamType type;
    const uint8_t* data_start;  // points to '{' of data object
    uint32_t data_len;
};

// Parse {"stream":"btcusdt@aggTrade","data":{...}}
inline CombinedStreamHeader parse_combined_stream(const uint8_t* json, uint32_t len) {
    CombinedStreamHeader hdr{};
    hdr.type = UsdmStreamType::UNKNOWN;
    hdr.data_start = nullptr;
    hdr.data_len = 0;

    const uint8_t* p = json;
    const uint8_t* end = json + len;

    // Skip to first field: {"stream":
    while (p < end && *p != '"') ++p;
    if (p >= end) return hdr;

    // Skip "stream" key, get to value
    p = to_value(p, end);
    if (p >= end || *p != '"') return hdr;

    // Parse stream name value
    const uint8_t* name_start = p + 1;
    const uint8_t* name_end = skip_string(p, end);
    uint32_t name_len = static_cast<uint32_t>((name_end - 1) - name_start);
    hdr.type = classify_stream(name_start, name_len);

    // Skip comma, advance to "data" field
    p = name_end;
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Skip "data" key
    if (p >= end || *p != '"') return hdr;
    p = to_value(p, end);
    if (p >= end) return hdr;

    // p now at '{' of data object
    hdr.data_start = p;
    // data_len = everything from '{' to the matching '}' (exclusive of outer '}')
    // Find the end of the data object
    const uint8_t* data_end = skip_value(p, end);
    hdr.data_len = static_cast<uint32_t>(data_end - p);

    return hdr;
}

// ── Type-Specific Field Parsers ────────────────────────────────────────────

// aggTrade field order: e, E, s, a, p, q, nq, f, l, T, m
struct AggTradeFields {
    int64_t event_time_ms;   // "E"
    int64_t agg_trade_id;    // "a"
    int64_t price_mantissa;  // "p"
    int64_t qty_mantissa;    // "q"
    int64_t trade_time_ms;   // "T"
    bool    buyer_is_maker;  // "m"
    bool    valid;
};

// p at '{' of data object
inline AggTradeFields parse_agg_trade_fields(const uint8_t* p, const uint8_t* end) {
    AggTradeFields f{};
    f.valid = false;

    if (p >= end || *p != '{') return f;
    ++p;  // skip '{'
    while (p < end && *p == ' ') ++p;

    // Field 1: "e" (event type string) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 2: "E" (event time) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.event_time_ms = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 3: "s" (symbol) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 4: "a" (aggregate trade id) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.agg_trade_id = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 5: "p" (price string) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.price_mantissa = parse_decimal_string(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 6: "q" (quantity string) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.qty_mantissa = parse_decimal_string(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 7: "nq" (notional quantity string) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 8: "f" (first trade id) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 9: "l" (last trade id) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 10: "T" (trade time) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.trade_time_ms = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 11: "m" (buyer is maker) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.buyer_is_maker = parse_bool_fast(p, end);

    f.valid = true;
    return f;
}

// depthUpdate field order: e, E, T, s, U, u, pu, b, a
struct DepthUpdateFields {
    int64_t event_time_ms;   // "E"
    int64_t txn_time_ms;     // "T"
    int64_t last_update_id;  // "u"
    const uint8_t* bids_array; // points to '[' of "b"
    const uint8_t* asks_array; // points to '[' of "a"
    const uint8_t* end;        // end of payload
    bool    valid;
};

// p at '{' of data object
inline DepthUpdateFields parse_depth_fields(const uint8_t* p, const uint8_t* end) {
    DepthUpdateFields f{};
    f.valid = false;
    f.bids_array = nullptr;
    f.asks_array = nullptr;
    f.end = end;

    if (p >= end || *p != '{') return f;
    ++p;  // skip '{'
    while (p < end && *p == ' ') ++p;

    // Field 1: "e" (event type) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 2: "E" (event time) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.event_time_ms = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 3: "T" (transaction time) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.txn_time_ms = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 4: "s" (symbol) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 5: "U" (first update id) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 6: "u" (last update id) — extract
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.last_update_id = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 7: "pu" (previous update id) — skip
    if (p >= end || *p != '"') return f;
    p = skip_field(p, end);

    // Field 8: "b" (bids array) — locate
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.bids_array = p;
    p = skip_value(p, end);  // skip past bids array
    while (p < end && (*p == ',' || *p == ' ')) ++p;

    // Field 9: "a" (asks array) — locate
    if (p >= end || *p != '"') return f;
    p = to_value(p, end);
    f.asks_array = p;

    f.valid = true;
    return f;
}

// ── Price Level Array Parsers ──────────────────────────────────────────────

}  // namespace websocket::json

// Forward declare types from mkt_event.hpp (always available since it's header-only)
#include "mkt_event.hpp"
#include "market_conf.hpp"
#include "../pipeline/pipeline_data.hpp"  // PIPELINE_MAX_CONN

namespace websocket::json {

// Parse [["price","qty"],...] into BookLevel[]. p at '[', returns count.
inline uint8_t parse_book_levels(const uint8_t* p, const uint8_t* end,
                                 websocket::msg::BookLevel* out, uint8_t max) {
    if (p >= end || *p != '[') return 0;
    ++p;  // skip '['
    uint8_t count = 0;
    while (p < end && *p != ']' && count < max) {
        while (p < end && *p != '[') ++p;
        if (p >= end) break;
        ++p;  // skip inner '['

        // Parse price string
        while (p < end && *p != '"') ++p;
        out[count].price = parse_decimal_string(p, end);

        // Skip comma
        while (p < end && *p != '"') ++p;

        // Parse qty string
        out[count].qty = parse_decimal_string(p, end);

        // Skip to end of inner array
        while (p < end && *p != ']') ++p;
        if (p < end) ++p;  // skip ']'

        count++;
        while (p < end && (*p == ',' || *p == ' ')) ++p;
    }
    return count;
}

// Parse [["price","qty"],...] into DeltaEntry[]. p at '[', returns count.
inline uint8_t parse_delta_levels(const uint8_t* p, const uint8_t* end,
                                  websocket::msg::DeltaEntry* out, uint8_t max, bool is_ask) {
    if (p >= end || *p != '[') return 0;
    ++p;  // skip '['
    uint8_t count = 0;
    while (p < end && *p != ']' && count < max) {
        while (p < end && *p != '[') ++p;
        if (p >= end) break;
        ++p;  // skip inner '['

        // Parse price string
        while (p < end && *p != '"') ++p;
        out[count].price = parse_decimal_string(p, end);

        // Skip comma
        while (p < end && *p != '"') ++p;

        // Parse qty string
        out[count].qty = parse_decimal_string(p, end);

        // Set action: DELETE if qty==0, else UPDATE
        out[count].action = (out[count].qty == 0)
            ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
            : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
        out[count].flags = is_ask ? websocket::msg::DeltaFlags::SIDE_ASK : 0;
        std::memset(out[count]._pad, 0, sizeof(out[count]._pad));

        // Skip to end of inner array
        while (p < end && *p != ']') ++p;
        if (p < end) ++p;  // skip ']'

        count++;
        while (p < end && (*p == ',' || *p == ' ')) ++p;
    }
    return count;
}

}  // namespace websocket::json

// ============================================================================
// Part 2: BinanceUSDMJsonParser (requires pipeline_data.hpp)
// ============================================================================

#ifdef PIPELINE_DATA_HPP_INCLUDED

namespace websocket::json {

struct JsonParseState {
    // Stub fields for WSCore template compatibility (continuation-frame state propagation).
    // Always zero — JSON handler doesn't use fragmented binary frames.
    uint16_t msg_type = 0;
    int64_t  sequence = 0;
    int64_t  event_time_us = 0;
    uint16_t group_count = 0;
    uint16_t bids_count = 0;
    uint16_t asks_count = 0;
    void reset() {}
};

struct BinanceUSDMJsonParser {
    static constexpr bool enabled = true;
    JsonParseState sbe_state_[PIPELINE_MAX_CONN]{};  // named sbe_state_ for compatibility with WSCore template

    // Pipeline wiring (same members as BinanceSBEHandler for compatibility)
    websocket::pipeline::IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    websocket::pipeline::ConnStateShm* conn_state = nullptr;
    bool merge_enabled = true;
    int64_t last_book_seq_ = 0;
    int64_t last_trade_id_ = 0;
    uint8_t active_ci_ = 0xFF;
    websocket::pipeline::WSFrameInfo* current_info_ = nullptr;

    // Ring producer for clearing M flag on published (winning) frames
    websocket::pipeline::IPCRingProducer<websocket::pipeline::WSFrameInfo>* ws_frame_info_prod_ = nullptr;
    int64_t pending_trades_ring_seq_ = -1;
    int64_t* pending_ring_seq_slot_ = nullptr;

    // Trade merge buffer (no BBO buffer — no bestBidAsk stream in futures)
    bool has_pending_trades_ = false;
    uint8_t pending_trades_ci_ = 0;
    uint8_t pending_trade_count_ = 0;
    websocket::msg::TradeEntry pending_trade_entries_[websocket::msg::MAX_TRADES];
    int64_t pending_trades_event_ts_ns_ = 0;
    int64_t pending_trades_max_id_ = 0;
    websocket::pipeline::WSFrameInfo pending_trades_info_{};

    // ── Main entry point ───────────────────────────────────────────────────

    void on_ws_data(JsonParseState&, uint8_t ci,
                    const uint8_t* payload, uint32_t len,
                    websocket::pipeline::WSFrameInfo& info) {
        pending_ring_seq_slot_ = nullptr;

        auto hdr = parse_combined_stream(payload, len);
        if (hdr.type == UsdmStreamType::UNKNOWN || !hdr.data_start)
            return;

        const uint8_t* data_end = hdr.data_start + hdr.data_len;

        switch (hdr.type) {
        case UsdmStreamType::AGG_TRADE: {
            // Cross-type flush: if we have pending trades and get a non-trade, flush.
            // (trades stay pending; only flush on type change)
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);

            auto tf = parse_agg_trade_fields(hdr.data_start, data_end);
            if (!tf.valid) return;
            tf.price_mantissa *= websocket::market::BinanceUSDM::price_scale;
            tf.qty_mantissa   *= websocket::market::BinanceUSDM::qty_scale;

            info.exchange_event_time_us = tf.event_time_ms * 1000;
            info.mkt_event_seq = tf.agg_trade_id;
            info.mkt_event_count = 1;

            // Dedup by agg_trade_id
            int64_t eff_tid = has_pending_trades_
                ? std::max(last_trade_id_, pending_trades_max_id_)
                : last_trade_id_;
            if (tf.agg_trade_id <= eff_tid) {
                info.set_discard_early(true);
                return;
            }

            int64_t event_ts_ns = tf.event_time_ms * 1000000LL;

            if (merge_enabled) {
                if (has_pending_trades_ && pending_trades_ci_ != ci) {
                    flush_pending_trades(false);
                }
                pending_trades_event_ts_ns_ = event_ts_ns;
                pending_trades_max_id_ = std::max(pending_trades_max_id_, tf.agg_trade_id);

                if (!has_pending_trades_) {
                    has_pending_trades_ = true;
                    pending_trades_ci_ = ci;
                    pending_trade_count_ = 0;
                    pending_trades_info_ = info;
                }
                if (pending_trade_count_ >= websocket::msg::MAX_TRADES) {
                    flush_pending_trades(false);
                    has_pending_trades_ = true;
                    pending_trades_ci_ = ci;
                    pending_trade_count_ = 0;
                    pending_trades_info_ = info;
                }
                auto& te = pending_trade_entries_[pending_trade_count_++];
                te.price = tf.price_mantissa;
                te.qty = tf.qty_mantissa;
                te.trade_id = tf.agg_trade_id;
                te.trade_time_ns = tf.trade_time_ms * 1000000LL;
                // buyer_is_maker=true means the taker is seller → NOT IS_BUYER
                te.flags = tf.buyer_is_maker ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                std::memset(te._pad, 0, sizeof(te._pad));

                info.set_merged(true);
                pending_ring_seq_slot_ = &pending_trades_ring_seq_;
            } else {
                // Non-merge: publish immediately
                last_trade_id_ = tf.agg_trade_id;
                record_win(ci);
                current_info_ = &info;
                publish_event([&](websocket::msg::MktEvent& ev) {
                    ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
                    ev.src_seq = tf.agg_trade_id;
                    ev.event_ts_ns = event_ts_ns;
                    ev.count = 1;
                    auto& te = ev.payload.trades.entries[0];
                    te.price = tf.price_mantissa;
                    te.qty = tf.qty_mantissa;
                    te.trade_id = tf.agg_trade_id;
                    te.trade_time_ns = tf.trade_time_ms * 1000000LL;
                    te.flags = tf.buyer_is_maker ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                    std::memset(te._pad, 0, sizeof(te._pad));
                });
                current_info_ = nullptr;
            }
            break;
        }

        case UsdmStreamType::DEPTH_PARTIAL: {
            // Cross-type flush
            if (has_pending_trades_) flush_pending_trades();

            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);

            auto df = parse_depth_fields(hdr.data_start, data_end);
            if (!df.valid) return;

            info.exchange_event_time_us = df.event_time_ms * 1000;
            info.mkt_event_seq = df.last_update_id;

            // Dedup by last_update_id
            if (df.last_update_id <= last_book_seq_) {
                info.set_discard_early(true);
                return;
            }
            last_book_seq_ = df.last_update_id;

            // Parse bid and ask levels
            static constexpr uint8_t SNAPSHOT_HALF = websocket::msg::MAX_BOOK_LEVELS / 2;  // 14
            websocket::msg::BookLevel bid_levels[SNAPSHOT_HALF];
            websocket::msg::BookLevel ask_levels[SNAPSHOT_HALF];
            uint8_t bid_count = 0, ask_count = 0;

            if (df.bids_array)
                bid_count = parse_book_levels(df.bids_array, data_end, bid_levels, SNAPSHOT_HALF);
            if (df.asks_array)
                ask_count = parse_book_levels(df.asks_array, data_end, ask_levels, SNAPSHOT_HALF);
            for (uint8_t i = 0; i < bid_count; i++) {
                bid_levels[i].price *= websocket::market::BinanceUSDM::price_scale;
                bid_levels[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
            }
            for (uint8_t i = 0; i < ask_count; i++) {
                ask_levels[i].price *= websocket::market::BinanceUSDM::price_scale;
                ask_levels[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
            }

            info.mkt_event_count = bid_count + ask_count;

            record_win(ci);
            current_info_ = &info;
            publish_event([&](websocket::msg::MktEvent& ev) {
                ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
                ev.flags = websocket::msg::EventFlags::SNAPSHOT;
                ev.src_seq = df.last_update_id;
                ev.event_ts_ns = df.event_time_ms * 1000000LL;
                ev.count = bid_count;
                ev.count2 = ask_count;
                for (uint8_t i = 0; i < bid_count; i++)
                    ev.payload.snapshot.levels[i] = bid_levels[i];
                for (uint8_t i = 0; i < ask_count; i++)
                    ev.payload.snapshot.levels[bid_count + i] = ask_levels[i];
            });
            current_info_ = nullptr;
            break;
        }

        case UsdmStreamType::DEPTH_DIFF: {
            // Cross-type flush
            if (has_pending_trades_) flush_pending_trades();

            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);

            auto df = parse_depth_fields(hdr.data_start, data_end);
            if (!df.valid) return;

            info.exchange_event_time_us = df.event_time_ms * 1000;
            info.mkt_event_seq = df.last_update_id;

            // Dedup by last_update_id
            if (df.last_update_id <= last_book_seq_) {
                info.set_discard_early(true);
                return;
            }
            last_book_seq_ = df.last_update_id;

            // Parse bid and ask deltas
            websocket::msg::DeltaEntry bid_deltas[websocket::msg::MAX_DELTAS];
            websocket::msg::DeltaEntry ask_deltas[websocket::msg::MAX_DELTAS];
            uint8_t bid_count = 0, ask_count = 0;

            if (df.bids_array)
                bid_count = parse_delta_levels(df.bids_array, data_end, bid_deltas,
                                               websocket::msg::MAX_DELTAS, false);
            if (df.asks_array)
                ask_count = parse_delta_levels(df.asks_array, data_end, ask_deltas,
                                               websocket::msg::MAX_DELTAS - bid_count, true);
            for (uint8_t i = 0; i < bid_count; i++) {
                bid_deltas[i].price *= websocket::market::BinanceUSDM::price_scale;
                bid_deltas[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
            }
            for (uint8_t i = 0; i < ask_count; i++) {
                ask_deltas[i].price *= websocket::market::BinanceUSDM::price_scale;
                ask_deltas[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
            }

            uint8_t total = bid_count + ask_count;
            info.mkt_event_count = total;

            record_win(ci);
            current_info_ = &info;
            publish_event([&](websocket::msg::MktEvent& ev) {
                ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
                ev.flags = 0;
                ev.src_seq = df.last_update_id;
                ev.event_ts_ns = df.event_time_ms * 1000000LL;
                ev.count = total;
                std::memcpy(ev.payload.deltas.entries, bid_deltas,
                            bid_count * sizeof(websocket::msg::DeltaEntry));
                std::memcpy(ev.payload.deltas.entries + bid_count, ask_deltas,
                            ask_count * sizeof(websocket::msg::DeltaEntry));
            });
            current_info_ = nullptr;
            break;
        }

        default:
            break;
        }
    }

    // ── Batch boundary / lifecycle ─────────────────────────────────────────

    void on_batch_end(uint8_t) {
        flush_pending_trades();
    }

    void on_heartbeat(uint8_t ci, uint8_t type) {
        publish_status(websocket::msg::SystemStatusType::HEARTBEAT, ci, 0,
                       type == 0 ? "PING" : "PONG");
    }

    void on_disconnected(uint8_t ci) {
        if (ci < PIPELINE_MAX_CONN) sbe_state_[ci].reset();
        publish_status(websocket::msg::SystemStatusType::DISCONNECTED, ci);
    }

    void on_reconnected(uint8_t ci) {
        if (ci < PIPELINE_MAX_CONN) sbe_state_[ci].reset();
        publish_status(websocket::msg::SystemStatusType::RECONNECTED, ci);
    }

    // ── Event publishing (copied from BinanceSBEHandler) ───────────────────

    void flush_pending_trades(bool clear_merged = true) {
        if (!has_pending_trades_) return;
        has_pending_trades_ = false;
        if (clear_merged && ws_frame_info_prod_ && pending_trades_ring_seq_ >= 0)
            (*ws_frame_info_prod_)[pending_trades_ring_seq_].set_merged(false);
        if (clear_merged) pending_trades_ring_seq_ = -1;
        last_trade_id_ = std::max(last_trade_id_, pending_trades_max_id_);
        record_win(pending_trades_ci_);
        current_info_ = &pending_trades_info_;
        publish_event([&](websocket::msg::MktEvent& ev) {
            ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
            ev.src_seq = pending_trade_entries_[pending_trade_count_ - 1].trade_id;
            ev.event_ts_ns = pending_trades_event_ts_ns_;
            ev.count = pending_trade_count_;
            std::memcpy(ev.payload.trades.entries, pending_trade_entries_,
                        pending_trade_count_ * sizeof(websocket::msg::TradeEntry));
        });
        current_info_ = nullptr;
        pending_trade_count_ = 0;
    }

    void publish_status(websocket::msg::SystemStatusType status, uint8_t ci,
                        int64_t detail = 0, const char* msg = nullptr) {
        if (!mkt_event_prod) return;
        int64_t slot = mkt_event_prod->try_claim();
        if (slot < 0) return;
        auto& e = (*mkt_event_prod)[slot];
        e.clear();
        e.venue_id = static_cast<uint8_t>(websocket::msg::VenueId::BINANCE);
        e.event_type = static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS);
        struct timespec ts_real;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        e.recv_ts_ns = static_cast<int64_t>(ts_real.tv_sec) * 1000000000LL + ts_real.tv_nsec;
        e.payload.status.status_type = static_cast<uint8_t>(status);
        e.payload.status.connection_id = ci;
        e.payload.status.detail_code = detail;
        if (msg) {
            std::strncpy(e.payload.status.message, msg,
                         sizeof(e.payload.status.message) - 1);
        }
        mkt_event_prod->publish(slot);
    }

    template<typename F>
    void publish_event(F&& build) {
        if (!mkt_event_prod) return;
        int64_t slot = mkt_event_prod->try_claim();
        if (slot < 0) return;
        auto& e = (*mkt_event_prod)[slot];
        e.clear();
        e.venue_id = static_cast<uint8_t>(websocket::msg::VenueId::BINANCE);
        struct timespec ts_real, ts_mono;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        int64_t real_ns = static_cast<int64_t>(ts_real.tv_sec) * 1000000000LL + ts_real.tv_nsec;
        int64_t mono_ns = static_cast<int64_t>(ts_mono.tv_sec) * 1000000000LL + ts_mono.tv_nsec;
        e.recv_ts_ns = real_ns;
        if (current_info_) {
            int64_t mono_arrival = 0;
            if (current_info_->latest_bpf_entry_ns > 0)
                mono_arrival = static_cast<int64_t>(current_info_->latest_bpf_entry_ns);
            else if (current_info_->first_byte_ts > 0)
                mono_arrival = static_cast<int64_t>(current_info_->first_byte_ts);
            if (mono_arrival > 0)
                e.nic_ts_ns = real_ns - (mono_ns - mono_arrival);
        }
        build(e);
        e.set_connection_id(active_ci_);
        mkt_event_prod->publish(slot);
    }

    void record_win(uint8_t ci) {
        if (ci != active_ci_) {
            active_ci_ = ci;
            if (conn_state)
                conn_state->conn_priority.active_connection.store(ci, std::memory_order_release);
        }
    }
};

}  // namespace websocket::json

#endif  // PIPELINE_DATA_HPP_INCLUDED
