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
#include "stream_decoder.hpp"

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
    case 't': return std::min(p + 4, end);  // true
    case 'f': return std::min(p + 5, end);  // false
    case 'n': return std::min(p + 4, end);  // null
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
    if (name_end <= name_start) return hdr;  // truncated — no valid name
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

// ── Essential Decoder (two-step dedup) ─────────────────────────────────────

struct BinanceUSDMJsonDecoder {
    struct Essential {
        uint16_t       msg_type = 0;       // UsdmStreamType → uint16_t
        int64_t        sequence = 0;       // agg_trade_id or last_update_id
        int64_t        event_time_ms = 0;  // "E"
        int64_t        txn_time_ms = 0;    // "T" (depth only)
        const uint8_t* data_start = nullptr;
        const uint8_t* resume_pos = nullptr;  // position after sequence field
        const uint8_t* data_end = nullptr;
        bool           valid = false;
    };

    static Essential decode_essential(const uint8_t* payload, uint32_t len) {
        Essential e;
        auto hdr = parse_combined_stream(payload, len);
        if (hdr.type == UsdmStreamType::UNKNOWN || !hdr.data_start) return e;

        e.msg_type = static_cast<uint16_t>(hdr.type);
        e.data_start = hdr.data_start;
        e.data_end = hdr.data_start + hdr.data_len;
        const uint8_t* p = hdr.data_start;
        const uint8_t* end = e.data_end;

        if (p >= end || *p != '{') return e;
        ++p;
        while (p < end && *p == ' ') ++p;

        switch (hdr.type) {
        case UsdmStreamType::AGG_TRADE:
            // e(skip), E(extract), next(skip), next(extract=sequence)
            p = skip_field(p, end);
            p = to_value(p, end); e.event_time_ms = parse_int64_fast(p, end);
            while (p < end && (*p == ',' || *p == ' ')) ++p;
            p = skip_field(p, end);
            p = to_value(p, end); e.sequence = parse_int64_fast(p, end);
            while (p < end && (*p == ',' || *p == ' ')) ++p;
            // Fallback: if positional parse got 0, field order may differ — scan for "a":
            if (e.sequence == 0) {
                for (const uint8_t* a = hdr.data_start; a + 4 < end; ++a) {
                    if (a[0] == '"' && a[1] == 'a' && a[2] == '"' && a[3] == ':') {
                        a += 4;
                        while (a < end && *a == ' ') ++a;
                        e.sequence = parse_int64_fast(a, end);
                        break;
                    }
                }
            }
            e.resume_pos = p; e.valid = true;
            break;
        case UsdmStreamType::DEPTH_PARTIAL:
        case UsdmStreamType::DEPTH_DIFF:
            // e(skip), E(extract), T(extract), s(skip), U(skip), u(extract=sequence)
            p = skip_field(p, end);
            p = to_value(p, end); e.event_time_ms = parse_int64_fast(p, end);
            while (p < end && (*p == ',' || *p == ' ')) ++p;
            p = to_value(p, end); e.txn_time_ms = parse_int64_fast(p, end);
            while (p < end && (*p == ',' || *p == ' ')) ++p;
            p = skip_field(p, end);
            p = skip_field(p, end);
            p = to_value(p, end); e.sequence = parse_int64_fast(p, end);
            while (p < end && (*p == ',' || *p == ' ')) ++p;
            e.resume_pos = p; e.valid = true;
            break;
        default: break;
        }
        return e;
    }
};
static_assert(websocket::msg::StreamDecoderPolicy<BinanceUSDMJsonDecoder>);

// ── Remaining-Field Parsers (for fresh messages after decode_essential) ────

struct AggTradeRemaining {  // fields after "a": p, q, nq, f, l, T, m
    int64_t price_mantissa = 0;
    int64_t qty_mantissa = 0;
    int64_t trade_time_ms = 0;
    bool buyer_is_maker = false;
    bool valid = false;
};

// p at resume_pos (after "a":NNN,), end at data_end
inline AggTradeRemaining parse_agg_trade_remaining(const uint8_t* p, const uint8_t* end) {
    AggTradeRemaining r;
    // Field 5: "p" (price string)
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    r.price_mantissa = parse_decimal_string(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;
    // Field 6: "q" (quantity string)
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    r.qty_mantissa = parse_decimal_string(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;
    // Field 7: "nq" — skip
    if (p >= end || *p != '"') return r;
    p = skip_field(p, end);
    // Field 8: "f" — skip
    if (p >= end || *p != '"') return r;
    p = skip_field(p, end);
    // Field 9: "l" — skip
    if (p >= end || *p != '"') return r;
    p = skip_field(p, end);
    // Field 10: "T" (trade time)
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    r.trade_time_ms = parse_int64_fast(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;
    // Field 11: "m" (buyer is maker)
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    if (!p || p >= end) return r;   // value truncated at TLS boundary
    r.buyer_is_maker = parse_bool_fast(p, end);
    r.valid = true;
    return r;
}

struct DepthRemaining {     // fields after "u": pu, b, a
    const uint8_t* bids_array = nullptr;
    const uint8_t* asks_array = nullptr;
    const uint8_t* end = nullptr;
    bool valid = false;
};

// p at resume_pos (after "u":NNN,), end at data_end
inline DepthRemaining parse_depth_remaining(const uint8_t* p, const uint8_t* end) {
    DepthRemaining r;
    r.end = end;
    // Field 7: "pu" — skip
    if (p >= end || *p != '"') return r;
    p = skip_field(p, end);
    // Field 8: "b" (bids array) — locate
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    r.bids_array = p;
    p = skip_value(p, end);
    while (p < end && (*p == ',' || *p == ' ')) ++p;
    // Field 9: "a" (asks array) — locate
    if (p >= end || *p != '"') return r;
    p = to_value(p, end);
    r.asks_array = p;
    r.valid = true;
    return r;
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
    if (!p || p >= end) return f;   // value truncated at TLS boundary
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
    enum Phase : uint8_t {
        IDLE = 0,
        HEADER_PARSED,   // decode_essential done, metadata saved, dedup passed
        BIDS_PARSING,    // Parsing bid levels into delta_buf
        ASKS_PARSING,    // Parsing ask levels into delta_buf
        DONE,            // Fully parsed or published, skip on subsequent fragments
    };

    Phase    phase = IDLE;
    bool     deduped = false;       // true if dedup early-return set DONE
    uint16_t msg_type = 0;          // UsdmStreamType
    int64_t  sequence = 0;          // agg_trade_id or last_update_id
    int64_t  event_time_us = 0;     // E * 1000
    int64_t  event_time_ms = 0;     // "E" raw (for publish)

    // Resume tracking
    uint32_t resume_offset = 0;     // byte offset from payload start to resume parsing

    // Depth level accumulation (mirrors SBE delta_buf)
    uint8_t  delta_count = 0;       // total entries in delta_buf
    uint8_t  snapshot_bid_count = 0; // bids in delta_buf (for snapshot bid/ask split)
    uint16_t bids_count = 0;
    uint16_t asks_count = 0;
    uint16_t group_count = 0;       // for timeline display
    uint8_t  flush_count = 0;       // multi-flush batch counter (for CONTINUATION flag)
    websocket::msg::DeltaEntry delta_buf[websocket::msg::MAX_BOOK_LEVELS]; // 29 slots

    void reset() {
        phase = IDLE; msg_type = 0; sequence = 0; event_time_us = 0;
        event_time_ms = 0; resume_offset = 0; deduped = false; delta_count = 0;
        snapshot_bid_count = 0; bids_count = 0; asks_count = 0; group_count = 0;
        flush_count = 0;
    }
};

// ── Streaming level parser ──────────────────────────────────────────────────

struct StreamingParseResult {
    uint8_t  new_count;       // complete levels parsed in this call
    uint32_t resume_offset;   // byte offset from payload start to resume
    bool     array_done;      // saw closing ']' of outer array
};

// Parse [["price","qty"],...] levels incrementally from payload.
// Starts at start_offset, writes into buf starting at buf_idx.
// Each level's [, price "...", qty "...", and closing ] must ALL be found
// before committing. On truncation mid-level, reverts to level start.
inline StreamingParseResult parse_levels_streaming(
    const uint8_t* payload, uint32_t len, uint32_t start_offset,
    websocket::msg::DeltaEntry* buf, uint8_t buf_idx, uint8_t buf_max,
    bool is_ask) {
    StreamingParseResult result{};
    result.new_count = 0;
    result.resume_offset = start_offset;
    result.array_done = false;

    const uint8_t* p = payload + start_offset;
    const uint8_t* end = payload + len;

    // Caller must advance past outer '[' before calling — start_offset
    // should point to the first element or whitespace/comma inside the array.

    while (p < end && buf_idx < buf_max) {
        // Skip whitespace/commas
        while (p < end && (*p == ',' || *p == ' ' || *p == '\n' || *p == '\r')) ++p;
        if (p >= end) break;

        // Check for end of array
        if (*p == ']') {
            result.array_done = true;
            result.resume_offset = static_cast<uint32_t>(p + 1 - payload);
            return result;
        }

        // Save position at start of this level for revert on truncation
        const uint8_t* level_start = p;

        // Expect inner '['
        if (*p != '[') break;
        ++p;

        // Parse price string: find opening '"'
        while (p < end && *p != '"') ++p;
        if (p >= end) { result.resume_offset = static_cast<uint32_t>(level_start - payload); return result; }
        int64_t price = parse_decimal_string(p, end);
        // p is now past closing '"' of price

        // Skip comma between price and qty
        while (p < end && *p != '"') ++p;
        if (p >= end) { result.resume_offset = static_cast<uint32_t>(level_start - payload); return result; }
        int64_t qty = parse_decimal_string(p, end);

        // Find closing ']' of inner array
        while (p < end && *p != ']') ++p;
        if (p >= end) { result.resume_offset = static_cast<uint32_t>(level_start - payload); return result; }
        ++p;  // skip ']'

        // Commit this level
        auto& de = buf[buf_idx];
        de.price = price;
        de.qty = qty;
        de.action = (qty == 0)
            ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
            : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
        de.flags = is_ask ? websocket::msg::DeltaFlags::SIDE_ASK : 0;
        std::memset(de._pad, 0, sizeof(de._pad));
        buf_idx++;
        result.new_count++;
    }

    // Update resume offset to current position
    result.resume_offset = static_cast<uint32_t>(p - payload);

    // Check if next char after whitespace/commas is ']'
    while (p < end && (*p == ',' || *p == ' ' || *p == '\n' || *p == '\r')) ++p;
    if (p < end && *p == ']') {
        result.array_done = true;
        result.resume_offset = static_cast<uint32_t>(p + 1 - payload);
    }

    return result;
}

// ── Streaming template functions ────────────────────────────────────────────

// AGG_TRADE: retry parse_agg_trade_remaining on each fragment
template<typename Handler>
inline void trade_streaming_continue(
    Handler& self, JsonParseState& state, uint8_t ci,
    const uint8_t* payload, uint32_t len,
    websocket::pipeline::WSFrameInfo& info) {
    if (state.phase == JsonParseState::DONE) return;

    auto r = parse_agg_trade_remaining(payload + state.resume_offset,
                                        payload + len);
    if (!r.valid) return;  // wait for more data

    r.price_mantissa *= websocket::market::BinanceUSDM::price_scale;
    r.qty_mantissa   *= websocket::market::BinanceUSDM::qty_scale;

    int64_t event_ts_ns = state.event_time_ms * 1000000LL;

    if (self.merge_enabled) {
        if (self.has_pending_trades_ && self.pending_trades_ci_ != ci) {
            self.flush_pending_trades(false);
        }
        self.pending_trades_event_ts_ns_ = event_ts_ns;
        self.pending_trades_max_id_ = std::max(self.pending_trades_max_id_, state.sequence);

        if (!self.has_pending_trades_) {
            self.has_pending_trades_ = true;
            self.pending_trades_ci_ = ci;
            self.pending_trade_count_ = 0;
            self.pending_trades_info_ = info;
        }
        if (self.pending_trade_count_ >= websocket::msg::MAX_TRADES) {
            self.flush_pending_trades(false);
            self.has_pending_trades_ = true;
            self.pending_trades_ci_ = ci;
            self.pending_trade_count_ = 0;
            self.pending_trades_info_ = info;
        }
        auto& te = self.pending_trade_entries_[self.pending_trade_count_++];
        te.price = r.price_mantissa;
        te.qty = r.qty_mantissa;
        te.trade_id = state.sequence;
        te.trade_time_ns = r.trade_time_ms * 1000000LL;
        te.flags = r.buyer_is_maker ? 0 : websocket::msg::TradeFlags::IS_BUYER;
        std::memset(te._pad, 0, sizeof(te._pad));

        info.set_merged(true);
        self.pending_ring_seq_slot_ = &self.pending_trades_ring_seq_;
    } else {
        self.last_trade_id_ = state.sequence;
        self.record_win(ci);
        self.publish_event([&](websocket::msg::MktEvent& ev) {
            ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
            ev.src_seq = state.sequence;
            ev.event_ts_ns = event_ts_ns;
            ev.count = 1;
            auto& te = ev.payload.trades.entries[0];
            te.price = r.price_mantissa;
            te.qty = r.qty_mantissa;
            te.trade_id = state.sequence;
            te.trade_time_ns = r.trade_time_ms * 1000000LL;
            te.flags = r.buyer_is_maker ? 0 : websocket::msg::TradeFlags::IS_BUYER;
            std::memset(te._pad, 0, sizeof(te._pad));
        });
    }
    state.phase = JsonParseState::DONE;
}

// Flush accumulated delta_buf as BOOK_DELTA
template<typename Handler>
inline void flush_depth_deltas_json(Handler& self, JsonParseState& state, uint8_t ci,
                                     websocket::pipeline::WSFrameInfo& info,
                                     bool is_final = false) {
    if (state.delta_count == 0) return;
    auto type = static_cast<UsdmStreamType>(state.msg_type);
    bool is_snapshot = (type == UsdmStreamType::DEPTH_PARTIAL);
    self.record_win(ci);
    uint8_t count = state.delta_count;
    int64_t seq = state.sequence;
    uint8_t fc = state.flush_count;
    // Apply scale factors at flush time
    for (uint8_t i = 0; i < count; i++) {
        state.delta_buf[i].price *= websocket::market::BinanceUSDM::price_scale;
        state.delta_buf[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
    }
    self.publish_event([&](websocket::msg::MktEvent& e) {
        e.event_type = static_cast<uint8_t>(
            is_snapshot ? websocket::msg::EventType::BOOK_SNAPSHOT : websocket::msg::EventType::BOOK_DELTA);
        uint16_t f = is_snapshot ? websocket::msg::EventFlags::SNAPSHOT : static_cast<uint16_t>(0);
        if (fc > 0)    f |= websocket::msg::EventFlags::CONTINUATION;
        if (is_final)  f |= websocket::msg::EventFlags::LAST_IN_BATCH;
        e.flags = f;
        e.src_seq = seq;
        e.event_ts_ns = state.event_time_ms * 1000000LL;
        e.count = count;
        std::memcpy(e.payload.deltas.entries, state.delta_buf,
                    count * sizeof(websocket::msg::DeltaEntry));
    });
    state.flush_count++;
    state.delta_count = 0;
}

// Flush accumulated delta_buf as BOOK_SNAPSHOT (bids + asks split)
template<typename Handler>
inline void flush_depth_snapshot_json(Handler& self, JsonParseState& state, uint8_t ci,
                                      websocket::pipeline::WSFrameInfo& info,
                                      bool is_final = false) {
    if (state.delta_count == 0) return;
    self.record_win(ci);
    uint8_t total = state.delta_count;
    int64_t seq = state.sequence;
    uint8_t bid_n = state.snapshot_bid_count;
    uint8_t ask_n = total - bid_n;
    // Apply scale factors at flush time
    for (uint8_t i = 0; i < total; i++) {
        state.delta_buf[i].price *= websocket::market::BinanceUSDM::price_scale;
        state.delta_buf[i].qty   *= websocket::market::BinanceUSDM::qty_scale;
    }
    self.publish_event([&](websocket::msg::MktEvent& e) {
        e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
        uint16_t f = websocket::msg::EventFlags::SNAPSHOT;
        if (state.flush_count > 0) f |= websocket::msg::EventFlags::CONTINUATION;
        if (is_final)              f |= websocket::msg::EventFlags::LAST_IN_BATCH;
        e.flags = f;
        e.src_seq = seq;
        e.event_ts_ns = state.event_time_ms * 1000000LL;
        e.count = bid_n;
        e.count2 = ask_n;
        for (uint8_t i = 0; i < total; i++)
            e.payload.snapshot.levels[i] = { state.delta_buf[i].price, state.delta_buf[i].qty };
    });
    state.flush_count++;
    state.delta_count = 0;
}

// Depth streaming: parse bids/asks incrementally, flush at capacity
static constexpr uint8_t JSON_SNAPSHOT_HALF = websocket::msg::MAX_BOOK_LEVELS / 2;  // 14

template<typename Handler>
inline void depth_streaming_continue(
    Handler& self, JsonParseState& state, uint8_t ci,
    const uint8_t* payload, uint32_t len,
    websocket::pipeline::WSFrameInfo& info) {
    if (state.phase == JsonParseState::DONE) return;

    auto type = static_cast<UsdmStreamType>(state.msg_type);
    bool is_snapshot = (type == UsdmStreamType::DEPTH_PARTIAL);

    // HEADER_PARSED → locate "b":[ array start
    if (state.phase == JsonParseState::HEADER_PARSED) {
        auto r = parse_depth_remaining(payload + state.resume_offset, payload + len);
        if (!r.valid) return;  // need more data to find "b":[
        // Found bids array — skip outer '[' and transition to BIDS_PARSING
        state.resume_offset = static_cast<uint32_t>(r.bids_array - payload + 1);
        state.phase = JsonParseState::BIDS_PARSING;
    }

    // BIDS_PARSING → parse bid levels into delta_buf
    if (state.phase == JsonParseState::BIDS_PARSING) {
        uint8_t max_bids = is_snapshot ? JSON_SNAPSHOT_HALF
                                       : static_cast<uint8_t>(websocket::msg::MAX_DELTAS);
        while (state.phase == JsonParseState::BIDS_PARSING) {
            uint8_t remaining = max_bids - state.delta_count;
            if (remaining == 0) {
                // Snapshot: skip remaining bids, find ']' then transition to asks
                if (is_snapshot) {
                    const uint8_t* p = payload + state.resume_offset;
                    const uint8_t* end_ptr = payload + len;
                    // Fast-scan past remaining bid levels to find outer ']'
                    int depth = 0;
                    while (p < end_ptr) {
                        if (*p == '"') { p = skip_string(p, end_ptr); continue; }
                        if (*p == '[') { depth++; ++p; continue; }
                        if (*p == ']') { if (depth == 0) { ++p; break; } depth--; ++p; continue; }
                        ++p;
                    }
                    if (p >= end_ptr) return;  // truncated mid-skip
                    state.resume_offset = static_cast<uint32_t>(p - payload);
                    state.snapshot_bid_count = state.delta_count;
                    state.phase = JsonParseState::ASKS_PARSING;
                    break;
                }
                // Delta: flush and continue
                flush_depth_deltas_json(self, state, ci, info);
                remaining = static_cast<uint8_t>(websocket::msg::MAX_DELTAS);
            }

            auto sr = parse_levels_streaming(payload, len, state.resume_offset,
                                              state.delta_buf, state.delta_count,
                                              state.delta_count + remaining, false);
            state.bids_count += sr.new_count;
            state.delta_count += sr.new_count;
            state.resume_offset = sr.resume_offset;
            info.mkt_event_count = state.bids_count + state.asks_count;

            if (sr.array_done) {
                // Bids done, transition to asks
                state.snapshot_bid_count = state.delta_count;
                state.phase = JsonParseState::ASKS_PARSING;
                break;
            }
            if (sr.new_count == 0) return;  // truncated, wait for more data
        }
    }

    // ASKS_PARSING → locate "a":[ if needed, then parse ask levels
    if (state.phase == JsonParseState::ASKS_PARSING) {
        // Find "a":[ if we haven't started parsing asks yet
        const uint8_t* p = payload + state.resume_offset;
        const uint8_t* end_ptr = payload + len;
        // Skip comma/whitespace and find "a":
        while (p < end_ptr && (*p == ',' || *p == ' ' || *p == '\n' || *p == '\r')) ++p;
        if (p >= end_ptr) return;  // need more data
        if (*p == '"') {
            // Skip "a" key and ':' to get to array, then skip outer '['
            p = to_value(p, end_ptr);
            if (p >= end_ptr) return;
            if (*p == '[') ++p;  // skip outer '['
            if (p >= end_ptr) return;
            state.resume_offset = static_cast<uint32_t>(p - payload);
        }

        uint8_t max_asks = is_snapshot ? JSON_SNAPSHOT_HALF
                                       : static_cast<uint8_t>(websocket::msg::MAX_DELTAS);
        while (state.phase == JsonParseState::ASKS_PARSING) {
            uint8_t current_asks = is_snapshot
                ? static_cast<uint8_t>(state.delta_count - state.snapshot_bid_count)
                : state.asks_count;
            uint8_t remaining_asks;
            if (is_snapshot) {
                remaining_asks = (current_asks < JSON_SNAPSHOT_HALF)
                    ? (JSON_SNAPSHOT_HALF - current_asks) : 0;
            } else {
                remaining_asks = (state.delta_count < websocket::msg::MAX_DELTAS)
                    ? static_cast<uint8_t>(websocket::msg::MAX_DELTAS - state.delta_count) : 0;
            }

            if (remaining_asks == 0) {
                if (is_snapshot) {
                    // Snapshot full: publish immediately
                    flush_depth_snapshot_json(self, state, ci, info, /*is_final=*/true);
                    state.phase = JsonParseState::DONE;
                    return;
                }
                // Delta: flush and continue
                flush_depth_deltas_json(self, state, ci, info);
                continue;
            }

            auto sr = parse_levels_streaming(payload, len, state.resume_offset,
                                              state.delta_buf, state.delta_count,
                                              state.delta_count + remaining_asks, true);
            state.asks_count += sr.new_count;
            state.delta_count += sr.new_count;
            state.resume_offset = sr.resume_offset;
            info.mkt_event_count = state.bids_count + state.asks_count;

            if (sr.array_done) {
                // Done parsing all asks
                if (state.delta_count > 0) {
                    if (is_snapshot)
                        flush_depth_snapshot_json(self, state, ci, info, /*is_final=*/true);
                    else
                        flush_depth_deltas_json(self, state, ci, info, /*is_final=*/true);
                }
                state.phase = JsonParseState::DONE;
                return;
            }
            if (sr.new_count == 0) return;  // truncated, wait for more data
        }
    }
}

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

    // ── Main entry point (streaming: essential → metadata → dedup → streaming parse) ──

    void on_ws_data(JsonParseState& state, uint8_t ci,
                    const uint8_t* payload, uint32_t len,
                    websocket::pipeline::WSFrameInfo& info) {
        pending_ring_seq_slot_ = nullptr;

        // ── Resume in-progress streaming parse ──
        if (state.phase != JsonParseState::IDLE) {
            auto type = static_cast<UsdmStreamType>(state.msg_type);
            switch (type) {
            case UsdmStreamType::AGG_TRADE:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
            case UsdmStreamType::DEPTH_PARTIAL:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
            case UsdmStreamType::DEPTH_DIFF:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
            default: break;
            }
            info.exchange_event_time_us = state.event_time_us;
            info.mkt_event_seq = state.sequence;
            info.mkt_event_count = (state.bids_count > 0 || state.asks_count > 0)
                ? state.bids_count + state.asks_count : state.group_count;
            if (state.phase == JsonParseState::DONE) {
                if (state.deduped) info.set_discard_early(true);
                return;
            }

            // ── Re-check dedup: another connection may have superseded while streaming ──
            if (type == UsdmStreamType::AGG_TRADE) {
                int64_t eff_tid = has_pending_trades_
                    ? std::max(last_trade_id_, pending_trades_max_id_)
                    : last_trade_id_;
                if (state.sequence <= eff_tid) {
                    state.deduped = true;
                    state.phase = JsonParseState::DONE;
                    info.set_discard_early(true);
                    return;
                }
            } else if (state.sequence < last_book_seq_) {
                state.deduped = true;
                state.phase = JsonParseState::DONE;
                info.set_discard_early(true);
                return;
            }

            current_info_ = &info;
            if (type == UsdmStreamType::AGG_TRADE)
                trade_streaming_continue(*this, state, ci, payload, len, info);
            else
                depth_streaming_continue(*this, state, ci, payload, len, info);
            current_info_ = nullptr;
            return;
        }

        // ── Stage 1: decode essential ──
        auto e = BinanceUSDMJsonDecoder::decode_essential(payload, len);
        if (!e.valid) return;

        auto type = static_cast<UsdmStreamType>(e.msg_type);

        // Stage 2: set WSFrameInfo metadata
        info.exchange_event_time_us = e.event_time_ms * 1000;
        info.mkt_event_seq = e.sequence;

        switch (type) {
        case UsdmStreamType::AGG_TRADE: {
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
            info.mkt_event_count = 1;

            // Stage 4: early dedup by agg_trade_id
            int64_t eff_tid = has_pending_trades_
                ? std::max(last_trade_id_, pending_trades_max_id_)
                : last_trade_id_;
            if (e.sequence <= eff_tid) {
                info.set_discard_early(true);
                state.msg_type = e.msg_type;
                state.sequence = e.sequence;
                state.event_time_us = e.event_time_ms * 1000;
                state.deduped = true;
                state.phase = JsonParseState::DONE;
                return;
            }

            // Initialize streaming state
            state.phase = JsonParseState::HEADER_PARSED;
            state.msg_type = e.msg_type;
            state.sequence = e.sequence;
            state.event_time_us = e.event_time_ms * 1000;
            state.event_time_ms = e.event_time_ms;
            state.resume_offset = static_cast<uint32_t>(e.resume_pos - payload);
            state.group_count = 1;

            current_info_ = &info;
            trade_streaming_continue(*this, state, ci, payload, len, info);
            current_info_ = nullptr;
            break;
        }

        case UsdmStreamType::DEPTH_PARTIAL:
        case UsdmStreamType::DEPTH_DIFF: {
            if (has_pending_trades_) flush_pending_trades();
            bool is_snapshot = (type == UsdmStreamType::DEPTH_PARTIAL);
            info.mkt_event_type = static_cast<uint8_t>(
                is_snapshot ? websocket::msg::EventType::BOOK_SNAPSHOT : websocket::msg::EventType::BOOK_DELTA);

            if (e.sequence <= last_book_seq_) {
                info.set_discard_early(true);
                state.msg_type = e.msg_type;
                state.sequence = e.sequence;
                state.event_time_us = e.event_time_ms * 1000;
                state.deduped = true;
                state.phase = JsonParseState::DONE;
                return;
            }
            last_book_seq_ = e.sequence;

            state.phase = JsonParseState::HEADER_PARSED;
            state.msg_type = e.msg_type;
            state.sequence = e.sequence;
            state.event_time_us = e.event_time_ms * 1000;
            state.event_time_ms = e.event_time_ms;
            state.resume_offset = static_cast<uint32_t>(e.resume_pos - payload);
            state.delta_count = 0;
            state.snapshot_bid_count = 0;
            state.bids_count = 0;
            state.asks_count = 0;

            current_info_ = &info;
            depth_streaming_continue(*this, state, ci, payload, len, info);
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
