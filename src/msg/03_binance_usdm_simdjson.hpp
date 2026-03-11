// msg/03_binance_usdm_simdjson.hpp
// Binance USD-M Futures: simdjson On Demand parse functions (Part 1 only)
//
// websocket::json::simd — simdjson On Demand parsers for Binance futures streams.
//   Reuses types and classify_stream() from 01_binance_usdm_json.hpp.
//   Uses simdjson 4.x On Demand (streaming cursor, no DOM tree).
#pragma once

#include "msg/01_binance_usdm_json.hpp"   // reuse types, classify_stream
#include "msg/market_conf.hpp"
#include "vendor/simdjson.h"

namespace websocket::json::simd {

// Decimal string_view -> int64 mantissa ("7403.89" -> 740389)
inline int64_t decimal_sv_to_int64(std::string_view sv) {
    bool neg = false;
    const char* s = sv.data();
    const char* end = s + sv.size();
    if (s < end && *s == '-') { neg = true; ++s; }
    int64_t v = 0;
    while (s < end) {
        if (*s == '.') { ++s; continue; }
        if (*s >= '0' && *s <= '9') v = v * 10 + (*s - '0');
        ++s;
    }
    return neg ? -v : v;
}

// Combined stream parse: classify + get data object.
// Caller owns the document via this struct — it must stay alive while accessing data.
struct SimdCombinedResult {
    UsdmStreamType type = UsdmStreamType::UNKNOWN;
    simdjson::ondemand::document doc;
    simdjson::ondemand::object data;
    bool valid = false;
};

inline SimdCombinedResult simd_parse_combined(
        simdjson::ondemand::parser& parser,
        const uint8_t* padded_buf, size_t len, size_t capacity) {
    SimdCombinedResult res;
    if (parser.iterate(padded_buf, len, capacity).get(res.doc))
        return res;

    std::string_view stream;
    if (res.doc.find_field("stream").get_string().get(stream))
        return res;
    res.type = classify_stream(
        reinterpret_cast<const uint8_t*>(stream.data()),
        static_cast<uint32_t>(stream.size()));
    if (res.type == UsdmStreamType::UNKNOWN) return res;
    if (res.doc.find_field("data").get_object().get(res.data))
        return res;
    res.valid = true;
    return res;
}

// Parse aggTrade from On Demand data object
inline AggTradeFields simd_parse_agg_trade(simdjson::ondemand::object& data) {
    AggTradeFields f{};
    int64_t val;
    std::string_view sv;
    bool bv;
    if (data.find_field("E").get_int64().get(val)) return f;
    f.event_time_ms = val;
    if (data.find_field("a").get_int64().get(val)) return f;
    f.agg_trade_id = val;
    if (data.find_field("p").get_string().get(sv)) return f;
    f.price_mantissa = decimal_sv_to_int64(sv);
    if (data.find_field("q").get_string().get(sv)) return f;
    f.qty_mantissa = decimal_sv_to_int64(sv);
    if (data.find_field("T").get_int64().get(val)) return f;
    f.trade_time_ms = val;
    if (data.find_field("m").get_bool().get(bv)) return f;
    f.buyer_is_maker = bv;
    f.valid = true;
    return f;
}

// Depth header — scalar fields only. Caller must then get "b"/"a" arrays
// from the same data object (On Demand cursor is positioned after "u").
struct SimdDepthHeader {
    int64_t event_time_ms = 0;
    int64_t txn_time_ms = 0;
    int64_t last_update_id = 0;
    bool valid = false;
};

inline SimdDepthHeader simd_parse_depth_header(simdjson::ondemand::object& data) {
    SimdDepthHeader f{};
    int64_t val;
    if (data.find_field("E").get_int64().get(val)) return f;
    f.event_time_ms = val;
    if (data.find_field("T").get_int64().get(val)) return f;
    f.txn_time_ms = val;
    if (data.find_field("u").get_int64().get(val)) return f;
    f.last_update_id = val;
    f.valid = true;
    return f;
}

// Parse [[price,qty],...] from On Demand array into BookLevel[]
inline uint8_t simd_parse_book_levels(simdjson::ondemand::array& arr,
                                       websocket::msg::BookLevel* out, uint8_t max) {
    uint8_t count = 0;
    for (auto item : arr) {
        if (count >= max) break;
        auto inner = item.get_array();
        std::string_view price_sv, qty_sv;
        auto it = inner.begin();
        if ((*it).get_string().get(price_sv)) break;
        ++it;
        if ((*it).get_string().get(qty_sv)) break;
        out[count].price = decimal_sv_to_int64(price_sv);
        out[count].qty   = decimal_sv_to_int64(qty_sv);
        count++;
    }
    return count;
}

inline uint8_t simd_parse_delta_levels(simdjson::ondemand::array& arr,
                                        websocket::msg::DeltaEntry* out, uint8_t max,
                                        bool is_ask) {
    uint8_t count = 0;
    for (auto item : arr) {
        if (count >= max) break;
        auto inner = item.get_array();
        std::string_view price_sv, qty_sv;
        auto it = inner.begin();
        if ((*it).get_string().get(price_sv)) break;
        ++it;
        if ((*it).get_string().get(qty_sv)) break;
        out[count].price  = decimal_sv_to_int64(price_sv);
        out[count].qty    = decimal_sv_to_int64(qty_sv);
        out[count].action = (out[count].qty == 0)
            ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
            : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
        out[count].flags  = is_ask ? websocket::msg::DeltaFlags::SIDE_ASK : 0;
        std::memset(out[count]._pad, 0, sizeof(out[count]._pad));
        count++;
    }
    return count;
}

// Parse forceOrder from On Demand data object
struct SimdForceOrderFields {
    int64_t price = 0;
    int64_t avg_price = 0;
    int64_t orig_qty = 0;
    int64_t filled_qty = 0;
    int64_t trade_time_ms = 0;
    bool    is_sell = false;
    bool    valid = false;
};

inline SimdForceOrderFields simd_parse_force_order(simdjson::ondemand::object& data) {
    SimdForceOrderFields f{};
    simdjson::ondemand::object order;
    if (data.find_field("o").get_object().get(order)) return f;
    std::string_view sv;
    if (order.find_field("S").get_string().get(sv)) return f;
    f.is_sell = (sv.size() > 0 && sv[0] == 'S');
    if (order.find_field("q").get_string().get(sv)) return f;
    f.orig_qty = decimal_sv_to_int64(sv);
    if (order.find_field("p").get_string().get(sv)) return f;
    f.price = decimal_sv_to_int64(sv);
    if (order.find_field("ap").get_string().get(sv)) return f;
    f.avg_price = decimal_sv_to_int64(sv);
    if (order.find_field("z").get_string().get(sv)) return f;
    f.filled_qty = decimal_sv_to_int64(sv);
    int64_t val;
    if (order.find_field("T").get_int64().get(val)) return f;
    f.trade_time_ms = val;
    f.valid = true;
    return f;
}

// Parse markPriceUpdate from On Demand data object
struct SimdMarkPriceFields {
    int64_t mark_price = 0;
    int64_t index_price = 0;
    int64_t settle_price = 0;
    int64_t funding_rate = 0;
    int64_t next_funding_time_ms = 0;
    bool    valid = false;
};

inline SimdMarkPriceFields simd_parse_mark_price(simdjson::ondemand::object& data) {
    SimdMarkPriceFields f{};
    std::string_view sv;
    if (data.find_field("p").get_string().get(sv)) return f;
    f.mark_price = decimal_sv_to_int64(sv);
    if (data.find_field("i").get_string().get(sv)) return f;
    f.index_price = decimal_sv_to_int64(sv);
    if (data.find_field("P").get_string().get(sv)) return f;
    f.settle_price = decimal_sv_to_int64(sv);
    if (data.find_field("r").get_string().get(sv)) return f;
    f.funding_rate = decimal_sv_to_int64(sv);
    int64_t val;
    if (data.find_field("T").get_int64().get(val)) return f;
    f.next_funding_time_ms = val;
    f.valid = true;
    return f;
}

}  // namespace websocket::json::simd

// ============================================================================
// Part 2: BinanceUSDMSimdjsonParser (requires pipeline_data.hpp)
// ============================================================================

#ifdef PIPELINE_DATA_HPP_INCLUDED

namespace websocket::json {

struct BinanceUSDMSimdjsonParser {
    static constexpr bool enabled = true;
    JsonParseState sbe_state_[PIPELINE_MAX_CONN]{};

    // Pipeline wiring (same members as BinanceUSDMJsonParser)
    websocket::pipeline::IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    websocket::pipeline::ConnStateShm* conn_state = nullptr;
    bool merge_enabled = true;
    static constexpr int DEPTH_CHANNELS = 4;
    int64_t last_book_seq_[DEPTH_CHANNELS] = {};
    InterleaveState interleave_[DEPTH_CHANNELS]{};
    int64_t last_trade_id_ = 0;
    uint16_t instrument_id = 0;
    uint8_t active_ci_ = 0xFF;
    websocket::pipeline::WSFrameInfo* current_info_ = nullptr;

    websocket::pipeline::IPCRingProducer<websocket::pipeline::WSFrameInfo>* ws_frame_info_prod_ = nullptr;
    int64_t pending_trades_ring_seq_ = -1;
    int64_t* pending_ring_seq_slot_ = nullptr;

    bool has_pending_trades_ = false;
    uint8_t pending_trades_ci_ = 0;
    uint8_t pending_trade_count_ = 0;
    websocket::msg::TradeEntry pending_trade_entries_[websocket::msg::MAX_TRADES];
    int64_t pending_trades_event_ts_ns_ = 0;
    int64_t pending_trades_max_id_ = 0;
    websocket::pipeline::WSFrameInfo pending_trades_info_{};

    // Per-channel pending depth delta accumulation buffer
    struct PendingDepth {
        bool has_pending = false;
        uint8_t ci = 0;
        uint8_t count = 0;
        uint8_t flush_count = 0;
        websocket::msg::DeltaEntry entries[websocket::msg::MAX_DELTAS];
        int64_t seq = 0;
        int64_t event_ts_ns = 0;
        websocket::pipeline::WSFrameInfo info{};
    };
    PendingDepth pending_depth_[DEPTH_CHANNELS];

    // Dedup for non-streaming event types
    int64_t last_liq_time_ = 0;
    int64_t last_mark_price_time_ = 0;

    // simdjson reusable parser (allocates internal buffers once)
    simdjson::ondemand::parser simd_parser_;

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
            case UsdmStreamType::DEPTH_DIFF_0:
            case UsdmStreamType::DEPTH_DIFF_1:
            case UsdmStreamType::DEPTH_DIFF_2:
            case UsdmStreamType::DEPTH_DIFF_3:
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
            } else if (is_depth_diff_type(type)) {
                uint8_t ch = depth_channel_index(type);
                if (state.sequence < last_book_seq_[ch]) {
                    state.deduped = true;
                    state.phase = JsonParseState::DONE;
                    info.set_discard_early(true);
                    return;
                }
                if (state.sequence == last_book_seq_[ch]) {
                    auto& il = interleave_[ch];
                    if (il.seq == state.sequence && il.finished) {
                        state.deduped = true;
                        state.phase = JsonParseState::DONE;
                        info.set_discard_early(true);
                        return;
                    }
                }
            } else if (type == UsdmStreamType::DEPTH_PARTIAL) {
                bool stale = true;
                for (int c = 0; c < DEPTH_CHANNELS; c++) {
                    if (state.sequence >= last_book_seq_[c]) { stale = false; break; }
                }
                if (stale) {
                    state.deduped = true;
                    state.phase = JsonParseState::DONE;
                    info.set_discard_early(true);
                    return;
                }
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
            for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
                if (pending_depth_[ch].has_pending) publish_pending_depth(ch, true);
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
        case UsdmStreamType::DEPTH_DIFF_0:
        case UsdmStreamType::DEPTH_DIFF_1:
        case UsdmStreamType::DEPTH_DIFF_2:
        case UsdmStreamType::DEPTH_DIFF_3: {
            if (has_pending_trades_) flush_pending_trades();
            bool is_snapshot = (type == UsdmStreamType::DEPTH_PARTIAL);
            if (is_snapshot) {
                // Flush pending deltas before snapshot to prevent stale
                // fragments from being published after the snapshot
                for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
                    if (pending_depth_[ch].has_pending) publish_pending_depth(ch, true);
            }
            info.mkt_event_type = static_cast<uint8_t>(
                is_snapshot ? websocket::msg::EventType::BOOK_SNAPSHOT : websocket::msg::EventType::BOOK_DELTA);

            if (is_snapshot) {
                int64_t max_seq = 0;
                for (int c = 0; c < DEPTH_CHANNELS; c++)
                    max_seq = std::max(max_seq, last_book_seq_[c]);
                if (e.sequence <= max_seq) {
                    info.set_discard_early(true);
                    state.msg_type = e.msg_type;
                    state.sequence = e.sequence;
                    state.event_time_us = e.event_time_ms * 1000;
                    state.deduped = true;
                    state.phase = JsonParseState::DONE;
                    return;
                }
                for (int c = 0; c < DEPTH_CHANNELS; c++) {
                    last_book_seq_[c] = e.sequence;
                    interleave_[c].reset(e.sequence);
                    interleave_[c].finished = true;
                }
            } else {
                uint8_t ch = depth_channel_index(type);
                if (e.sequence < last_book_seq_[ch]) {
                    info.set_discard_early(true);
                    state.msg_type = e.msg_type;
                    state.sequence = e.sequence;
                    state.event_time_us = e.event_time_ms * 1000;
                    state.deduped = true;
                    state.phase = JsonParseState::DONE;
                    return;
                }
                if (e.sequence == last_book_seq_[ch]) {
                    auto& il = interleave_[ch];
                    if (il.seq == e.sequence && il.finished) {
                        info.set_discard_early(true);
                        state.msg_type = e.msg_type;
                        state.sequence = e.sequence;
                        state.event_time_us = e.event_time_ms * 1000;
                        state.deduped = true;
                        state.phase = JsonParseState::DONE;
                        return;
                    }
                } else {
                    last_book_seq_[ch] = e.sequence;
                    interleave_[ch].reset(e.sequence);
                }
            }

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

        case UsdmStreamType::FORCE_ORDER: {
            if (has_pending_trades_) flush_pending_trades();
            for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
                if (pending_depth_[ch].has_pending) publish_pending_depth(ch, true);
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::LIQUIDATION);
            info.mkt_event_count = 1;

            // Dedup by E timestamp
            if (e.sequence <= last_liq_time_) {
                info.set_discard_early(true);
                state.msg_type = e.msg_type;
                state.sequence = e.sequence;
                state.event_time_us = e.event_time_ms * 1000;
                state.deduped = true;
                state.phase = JsonParseState::DONE;
                return;
            }
            last_liq_time_ = e.sequence;

            // Single-pass parse via positional parser
            auto fo = parse_force_order_remaining(e.resume_pos, e.data_end);
            if (!fo.valid) return;

            record_win(ci);
            current_info_ = &info;
            publish_event([&](websocket::msg::MktEvent& ev) {
                ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::LIQUIDATION));
                ev.src_seq = e.sequence;
                ev.event_ts_ns = e.event_time_ms * 1000000LL;
                ev.count = 1;
                auto& liq = ev.payload.liquidations.entries[0];
                liq.price = fo.price * websocket::market::BinanceUSDM::price_scale;
                liq.avg_price = fo.avg_price * websocket::market::BinanceUSDM::price_scale;
                liq.orig_qty = fo.orig_qty * websocket::market::BinanceUSDM::qty_scale;
                liq.filled_qty = fo.filled_qty * websocket::market::BinanceUSDM::qty_scale;
                liq.trade_time_ns = fo.trade_time_ms * 1000000LL;
                liq.flags = fo.is_sell ? websocket::msg::LiqFlags::SIDE_SELL : 0;
                std::memset(liq._pad, 0, sizeof(liq._pad));
            });
            current_info_ = nullptr;
            state.msg_type = e.msg_type;
            state.sequence = e.sequence;
            state.event_time_us = e.event_time_ms * 1000;
            state.phase = JsonParseState::DONE;
            break;
        }

        case UsdmStreamType::MARK_PRICE: {
            if (has_pending_trades_) flush_pending_trades();
            for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
                if (pending_depth_[ch].has_pending) publish_pending_depth(ch, true);
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::MARK_PRICE);
            info.mkt_event_count = 1;

            // Dedup by E timestamp
            if (e.sequence <= last_mark_price_time_) {
                info.set_discard_early(true);
                state.msg_type = e.msg_type;
                state.sequence = e.sequence;
                state.event_time_us = e.event_time_ms * 1000;
                state.deduped = true;
                state.phase = JsonParseState::DONE;
                return;
            }
            last_mark_price_time_ = e.sequence;

            // Single-pass parse via positional parser
            auto mp = parse_mark_price_remaining(e.resume_pos, e.data_end);
            if (!mp.valid) return;

            record_win(ci);
            current_info_ = &info;
            publish_event([&](websocket::msg::MktEvent& ev) {
                ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::MARK_PRICE));
                ev.src_seq = e.sequence;
                ev.event_ts_ns = e.event_time_ms * 1000000LL;
                ev.count = 1;
                auto& entry = ev.payload.mark_prices.entries[0];
                entry.mark_price = mp.mark_price * websocket::market::BinanceUSDM::BTCUSDT::mp_price_scale;
                entry.index_price = mp.index_price * websocket::market::BinanceUSDM::BTCUSDT::mp_price_scale;
                entry.settle_price = mp.settle_price * websocket::market::BinanceUSDM::BTCUSDT::mp_price_scale;
                entry.funding_rate = mp.funding_rate * websocket::market::BinanceUSDM::BTCUSDT::mp_rate_scale;
                entry.next_funding_ns = mp.next_funding_time_ms * 1000000LL;
                std::memset(entry._pad, 0, sizeof(entry._pad));
            });
            current_info_ = nullptr;
            state.msg_type = e.msg_type;
            state.sequence = e.sequence;
            state.event_time_us = e.event_time_ms * 1000;
            state.phase = JsonParseState::DONE;
            break;
        }

        default:
            break;
        }
    }

    // ── Batch boundary / lifecycle (identical to BinanceUSDMJsonParser) ──────

    void on_batch_end(uint8_t) {
        for (int ch = 0; ch < DEPTH_CHANNELS; ch++)
            publish_pending_depth(ch, true);
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

    // ── Event publishing (identical to BinanceUSDMJsonParser) ────────────────

    void publish_pending_depth(uint8_t ch, bool is_final) {
        auto& pd = pending_depth_[ch];
        if (!pd.has_pending || pd.count == 0) return;
        record_win(pd.ci);
        current_info_ = &pd.info;
        uint8_t count = pd.count;
        uint8_t fc = pd.flush_count;
        publish_event([&](websocket::msg::MktEvent& e) {
            e.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA));
            uint16_t f = 0;
            if (fc > 0)    f |= websocket::msg::EventFlags::CONTINUATION;
            if (is_final)  f |= websocket::msg::EventFlags::LAST_IN_BATCH;
            e.flags |= f;
            e.set_depth_channel(ch);
            e.src_seq = pd.seq;
            e.event_ts_ns = pd.event_ts_ns;
            e.count = count;
            e.count2 = fc;  // flush_index
            std::memcpy(e.payload.deltas.entries, pd.entries,
                        count * sizeof(websocket::msg::DeltaEntry));
        });
        current_info_ = nullptr;
        pd.flush_count++;
        auto& il = interleave_[ch];
        if (il.seq == pd.seq) il.flush_count = pd.flush_count;
        pd.count = 0;
        if (is_final) {
            pd.has_pending = false;
            pd.flush_count = 0;
        }
    }

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
            ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY));
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
        e.set_venue_id(static_cast<uint8_t>(websocket::msg::VenueId::BINANCE_USDM));
        e.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS));
        struct timespec ts_real;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        e.nic_ts_ns = static_cast<int64_t>(ts_real.tv_sec) * 1000000000LL + ts_real.tv_nsec;
        e.recv_local_latency_ns = 0;
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
        e.set_venue_id(static_cast<uint8_t>(websocket::msg::VenueId::BINANCE_USDM));
        e.set_instrument_id(instrument_id);
        struct timespec ts_real, ts_mono;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        int64_t real_ns = static_cast<int64_t>(ts_real.tv_sec) * 1000000000LL + ts_real.tv_nsec;
        int64_t mono_ns = static_cast<int64_t>(ts_mono.tv_sec) * 1000000000LL + ts_mono.tv_nsec;
        if (current_info_) {
            int64_t mono_arrival = 0;
            if (current_info_->latest_bpf_entry_ns > 0)
                mono_arrival = static_cast<int64_t>(current_info_->latest_bpf_entry_ns);
            else if (current_info_->first_byte_ts > 0)
                mono_arrival = static_cast<int64_t>(current_info_->first_byte_ts);
            if (mono_arrival > 0)
                e.nic_ts_ns = real_ns - (mono_ns - mono_arrival);
        }
        int64_t local_lat = real_ns - e.nic_ts_ns;
        e.recv_local_latency_ns = (e.nic_ts_ns > 0 && local_lat > 0)
            ? static_cast<uint16_t>(local_lat > 65535 ? 65535 : local_lat) : 0;
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
