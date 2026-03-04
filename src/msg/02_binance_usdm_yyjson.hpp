// msg/02_binance_usdm_yyjson.hpp
// Binance USD-M Futures JSON market data: yyjson DOM parser + handler
//
// websocket::json::yy — yyjson-backed parsers for Binance futures streams.
//   Reuses types and classify_stream() from 01_binance_usdm_json.hpp.
//   Uses yyjson 0.12.0 DOM API for field extraction.
//
//   BinanceUSDMYyjsonParser — Handler struct for pipeline integration
#pragma once

#include "msg/01_binance_usdm_json.hpp"  // reuse types + classify_stream()
#include "msg/market_conf.hpp"

extern "C" {
#include "vendor/yyjson.h"
}

// ============================================================================
// Part 1: yyjson Parse Functions
// ============================================================================

namespace websocket::json::yy {

// Decimal C-string → int64 mantissa (e.g., "7403.89" → 740389)
inline int64_t decimal_cstr_to_int64(const char* s) {
    if (!s) return 0;
    bool neg = false;
    if (*s == '-') { neg = true; ++s; }
    int64_t v = 0;
    while (*s) {
        if (*s == '.') { ++s; continue; }
        if (*s >= '0' && *s <= '9')
            v = v * 10 + (*s - '0');
        ++s;
    }
    return neg ? -v : v;
}

// RAII wrapper for yyjson_doc* lifetime
struct YyDoc {
    yyjson_doc* doc = nullptr;
    YyDoc() = default;
    explicit YyDoc(yyjson_doc* d) : doc(d) {}
    ~YyDoc() { if (doc) yyjson_doc_free(doc); }
    YyDoc(const YyDoc&) = delete;
    YyDoc& operator=(const YyDoc&) = delete;
    YyDoc(YyDoc&& o) noexcept : doc(o.doc) { o.doc = nullptr; }
    YyDoc& operator=(YyDoc&& o) noexcept {
        if (doc) yyjson_doc_free(doc);
        doc = o.doc; o.doc = nullptr;
        return *this;
    }
    explicit operator bool() const { return doc != nullptr; }
};

// Combined stream parse result (owns document)
struct YyCombinedResult {
    UsdmStreamType type = UsdmStreamType::UNKNOWN;
    YyDoc doc;
    yyjson_val* data = nullptr;
};

inline YyCombinedResult yy_parse_combined(const uint8_t* json, uint32_t len) {
    YyCombinedResult res;
    res.doc = YyDoc(yyjson_read(reinterpret_cast<const char*>(json), len, 0));
    if (!res.doc) return res;
    yyjson_val* root = yyjson_doc_get_root(res.doc.doc);
    if (!root) return res;
    yyjson_val* stream = yyjson_obj_get(root, "stream");
    if (!stream) return res;
    const char* sname = yyjson_get_str(stream);
    size_t slen = yyjson_get_len(stream);
    res.type = classify_stream(reinterpret_cast<const uint8_t*>(sname),
                               static_cast<uint32_t>(slen));
    res.data = yyjson_obj_get(root, "data");
    return res;
}

inline AggTradeFields yy_parse_agg_trade(yyjson_val* data) {
    AggTradeFields f{};
    f.valid = false;
    if (!data) return f;
    f.event_time_ms  = yyjson_get_sint(yyjson_obj_get(data, "E"));
    f.agg_trade_id   = yyjson_get_sint(yyjson_obj_get(data, "a"));
    f.price_mantissa = decimal_cstr_to_int64(yyjson_get_str(yyjson_obj_get(data, "p")));
    f.qty_mantissa   = decimal_cstr_to_int64(yyjson_get_str(yyjson_obj_get(data, "q")));
    f.trade_time_ms  = yyjson_get_sint(yyjson_obj_get(data, "T"));
    f.buyer_is_maker = yyjson_get_bool(yyjson_obj_get(data, "m"));
    f.valid = true;
    return f;
}

// Depth result with yyjson_val* array pointers (instead of uint8_t*)
struct YyDepthFields {
    int64_t event_time_ms;
    int64_t txn_time_ms;
    int64_t last_update_id;
    yyjson_val* bids_val;
    yyjson_val* asks_val;
    bool valid;
};

inline YyDepthFields yy_parse_depth(yyjson_val* data) {
    YyDepthFields f{};
    f.valid = false;
    f.bids_val = nullptr;
    f.asks_val = nullptr;
    if (!data) return f;
    f.event_time_ms  = yyjson_get_sint(yyjson_obj_get(data, "E"));
    f.txn_time_ms    = yyjson_get_sint(yyjson_obj_get(data, "T"));
    f.last_update_id = yyjson_get_sint(yyjson_obj_get(data, "u"));
    f.bids_val       = yyjson_obj_get(data, "b");
    f.asks_val       = yyjson_obj_get(data, "a");
    f.valid = true;
    return f;
}

inline uint8_t yy_parse_book_levels(yyjson_val* arr,
                                     websocket::msg::BookLevel* out, uint8_t max) {
    if (!arr) return 0;
    uint8_t count = 0;
    size_t idx, max_arr;
    yyjson_val* val;
    yyjson_arr_foreach(arr, idx, max_arr, val) {
        if (count >= max) break;
        out[count].price = decimal_cstr_to_int64(yyjson_get_str(yyjson_arr_get(val, 0)));
        out[count].qty   = decimal_cstr_to_int64(yyjson_get_str(yyjson_arr_get(val, 1)));
        count++;
    }
    return count;
}

inline uint8_t yy_parse_delta_levels(yyjson_val* arr,
                                      websocket::msg::DeltaEntry* out, uint8_t max,
                                      bool is_ask) {
    if (!arr) return 0;
    uint8_t count = 0;
    size_t idx, max_arr;
    yyjson_val* val;
    yyjson_arr_foreach(arr, idx, max_arr, val) {
        if (count >= max) break;
        out[count].price = decimal_cstr_to_int64(yyjson_get_str(yyjson_arr_get(val, 0)));
        out[count].qty   = decimal_cstr_to_int64(yyjson_get_str(yyjson_arr_get(val, 1)));
        out[count].action = (out[count].qty == 0)
            ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
            : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
        out[count].flags = is_ask ? websocket::msg::DeltaFlags::SIDE_ASK : 0;
        std::memset(out[count]._pad, 0, sizeof(out[count]._pad));
        count++;
    }
    return count;
}

}  // namespace websocket::json::yy

// ============================================================================
// Part 2: BinanceUSDMYyjsonParser (requires pipeline_data.hpp)
// ============================================================================

#ifdef PIPELINE_DATA_HPP_INCLUDED

namespace websocket::json {

struct BinanceUSDMYyjsonParser {
    static constexpr bool enabled = true;
    JsonParseState sbe_state_[PIPELINE_MAX_CONN]{};

    // Pipeline wiring (same members as BinanceUSDMJsonParser)
    websocket::pipeline::IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    websocket::pipeline::ConnStateShm* conn_state = nullptr;
    bool merge_enabled = true;
    int64_t last_book_seq_ = 0;
    int64_t last_trade_id_ = 0;
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

    // ── Main entry point (yyjson-based) ─────────────────────────────────────

    void on_ws_data(JsonParseState&, uint8_t ci,
                    const uint8_t* payload, uint32_t len,
                    websocket::pipeline::WSFrameInfo& info) {
        pending_ring_seq_slot_ = nullptr;

        auto res = yy::yy_parse_combined(payload, len);
        if (res.type == UsdmStreamType::UNKNOWN || !res.data)
            return;

        switch (res.type) {
        case UsdmStreamType::AGG_TRADE: {
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);

            auto tf = yy::yy_parse_agg_trade(res.data);
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
                te.flags = tf.buyer_is_maker ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                std::memset(te._pad, 0, sizeof(te._pad));

                info.set_merged(true);
                pending_ring_seq_slot_ = &pending_trades_ring_seq_;
            } else {
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
            if (has_pending_trades_) flush_pending_trades();

            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);

            auto df = yy::yy_parse_depth(res.data);
            if (!df.valid) return;

            info.exchange_event_time_us = df.event_time_ms * 1000;
            info.mkt_event_seq = df.last_update_id;

            if (df.last_update_id <= last_book_seq_) {
                info.set_discard_early(true);
                return;
            }
            last_book_seq_ = df.last_update_id;

            static constexpr uint8_t SNAPSHOT_HALF = websocket::msg::MAX_BOOK_LEVELS / 2;
            websocket::msg::BookLevel bid_levels[SNAPSHOT_HALF];
            websocket::msg::BookLevel ask_levels[SNAPSHOT_HALF];
            uint8_t bid_count = yy::yy_parse_book_levels(df.bids_val, bid_levels, SNAPSHOT_HALF);
            uint8_t ask_count = yy::yy_parse_book_levels(df.asks_val, ask_levels, SNAPSHOT_HALF);
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
            if (has_pending_trades_) flush_pending_trades();

            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);

            auto df = yy::yy_parse_depth(res.data);
            if (!df.valid) return;

            info.exchange_event_time_us = df.event_time_ms * 1000;
            info.mkt_event_seq = df.last_update_id;

            if (df.last_update_id <= last_book_seq_) {
                info.set_discard_early(true);
                return;
            }
            last_book_seq_ = df.last_update_id;

            websocket::msg::DeltaEntry bid_deltas[websocket::msg::MAX_DELTAS];
            websocket::msg::DeltaEntry ask_deltas[websocket::msg::MAX_DELTAS];
            uint8_t bid_count = yy::yy_parse_delta_levels(df.bids_val, bid_deltas,
                                                           websocket::msg::MAX_DELTAS, false);
            uint8_t ask_count = yy::yy_parse_delta_levels(df.asks_val, ask_deltas,
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

    // ── Batch boundary / lifecycle (identical to BinanceUSDMJsonParser) ──────

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

    // ── Event publishing (identical to BinanceUSDMJsonParser) ────────────────

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
