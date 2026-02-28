// msg/00_binance_spot_sbe.hpp
// Binance Spot SBE market data: zero-copy wire decoders + policy-based stream decoder
//
// websocket::sbe — Zero-copy SBE decoders for Binance binary market data.
//   All little-endian (x86 native). Reads directly from WS payload via const uint8_t*.
//   Supported messages:
//     templateId 10000 = TradesStreamEvent
//     templateId 10001 = BestBidAskStreamEvent
//     templateId 10002 = DepthSnapshotStreamEvent
//     templateId 10003 = DepthDiffStreamEvent
//
//   BinanceSpotSBEDecoder — StreamDecoderPolicy implementation for two-step decode:
//     1. decode_essential() — extract msg_type + sequence from SBE header (fast)
//     2. Full decode via *View structs — only if sequence is fresh
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <string_view>

#include "stream_decoder.hpp"

// ============================================================================
// Part 1: Zero-copy SBE wire decoders
// ============================================================================

namespace websocket::sbe {

// ── Primitive read helpers (little-endian native on x86) ──────────────────

inline int64_t  read_i64(const uint8_t* p) { int64_t  v; std::memcpy(&v, p, 8); return v; }
inline uint64_t read_u64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }
inline uint32_t read_u32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
inline uint16_t read_u16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
inline int8_t   read_i8 (const uint8_t* p) { return static_cast<int8_t>(*p); }
inline uint8_t  read_u8 (const uint8_t* p) { return *p; }

// ── SBE Header (8 bytes at offset 0 of every binary frame) ───────────────

static constexpr size_t HEADER_SIZE = 8;

struct SBEHeader {
    uint16_t block_length;   // Root block size in bytes
    uint16_t template_id;    // Message type discriminator
    uint16_t schema_id;      // Schema identifier (expect 1)
    uint16_t version;        // Schema version (expect 0)
};

inline bool decode_header(const uint8_t* buf, size_t len, SBEHeader& out) {
    if (len < HEADER_SIZE) return false;
    out.block_length = read_u16(buf + 0);
    out.template_id  = read_u16(buf + 2);
    out.schema_id    = read_u16(buf + 4);
    out.version      = read_u16(buf + 6);
    return true;
}

// ── Template IDs ─────────────────────────────────────────────────────────

static constexpr uint16_t TRADES_STREAM          = 10000;
static constexpr uint16_t BEST_BID_ASK_STREAM    = 10001;
static constexpr uint16_t DEPTH_SNAPSHOT_STREAM  = 10002;
static constexpr uint16_t DEPTH_DIFF_STREAM      = 10003;

// ── Price reconstruction ─────────────────────────────────────────────────
// actual_price = mantissa × 10^exponent
// For HFT: store mantissa + exponent separately, convert only for display

inline double to_double(int64_t mantissa, int8_t exponent) {
    static constexpr double pow10[] = {
        1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1,
        1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8
    };
    int idx = exponent + 8;
    if (idx >= 0 && idx <= 16) return mantissa * pow10[idx];
    return mantissa * std::pow(10.0, exponent);  // fallback
}

// ── groupSizeEncoding (6 bytes — TradesStreamEvent) ──────────────────────

struct GroupSize {
    uint16_t block_length;
    uint32_t num_in_group;
};

inline bool read_group_size(const uint8_t* p, size_t avail, GroupSize& out) {
    if (avail < 6) return false;
    out.block_length = read_u16(p + 0);
    out.num_in_group = read_u32(p + 2);
    return true;
}

// ── groupSize16Encoding (4 bytes — Depth messages) ───────────────────────

struct GroupSize16 {
    uint16_t block_length;
    uint16_t num_in_group;
};

inline bool read_group_size16(const uint8_t* p, size_t avail, GroupSize16& out) {
    if (avail < 4) return false;
    out.block_length = read_u16(p + 0);
    out.num_in_group = read_u16(p + 2);
    return true;
}

// ── varString8 ───────────────────────────────────────────────────────────

inline std::string_view read_var_string8(const uint8_t* p, size_t avail) {
    if (avail < 1) return {};
    uint8_t len = read_u8(p);
    if (avail < 1u + len) return {};
    return { reinterpret_cast<const char*>(p + 1), len };
}

// ── TradeEntryView ───────────────────────────────────────────────────────

struct TradeEntryView {
    const uint8_t* p_;
    int64_t  id()              const { return read_i64(p_ + 0); }
    int64_t  price_mantissa()  const { return read_i64(p_ + 8); }
    int64_t  qty_mantissa()    const { return read_i64(p_ + 16); }
    bool     is_buyer_maker()  const { return read_u8(p_ + 24) == 1; }
    static constexpr bool is_best_match() { return true; }  // presence="constant" valueRef="True"
    static constexpr size_t WIRE_SIZE = 25;  // 8+8+8+1, isBestMatch not on wire
};

// ── TradesView (templateId=10000) ────────────────────────────────────────

struct TradesView {
    const uint8_t* buf_;          // Points to start of root block (after messageHeader)
    size_t len_;
    uint16_t group_block_len_;
    uint32_t trade_count_;
    const uint8_t* trades_;       // First trade entry
    const uint8_t* symbol_ptr_;   // Points to varString8

    int64_t event_time_us()    const { return read_i64(buf_ + 0); }
    int64_t transact_time_us() const { return read_i64(buf_ + 8); }
    int8_t  price_exponent()   const { return read_i8(buf_ + 16); }
    int8_t  qty_exponent()     const { return read_i8(buf_ + 17); }
    uint32_t count()           const { return trade_count_; }

    TradeEntryView trade(uint32_t i) const {
        return { trades_ + i * group_block_len_ };
    }

    std::string_view symbol() const {
        return read_var_string8(symbol_ptr_, len_ - static_cast<size_t>(symbol_ptr_ - buf_));
    }

    static bool decode(const uint8_t* body, size_t body_len,
                       uint16_t root_block_len, TradesView& out) {
        if (body_len < root_block_len) return false;
        out.buf_ = body;
        out.len_ = body_len;

        const uint8_t* cursor = body + root_block_len;
        size_t remaining = body_len - root_block_len;

        // groupSizeEncoding (6 bytes)
        GroupSize gs;
        if (!read_group_size(cursor, remaining, gs)) return false;
        cursor += 6;
        remaining -= 6;

        out.group_block_len_ = gs.block_length;
        out.trade_count_ = gs.num_in_group;
        out.trades_ = cursor;

        size_t trades_size = static_cast<size_t>(gs.num_in_group) * gs.block_length;
        if (remaining < trades_size) return false;
        cursor += trades_size;
        remaining -= trades_size;

        out.symbol_ptr_ = cursor;
        return true;
    }
};

// ── PriceLevelView ───────────────────────────────────────────────────────

struct PriceLevelView {
    const uint8_t* p_;
    int64_t price_mantissa() const { return read_i64(p_ + 0); }
    int64_t qty_mantissa()   const { return read_i64(p_ + 8); }
};

// ── BestBidAskView (templateId=10001) ────────────────────────────────────

struct BestBidAskView {
    const uint8_t* buf_;
    size_t len_;
    uint16_t root_block_len_;

    int64_t event_time_us()      const { return read_i64(buf_ + 0); }
    int64_t book_update_id()     const { return read_i64(buf_ + 8); }
    int8_t  price_exponent()     const { return read_i8(buf_ + 16); }
    int8_t  qty_exponent()       const { return read_i8(buf_ + 17); }
    int64_t bid_price_mantissa() const { return read_i64(buf_ + 18); }
    int64_t bid_qty_mantissa()   const { return read_i64(buf_ + 26); }
    int64_t ask_price_mantissa() const { return read_i64(buf_ + 34); }
    int64_t ask_qty_mantissa()   const { return read_i64(buf_ + 42); }

    std::string_view symbol() const {
        const uint8_t* sym_ptr = buf_ + root_block_len_;
        size_t remaining = (len_ > root_block_len_) ? len_ - root_block_len_ : 0;
        return read_var_string8(sym_ptr, remaining);
    }

    static bool decode(const uint8_t* body, size_t body_len,
                       uint16_t root_block_len, BestBidAskView& out) {
        if (body_len < root_block_len) return false;
        out.buf_ = body;
        out.len_ = body_len;
        out.root_block_len_ = root_block_len;
        return true;
    }
};

// ── DepthGroupView (shared by DepthSnapshot and DepthDiff) ───────────────

struct DepthGroupView {
    uint16_t block_len;
    uint16_t count;
    const uint8_t* entries;

    PriceLevelView level(uint16_t i) const {
        return { entries + i * block_len };
    }
};

// ── DepthSnapshotView (templateId=10002) ─────────────────────────────────

struct DepthSnapshotView {
    const uint8_t* buf_;
    size_t len_;
    DepthGroupView bids_;
    DepthGroupView asks_;
    const uint8_t* symbol_ptr_;

    int64_t event_time_us()   const { return read_i64(buf_ + 0); }
    int64_t book_update_id()  const { return read_i64(buf_ + 8); }
    int8_t  price_exponent()  const { return read_i8(buf_ + 16); }
    int8_t  qty_exponent()    const { return read_i8(buf_ + 17); }

    const DepthGroupView& bids() const { return bids_; }
    const DepthGroupView& asks() const { return asks_; }

    std::string_view symbol() const {
        size_t remaining = len_ - static_cast<size_t>(symbol_ptr_ - buf_);
        return read_var_string8(symbol_ptr_, remaining);
    }

    static bool decode(const uint8_t* body, size_t body_len,
                       uint16_t root_block_len, DepthSnapshotView& out) {
        if (body_len < root_block_len) return false;
        out.buf_ = body;
        out.len_ = body_len;

        const uint8_t* cursor = body + root_block_len;
        size_t remaining = body_len - root_block_len;

        // Bids group (groupSize16Encoding = 4 bytes)
        GroupSize16 bids_gs;
        if (!read_group_size16(cursor, remaining, bids_gs)) return false;
        cursor += 4;
        remaining -= 4;

        out.bids_.block_len = bids_gs.block_length;
        out.bids_.count = bids_gs.num_in_group;
        out.bids_.entries = cursor;

        size_t bids_size = static_cast<size_t>(bids_gs.num_in_group) * bids_gs.block_length;
        if (remaining < bids_size) return false;
        cursor += bids_size;
        remaining -= bids_size;

        // Asks group (groupSize16Encoding = 4 bytes)
        GroupSize16 asks_gs;
        if (!read_group_size16(cursor, remaining, asks_gs)) return false;
        cursor += 4;
        remaining -= 4;

        out.asks_.block_len = asks_gs.block_length;
        out.asks_.count = asks_gs.num_in_group;
        out.asks_.entries = cursor;

        size_t asks_size = static_cast<size_t>(asks_gs.num_in_group) * asks_gs.block_length;
        if (remaining < asks_size) return false;
        cursor += asks_size;
        remaining -= asks_size;

        out.symbol_ptr_ = cursor;
        return true;
    }
};

// ── DepthDiffView (templateId=10003) ─────────────────────────────────────

struct DepthDiffView {
    const uint8_t* buf_;
    size_t len_;
    DepthGroupView bids_;
    DepthGroupView asks_;
    const uint8_t* symbol_ptr_;

    int64_t event_time_us()         const { return read_i64(buf_ + 0); }
    int64_t first_book_update_id()  const { return read_i64(buf_ + 8); }
    int64_t last_book_update_id()   const { return read_i64(buf_ + 16); }
    int8_t  price_exponent()        const { return read_i8(buf_ + 24); }
    int8_t  qty_exponent()          const { return read_i8(buf_ + 25); }

    const DepthGroupView& bids() const { return bids_; }
    const DepthGroupView& asks() const { return asks_; }

    std::string_view symbol() const {
        size_t remaining = len_ - static_cast<size_t>(symbol_ptr_ - buf_);
        return read_var_string8(symbol_ptr_, remaining);
    }

    static bool decode(const uint8_t* body, size_t body_len,
                       uint16_t root_block_len, DepthDiffView& out) {
        if (body_len < root_block_len) return false;
        out.buf_ = body;
        out.len_ = body_len;

        const uint8_t* cursor = body + root_block_len;
        size_t remaining = body_len - root_block_len;

        // Bids group (groupSize16Encoding = 4 bytes)
        GroupSize16 bids_gs;
        if (!read_group_size16(cursor, remaining, bids_gs)) return false;
        cursor += 4;
        remaining -= 4;

        out.bids_.block_len = bids_gs.block_length;
        out.bids_.count = bids_gs.num_in_group;
        out.bids_.entries = cursor;

        size_t bids_size = static_cast<size_t>(bids_gs.num_in_group) * bids_gs.block_length;
        if (remaining < bids_size) return false;
        cursor += bids_size;
        remaining -= bids_size;

        // Asks group (groupSize16Encoding = 4 bytes)
        GroupSize16 asks_gs;
        if (!read_group_size16(cursor, remaining, asks_gs)) return false;
        cursor += 4;
        remaining -= 4;

        out.asks_.block_len = asks_gs.block_length;
        out.asks_.count = asks_gs.num_in_group;
        out.asks_.entries = cursor;

        size_t asks_size = static_cast<size_t>(asks_gs.num_in_group) * asks_gs.block_length;
        if (remaining < asks_size) return false;
        cursor += asks_size;
        remaining -= asks_size;

        out.symbol_ptr_ = cursor;
        return true;
    }
};

// ── BinanceSpotSBEDecoder — StreamDecoderPolicy for two-step decode ──────

struct BinanceSpotSBEDecoder {
    struct Essential {
        uint16_t       msg_type = 0;        // SBE template_id
        int64_t        sequence = 0;        // book_update_id or last trade_id
        const uint8_t* body = nullptr;      // payload after 8-byte SBE header
        size_t         body_len = 0;
        uint16_t       block_length = 0;    // SBE root block length
        uint16_t       count = 0;           // Element count (trades, bid+ask levels)
        bool           valid = false;
    };

    static Essential decode_essential(const uint8_t* payload, uint32_t len) {
        Essential e;
        SBEHeader hdr;
        if (len < HEADER_SIZE || !decode_header(payload, len, hdr)) return e;

        e.msg_type = hdr.template_id;
        e.body = payload + HEADER_SIZE;
        e.body_len = len - HEADER_SIZE;
        e.block_length = hdr.block_length;
        e.valid = true;

        const uint8_t* after_root = e.body + hdr.block_length;
        size_t remaining = (e.body_len > hdr.block_length) ? e.body_len - hdr.block_length : 0;

        switch (hdr.template_id) {
        case TRADES_STREAM:
            // groupSizeEncoding (6 bytes): u16 block_length, u32 num_in_group
            if (remaining >= 6) {
                uint16_t entry_block = read_u16(after_root);
                uint32_t num_trades = read_u32(after_root + 2);
                e.count = static_cast<uint16_t>(std::min(num_trades, (uint32_t)65535));
                // Last entry's trade_id as sequence for dedup
                if (num_trades > 0) {
                    size_t last_entry_offset = 6 + static_cast<size_t>(num_trades - 1) * entry_block;
                    if (remaining >= last_entry_offset + 8)
                        e.sequence = read_i64(after_root + last_entry_offset);
                }
            }
            break;
        case BEST_BID_ASK_STREAM:
            // book_update_id at body+8
            if (e.body_len >= 16) e.sequence = read_i64(e.body + 8);
            e.count = 2;  // always 1 bid + 1 ask
            break;
        case DEPTH_SNAPSHOT_STREAM:
            // book_update_id at body+8
            if (e.body_len >= 16) e.sequence = read_i64(e.body + 8);
            // Two groupSize16Encoding: bids then asks (need to skip bid entries)
            if (remaining >= 4) {
                uint16_t bid_block = read_u16(after_root);
                uint16_t bid_count = read_u16(after_root + 2);
                size_t bids_end = 4 + static_cast<size_t>(bid_count) * bid_block;
                if (remaining >= bids_end + 4) {
                    uint16_t ask_count = read_u16(after_root + bids_end + 2);
                    e.count = bid_count + ask_count;
                } else {
                    e.count = bid_count;
                }
            }
            break;
        case DEPTH_DIFF_STREAM:
            // last_book_update_id at body+16
            if (e.body_len >= 24) e.sequence = read_i64(e.body + 16);
            // Two groupSize16Encoding: bids then asks
            if (remaining >= 4) {
                uint16_t bid_block = read_u16(after_root);
                uint16_t bid_count = read_u16(after_root + 2);
                size_t bids_end = 4 + static_cast<size_t>(bid_count) * bid_block;
                if (remaining >= bids_end + 4) {
                    uint16_t ask_count = read_u16(after_root + bids_end + 2);
                    e.count = bid_count + ask_count;
                } else {
                    e.count = bid_count;
                }
            }
            break;
        }
        return e;
    }
};

static_assert(websocket::msg::StreamDecoderPolicy<BinanceSpotSBEDecoder>);

}  // namespace websocket::sbe

// ============================================================================
// Part 3: BinanceSBEHandler — MktEventHandler for inline SBE decode + MktEvent publish
// Requires pipeline_data.hpp to be included before this header.
// ============================================================================

#ifdef PIPELINE_DATA_HPP_INCLUDED

namespace websocket::sbe {

struct BinanceSBEHandler {
    static constexpr bool enabled = true;
    websocket::pipeline::IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    websocket::pipeline::ConnStateShm* conn_state = nullptr;
    bool merge_enabled = true;
    int64_t last_book_seq_ = 0;
    int64_t last_bbo_seq_ = 0;
    int64_t last_trade_id_ = 0;
    uint8_t active_ci_ = 0xFF;
    websocket::pipeline::WSFrameInfo* current_info_ = nullptr;

    // A/B failover state
    static constexpr uint32_t FAILOVER_LOSS_THRESHOLD = 10;
    static constexpr uint64_t FAILOVER_LOCK_MS = 5000;
    static constexpr uint64_t STALE_THRESHOLD_MS = 500;

    uint32_t conn_win_count_[2] = {};
    uint32_t conn_loss_streak_[2] = {};
    uint64_t conn_last_win_cycle_[2] = {};
    uint64_t conn_last_data_cycle_[2] = {};
    uint8_t  primary_ci_ = 0;
    bool     failover_locked_ = false;
    uint64_t failover_lock_until_cycle_ = 0;
    uint64_t failover_lock_cycles_ = 0;
    uint64_t stale_threshold_cycles_ = 0;

    // Ring producer for clearing M flag on published (winning) frames
    websocket::pipeline::IPCRingProducer<websocket::pipeline::WSFrameInfo>* ws_frame_info_prod_ = nullptr;  // set by WSCore::init()
    int64_t pending_bbo_ring_seq_ = -1;      // ring seq of last BBO frame that entered buffer
    int64_t pending_trades_ring_seq_ = -1;   // ring seq of last trade frame that entered buffer
    int64_t* pending_ring_seq_slot_ = nullptr; // WSCore writes published seq here after ring publish

    // Pending BBO accumulation buffer — merges consecutive BEST_BID_ASK_STREAM frames
    bool has_pending_bbo_ = false;
    uint8_t pending_bbo_ci_ = 0;
    uint8_t pending_bbo_count_ = 0;
    websocket::msg::BboEntry pending_bbo_entries_[websocket::msg::MAX_BBOS];
    int64_t pending_bbo_max_seq_ = 0;
    int64_t pending_bbo_event_ts_ns_ = 0;
    websocket::pipeline::WSFrameInfo pending_bbo_info_{};

    // Pending trade accumulation buffer — merges consecutive TRADES_STREAM frames
    bool has_pending_trades_ = false;
    uint8_t pending_trades_ci_ = 0;
    uint8_t pending_trade_count_ = 0;
    websocket::msg::TradeEntry pending_trade_entries_[websocket::msg::MAX_TRADES];
    int64_t pending_trades_event_ts_ns_ = 0;
    int64_t pending_trades_max_id_ = 0;
    websocket::pipeline::WSFrameInfo pending_trades_info_{};

    // Lightweight fragment parser: populate WSFrameInfo fields from SBE header
    // without producing MktEvents. Called for intermediate WS fragments only.
    void on_ws_fragment(const uint8_t* payload, uint32_t len, websocket::pipeline::WSFrameInfo& info) {
        auto e = BinanceSpotSBEDecoder::decode_essential(payload, len);
        if (!e.valid) return;
        switch (e.msg_type) {
        case TRADES_STREAM:       info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY); break;
        case BEST_BID_ASK_STREAM: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY); break;
        case DEPTH_SNAPSHOT_STREAM: info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT); break;
        case DEPTH_DIFF_STREAM:   info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA); break;
        default: return;
        }
        info.mkt_event_count = static_cast<uint16_t>(e.count);
        info.mkt_event_seq = e.sequence;
        if (len >= HEADER_SIZE + 8)
            info.exchange_event_time_us = read_i64(payload + HEADER_SIZE);
    }

    void on_ws_frame(uint8_t ci, uint8_t, const uint8_t* payload,
                     uint32_t len, websocket::pipeline::WSFrameInfo& info) {
        auto e = BinanceSpotSBEDecoder::decode_essential(payload, len);
        pending_ring_seq_slot_ = nullptr;  // reset per frame; WSCore fills after ring publish
        if (!e.valid) {
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS);
            return;
        }

        switch (e.msg_type) {
        case TRADES_STREAM:
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
            info.mkt_event_count = static_cast<uint16_t>(e.count);
            info.mkt_event_seq = e.sequence;
            info.exchange_event_time_us = read_i64(payload + HEADER_SIZE);
            break;
        case BEST_BID_ASK_STREAM:
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY);
            info.mkt_event_count = static_cast<uint16_t>(e.count);
            info.mkt_event_seq = e.sequence;
            info.exchange_event_time_us = read_i64(payload + HEADER_SIZE);
            break;
        case DEPTH_SNAPSHOT_STREAM:
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
            info.mkt_event_count = static_cast<uint16_t>(e.count);
            info.mkt_event_seq = e.sequence;
            info.exchange_event_time_us = read_i64(payload + HEADER_SIZE);
            break;
        case DEPTH_DIFF_STREAM:
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
            info.mkt_event_count = static_cast<uint16_t>(e.count);
            info.mkt_event_seq = e.sequence;
            info.exchange_event_time_us = read_i64(payload + HEADER_SIZE);
            break;
        default:
            info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS);
            break;
        }

        // Flush pending trades before any non-trade message
        if (has_pending_trades_ && e.msg_type != TRADES_STREAM) {
            flush_pending_trades();
        }

        // Flush pending BBO before any non-BBO message (symmetric with trade flush above)
        if (has_pending_bbo_ && e.msg_type != BEST_BID_ASK_STREAM) {
            flush_pending_bbo();
        }

        if (e.sequence > 0) {
            int64_t effective_trade_id = has_pending_trades_
                ? std::max(last_trade_id_, pending_trades_max_id_)
                : last_trade_id_;
            bool stale = (e.msg_type == TRADES_STREAM)
                ? (e.sequence <= effective_trade_id)
                : (e.sequence <= last_book_seq_);
            if (stale) {
                info.set_discard_early(true);
                return;
            }
        }

        current_info_ = &info;

        switch (e.msg_type) {
        case TRADES_STREAM: {
            TradesView tv;
            if (TradesView::decode(e.body, e.body_len, e.block_length, tv)) {
                if (tv.count() == 0) break;
                int64_t max_id = tv.trade(tv.count() - 1).id();
                int64_t eff_tid = has_pending_trades_
                    ? std::max(last_trade_id_, pending_trades_max_id_)
                    : last_trade_id_;
                if (max_id <= eff_tid) {
                    info.set_discard_early(true);
                    break;
                }
                info.mkt_event_count = static_cast<uint16_t>(tv.count());

                uint32_t total_trades = tv.count();
                if (merge_enabled) {
                    int64_t transact_ns = tv.transact_time_us() * 1000;
                    pending_trades_event_ts_ns_ = tv.event_time_us() * 1000;
                    pending_trades_max_id_ = max_id;
                    for (uint32_t i = 0; i < total_trades; i++) {
                        // Start new accumulation if needed (first trade or after flush)
                        if (!has_pending_trades_) {
                            has_pending_trades_ = true;
                            pending_trades_ci_ = ci;
                            pending_trade_count_ = 0;
                            pending_trades_info_ = info;
                        }
                        // Flush if buffer full
                        if (pending_trade_count_ >= websocket::msg::MAX_TRADES) {
                            flush_pending_trades(false);  // mid-frame: don't clear M, trades span multiple frames
                            has_pending_trades_ = true;
                            pending_trades_ci_ = ci;
                            pending_trade_count_ = 0;
                            pending_trades_info_ = info;
                        }
                        auto t = tv.trade(i);
                        auto& te = pending_trade_entries_[pending_trade_count_++];
                        te.price = t.price_mantissa();
                        te.qty = t.qty_mantissa();
                        te.trade_id = t.id();
                        te.trade_time_ns = transact_ns;
                        te.flags = t.is_buyer_maker() ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                    }
                    info.set_merged(true);
                    pending_ring_seq_slot_ = &pending_trades_ring_seq_;
                } else {
                    int64_t transact_ns = tv.transact_time_us() * 1000;
                    int64_t event_ts_ns = tv.event_time_us() * 1000;
                    last_trade_id_ = max_id;
                    record_win(ci);
                    uint32_t offset = 0;
                    while (offset < total_trades) {
                        uint8_t chunk = static_cast<uint8_t>(
                            std::min<uint32_t>(total_trades - offset, websocket::msg::MAX_TRADES));
                        publish_event([&](websocket::msg::MktEvent& ev) {
                            ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
                            ev.src_seq = max_id;
                            ev.event_ts_ns = event_ts_ns;
                            ev.count = chunk;
                            for (uint8_t j = 0; j < chunk; j++) {
                                auto t = tv.trade(offset + j);
                                auto& te = ev.payload.trades.entries[j];
                                te.price = t.price_mantissa();
                                te.qty = t.qty_mantissa();
                                te.trade_id = t.id();
                                te.trade_time_ns = transact_ns;
                                te.flags = t.is_buyer_maker() ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                            }
                        });
                        offset += chunk;
                    }
                }
            }
            break;
        }
        case BEST_BID_ASK_STREAM: {
            BestBidAskView bv;
            if (BestBidAskView::decode(e.body, e.body_len, e.block_length, bv)) {
                int64_t seq = bv.book_update_id();
                int64_t eff_book_seq = has_pending_bbo_
                    ? std::max(std::max(last_book_seq_, last_bbo_seq_), pending_bbo_max_seq_)
                    : std::max(last_book_seq_, last_bbo_seq_);
                if (seq <= eff_book_seq) {
                    info.set_discard_early(true);
                    break;
                }
                info.mkt_event_count = 1;
                if (merge_enabled) {
                    if (!has_pending_bbo_) {
                        has_pending_bbo_ = true;
                        pending_bbo_ci_ = ci;
                        pending_bbo_count_ = 0;
                        pending_bbo_info_ = info;
                    }
                    if (pending_bbo_count_ >= websocket::msg::MAX_BBOS) {
                        flush_pending_bbo();
                        has_pending_bbo_ = true;
                        pending_bbo_ci_ = ci;
                        pending_bbo_count_ = 0;
                        pending_bbo_info_ = info;
                    }
                    auto& be = pending_bbo_entries_[pending_bbo_count_++];
                    be.bid_price = bv.bid_price_mantissa();
                    be.bid_qty = bv.bid_qty_mantissa();
                    be.ask_price = bv.ask_price_mantissa();
                    be.ask_qty = bv.ask_qty_mantissa();
                    be.event_time_ns = bv.event_time_us() * 1000;
                    be.book_update_id = seq;
                    pending_bbo_max_seq_ = seq;
                    pending_bbo_event_ts_ns_ = bv.event_time_us() * 1000;
                    info.set_merged(true);
                    pending_ring_seq_slot_ = &pending_bbo_ring_seq_;
                } else {
                    publish_bbo_single(ci, bv);
                }
            }
            break;
        }
        case DEPTH_SNAPSHOT_STREAM: {
            DepthSnapshotView sv;
            if (DepthSnapshotView::decode(e.body, e.body_len, e.block_length, sv)) {
                info.mkt_event_count = static_cast<uint16_t>(sv.bids().count + sv.asks().count);
                publish_depth_snapshot(ci, sv);
            }
            break;
        }
        case DEPTH_DIFF_STREAM: {
            DepthDiffView dv;
            if (DepthDiffView::decode(e.body, e.body_len, e.block_length, dv)) {
                info.mkt_event_count = static_cast<uint16_t>(dv.bids().count + dv.asks().count);
                publish_depth_diff(ci, dv);
            }
            break;
        }
        }
        current_info_ = nullptr;
    }

    void flush_pending_bbo() {
        if (!has_pending_bbo_ || pending_bbo_count_ == 0) return;
        has_pending_bbo_ = false;
        if (ws_frame_info_prod_ && pending_bbo_ring_seq_ >= 0)
            (*ws_frame_info_prod_)[pending_bbo_ring_seq_].set_merged(false);
        pending_bbo_ring_seq_ = -1;
        last_bbo_seq_ = pending_bbo_max_seq_;
        record_win(pending_bbo_ci_);
        current_info_ = &pending_bbo_info_;
        publish_event([&](websocket::msg::MktEvent& ev) {
            ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY);
            ev.src_seq = pending_bbo_entries_[pending_bbo_count_ - 1].book_update_id;
            ev.event_ts_ns = pending_bbo_event_ts_ns_;
            ev.count = pending_bbo_count_;
            ev.count2 = 0;
            std::memcpy(ev.payload.bbo_array.entries, pending_bbo_entries_,
                        pending_bbo_count_ * sizeof(websocket::msg::BboEntry));
        });
        current_info_ = nullptr;
        pending_bbo_count_ = 0;
    }

    void flush_pending_trades(bool clear_merged = true) {
        if (!has_pending_trades_) return;
        has_pending_trades_ = false;
        // Clear M on the winning frame — only at batch boundaries, not mid-frame overflows
        if (clear_merged && ws_frame_info_prod_ && pending_trades_ring_seq_ >= 0) {
            (*ws_frame_info_prod_)[pending_trades_ring_seq_].set_merged(false);
        }
        if (clear_merged) pending_trades_ring_seq_ = -1;
        last_trade_id_ = pending_trades_max_id_;
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

    void on_batch_end(uint8_t) {
        flush_pending_bbo();
        flush_pending_trades();

        // Stale connection check: if primary hasn't won recently, switch
        if (conn_state && stale_threshold_cycles_ > 0) {
            uint64_t now = __rdtsc();
            uint8_t other = primary_ci_ ^ 1;
            bool primary_stale = conn_last_data_cycle_[primary_ci_] > 0
                && (now - conn_last_data_cycle_[primary_ci_]) > stale_threshold_cycles_;
            bool other_active = conn_last_data_cycle_[other] > 0
                && (now - conn_last_data_cycle_[other]) < stale_threshold_cycles_;
            if (primary_stale && other_active && !failover_locked_) {
                uint8_t old = primary_ci_;
                primary_ci_ = other;
                failover_locked_ = true;
                failover_lock_until_cycle_ = now + failover_lock_cycles_;
                on_failover(old, other, "stale");
            }
        }
    }

    void on_heartbeat(uint8_t ci, uint8_t type) {
        publish_status(websocket::msg::SystemStatusType::HEARTBEAT, ci, 0,
                       type == 0 ? "PING" : "PONG");
    }

    void on_disconnected(uint8_t ci) {
        publish_status(websocket::msg::SystemStatusType::DISCONNECTED, ci);
    }

    void on_reconnected(uint8_t ci) {
        publish_status(websocket::msg::SystemStatusType::RECONNECTED, ci);
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

    void publish_bbo_single(uint8_t ci, const BestBidAskView& bv) {
        int64_t seq = bv.book_update_id();
        if (seq <= std::max(last_book_seq_, last_bbo_seq_)) return;
        last_bbo_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& ev) {
            ev.event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY);
            ev.src_seq = seq;
            ev.event_ts_ns = bv.event_time_us() * 1000;
            ev.count = 1;
            ev.count2 = 0;
            auto& be = ev.payload.bbo_array.entries[0];
            be.bid_price = bv.bid_price_mantissa();
            be.bid_qty = bv.bid_qty_mantissa();
            be.ask_price = bv.ask_price_mantissa();
            be.ask_qty = bv.ask_qty_mantissa();
            be.event_time_ns = bv.event_time_us() * 1000;
            be.book_update_id = seq;
        });
    }

    void publish_depth_snapshot(uint8_t ci, const DepthSnapshotView& sv) {
        int64_t seq = sv.book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
            e.flags = websocket::msg::EventFlags::SNAPSHOT;
            e.src_seq = seq;
            e.event_ts_ns = sv.event_time_us() * 1000;
            auto& sb = sv.bids();
            auto& sa = sv.asks();
            e.count = static_cast<uint8_t>(std::min<uint16_t>(sb.count, websocket::msg::MAX_BOOK_LEVELS / 2));
            e.count2 = static_cast<uint8_t>(std::min<uint16_t>(sa.count, websocket::msg::MAX_BOOK_LEVELS / 2));
            for (uint8_t i = 0; i < e.count; i++) {
                auto lv = sb.level(i);
                e.payload.snapshot.levels[i] = { lv.price_mantissa(), lv.qty_mantissa() };
            }
            for (uint8_t i = 0; i < e.count2; i++) {
                auto lv = sa.level(i);
                e.payload.snapshot.levels[e.count + i] = { lv.price_mantissa(), lv.qty_mantissa() };
            }
        });
    }

    void publish_depth_diff(uint8_t ci, const DepthDiffView& dv) {
        int64_t seq = dv.last_book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
            e.src_seq = seq;
            e.event_ts_ns = dv.event_time_us() * 1000;
            auto& db = dv.bids();
            auto& da = dv.asks();
            uint8_t n = 0;
            for (uint16_t i = 0; i < db.count && n < websocket::msg::MAX_DELTAS; i++, n++) {
                auto lv = db.level(i);
                auto& de = e.payload.deltas.entries[n];
                de.price = lv.price_mantissa();
                de.qty = lv.qty_mantissa();
                de.action = (lv.qty_mantissa() == 0)
                    ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                    : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                de.flags = 0;  // bid
            }
            for (uint16_t i = 0; i < da.count && n < websocket::msg::MAX_DELTAS; i++, n++) {
                auto lv = da.level(i);
                auto& de = e.payload.deltas.entries[n];
                de.price = lv.price_mantissa();
                de.qty = lv.qty_mantissa();
                de.action = (lv.qty_mantissa() == 0)
                    ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                    : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                de.flags = websocket::msg::DeltaFlags::SIDE_ASK;
            }
            e.count = n;
        });
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
        mkt_event_prod->publish(slot);
    }

    void init_failover(uint64_t tsc_hz) {
        if (tsc_hz > 0) {
            failover_lock_cycles_ = FAILOVER_LOCK_MS * tsc_hz / 1000;
            stale_threshold_cycles_ = STALE_THRESHOLD_MS * tsc_hz / 1000;
        }
    }

    void on_failover(uint8_t old_ci, uint8_t new_ci, const char* reason) {
        publish_status(websocket::msg::SystemStatusType::FAILOVER, new_ci, 0, reason);
        fprintf(stderr, "[FAILOVER] %c → %c (%s)\n",
                'A' + old_ci, 'A' + new_ci, reason);
    }

    void record_win(uint8_t ci) {
        uint64_t now = __rdtsc();
        conn_win_count_[ci]++;
        conn_loss_streak_[ci] = 0;
        conn_last_win_cycle_[ci] = now;
        conn_last_data_cycle_[ci] = now;

        uint8_t other = ci ^ 1;
        conn_loss_streak_[other]++;

        // Update active_ci_ (for is_active_conn flag on WSFrameInfo)
        if (ci != active_ci_) {
            active_ci_ = ci;
            if (conn_state)
                conn_state->conn_priority.active_connection.store(ci, std::memory_order_release);
        }

        // Failover: switch primary if non-primary wins consistently
        if (ci != primary_ci_ && !failover_locked_) {
            if (conn_loss_streak_[primary_ci_] >= FAILOVER_LOSS_THRESHOLD) {
                uint8_t old = primary_ci_;
                primary_ci_ = ci;
                failover_locked_ = true;
                failover_lock_until_cycle_ = now + failover_lock_cycles_;
                on_failover(old, ci, "loss_streak");
            }
        }

        // Unlock after grace period
        if (failover_locked_ && now >= failover_lock_until_cycle_) {
            failover_locked_ = false;
        }
    }
};

}  // namespace websocket::sbe

#endif  // PIPELINE_DATA_HPP_INCLUDED
