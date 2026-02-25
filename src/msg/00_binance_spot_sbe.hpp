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
    int64_t last_trade_id_ = 0;
    uint8_t active_ci_ = 0xFF;
    websocket::pipeline::WSFrameInfo* current_info_ = nullptr;

    // Ring producer for clearing M flag on published (winning) frames
    websocket::pipeline::IPCRingProducer<websocket::pipeline::WSFrameInfo>* ws_frame_info_prod_ = nullptr;  // set by WSCore::init()
    int64_t pending_bbo_ring_seq_ = -1;      // ring seq of last BBO frame that entered buffer
    int64_t pending_trades_ring_seq_ = -1;   // ring seq of last trade frame that entered buffer
    int64_t* pending_ring_seq_slot_ = nullptr; // WSCore writes published seq here after ring publish

    // Pending BBO buffer — defers publish until batch boundary or non-BBO book message
    bool has_pending_bbo_ = false;
    uint8_t pending_bbo_ci_ = 0;
    BestBidAskView pending_bbo_{};
    websocket::pipeline::WSFrameInfo pending_bbo_info_{};

    // Pending trade accumulation buffer — merges consecutive TRADES_STREAM frames
    bool has_pending_trades_ = false;
    uint8_t pending_trades_ci_ = 0;
    uint8_t pending_trade_count_ = 0;
    websocket::msg::TradeEntry pending_trade_entries_[websocket::msg::MAX_TRADES];
    int64_t pending_trades_event_ts_ns_ = 0;
    int64_t pending_trades_max_id_ = 0;
    websocket::pipeline::WSFrameInfo pending_trades_info_{};

    void on_ws_frame(uint8_t ci, uint8_t, const uint8_t* payload,
                     uint32_t len, websocket::pipeline::WSFrameInfo& info) {
        auto e = BinanceSpotSBEDecoder::decode_essential(payload, len);
        pending_ring_seq_slot_ = nullptr;  // reset per frame; WSCore fills after ring publish
        if (!e.valid) {
            info.set_mkt_event_info(
                static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS), 0);
            return;
        }

        switch (e.msg_type) {
        case TRADES_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY),
                                    static_cast<uint16_t>(e.count));
            break;
        case BEST_BID_ASK_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT),
                                    static_cast<uint16_t>(e.count), true);
            break;
        case DEPTH_SNAPSHOT_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT),
                                    static_cast<uint16_t>(e.count));
            break;
        case DEPTH_DIFF_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA),
                                    static_cast<uint16_t>(e.count));
            break;
        default:
            info.set_mkt_event_info(
                static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS), 0);
            break;
        }

        // Flush pending trades before any non-trade message
        if (has_pending_trades_ && e.msg_type != TRADES_STREAM) {
            flush_pending_trades();
        }

        // Flush pending BBO before any book-domain message (delta/snapshot share last_book_seq_)
        if (has_pending_bbo_ &&
            (e.msg_type == DEPTH_DIFF_STREAM || e.msg_type == DEPTH_SNAPSHOT_STREAM)) {
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
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY),
                                        static_cast<uint16_t>(tv.count()));

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
                if (seq <= last_book_seq_) {
                    info.set_discard_early(true);
                    break;
                }
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT), 1, true);
                if (merge_enabled) {
                    // Buffer: newer BBO replaces any previously pending one
                    pending_bbo_ = bv;
                    pending_bbo_ci_ = ci;
                    pending_bbo_info_ = info;
                    has_pending_bbo_ = true;
                    info.set_merged(true);  // optimistic: assume will be superseded
                    pending_ring_seq_slot_ = &pending_bbo_ring_seq_;  // WSCore fills ring seq
                } else {
                    publish_bbo(ci, bv);
                }
            }
            break;
        }
        case DEPTH_SNAPSHOT_STREAM: {
            DepthSnapshotView sv;
            if (DepthSnapshotView::decode(e.body, e.body_len, e.block_length, sv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT),
                                        static_cast<uint16_t>(sv.bids().count + sv.asks().count));
                publish_depth_snapshot(ci, sv);
            }
            break;
        }
        case DEPTH_DIFF_STREAM: {
            DepthDiffView dv;
            if (DepthDiffView::decode(e.body, e.body_len, e.block_length, dv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA),
                                        static_cast<uint16_t>(dv.bids().count + dv.asks().count));
                publish_depth_diff(ci, dv);
            }
            break;
        }
        }
        current_info_ = nullptr;
    }

    void flush_pending_bbo() {
        if (!has_pending_bbo_) return;
        has_pending_bbo_ = false;
        // Clear M on the winning frame — it IS being published, not superseded
        if (ws_frame_info_prod_ && pending_bbo_ring_seq_ >= 0) {
            (*ws_frame_info_prod_)[pending_bbo_ring_seq_].set_merged(false);
        }
        pending_bbo_ring_seq_ = -1;
        current_info_ = &pending_bbo_info_;
        publish_bbo(pending_bbo_ci_, pending_bbo_);
        current_info_ = nullptr;
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

    void publish_bbo(uint8_t ci, const BestBidAskView& bv) {
        int64_t seq = bv.book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
            e.flags |= websocket::msg::EventFlags::BBO;
            e.src_seq = seq;
            e.event_ts_ns = bv.event_time_us() * 1000;
            e.count = 1;
            e.count2 = 1;
            e.payload.snapshot.levels[0] = { bv.bid_price_mantissa(), bv.bid_qty_mantissa() };
            e.payload.snapshot.levels[1] = { bv.ask_price_mantissa(), bv.ask_qty_mantissa() };
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

    void record_win(uint8_t ci) {
        if (ci != active_ci_) {
            active_ci_ = ci;
            if (conn_state)
                conn_state->conn_priority.active_connection.store(ci, std::memory_order_release);
        }
    }
};

}  // namespace websocket::sbe

#endif  // PIPELINE_DATA_HPP_INCLUDED
