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
#include "../pipeline/pipeline_data.hpp"  // PIPELINE_MAX_CONN

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

    // ── Streaming parse state machine (one per connection) ──────────────────
    struct SBEParseState {
        enum Phase : uint8_t {
            IDLE = 0,         // No active fragmented message
            HEADER_PARSED,    // SBE header + root block parsed, know msg type/seq
            BIDS_HEADER,      // Bids group header parsed, know bid count
            BIDS_ENTRIES,     // Publishing bid entries as they arrive
            ASKS_HEADER,      // Asks group header parsed, know ask count
            ASKS_ENTRIES,     // Publishing ask entries as they arrive
            TRADES_HEADER,    // Trades group header parsed, know trade count
            TRADES_ENTRIES,   // Publishing trade entries as they arrive
            DONE,             // All data published, skip re-publish on last fragment
        };

        Phase phase = IDLE;
        uint16_t msg_type = 0;         // SBE template ID
        int64_t sequence = 0;          // Dedup sequence (book_update_id / last trade_id)
        int64_t event_time_us = 0;     // Exchange event time

        // Group parsing state
        uint16_t group_block_len = 0;  // Per-entry size in bytes
        uint16_t group_count = 0;      // Total entries in current group
        uint16_t group_published = 0;  // Entries already published from current group

        // For depth: track bid/ask separately
        uint16_t bids_count = 0;
        uint16_t bids_published = 0;
        uint16_t asks_count = 0;
        uint16_t asks_published = 0;

        // Dedup propagation: set when initial dedup fires DONE, so subsequent
        // TLS records hitting the non-IDLE DONE path can propagate discard_early.
        bool deduped = false;

        // Cursor tracking
        uint32_t bytes_consumed = 0;   // Total bytes parsed so far from payload start
        uint16_t root_block_len = 0;   // SBE root block length

        // Depth delta accumulator (partial publish across fragments)
        uint8_t delta_count = 0;       // Entries accumulated in delta_buf
        uint8_t snapshot_bid_count = 0; // Bids accumulated (snapshot only, for bid/ask split)
        uint8_t flush_count = 0;       // Multi-flush batch counter (for CONTINUATION flag)
        websocket::msg::DeltaEntry delta_buf[websocket::msg::MAX_BOOK_LEVELS];

        void reset() {
            phase = IDLE;
            deduped = false;
            bytes_consumed = 0;
            msg_type = 0;
            sequence = 0;
            event_time_us = 0;
            group_block_len = 0;
            group_count = 0;
            group_published = 0;
            bids_count = 0;
            bids_published = 0;
            asks_count = 0;
            asks_published = 0;
            root_block_len = 0;
            delta_count = 0;
            snapshot_bid_count = 0;
            flush_count = 0;
        }
    };

    // Interleave state for multi-connection same-SEQ dedup (SBE single channel)
    struct InterleaveState {
        int64_t  seq = 0;
        uint16_t committed_count = 0;
        bool     finished = false;
        websocket::msg::DeltaEntry boundary_entry{};
        uint8_t  flush_count = 0;       // global MktEvent flush count for this seq

        void reset(int64_t new_seq) {
            seq = new_seq; committed_count = 0; finished = false;
            boundary_entry = {};
            flush_count = 0;
        }
    };

struct BinanceSBEHandler {
    static constexpr bool enabled = true;
    websocket::pipeline::IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    websocket::pipeline::ConnStateShm* conn_state = nullptr;
    bool merge_enabled = true;
    int64_t last_book_seq_ = 0;
    InterleaveState interleave_{};
    int64_t last_bbo_seq_ = 0;
    int64_t last_trade_id_ = 0;
    uint16_t instrument_id = 0;
    uint8_t active_ci_ = 0xFF;
    websocket::pipeline::WSFrameInfo* current_info_ = nullptr;

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

    // Pending depth delta accumulation buffer — merges consecutive DEPTH_DIFF frames
    bool has_pending_depth_ = false;
    uint8_t pending_depth_ci_ = 0;
    uint8_t pending_depth_count_ = 0;
    websocket::msg::DeltaEntry pending_depth_entries_[websocket::msg::MAX_DELTAS];
    int64_t pending_depth_seq_ = 0;
    int64_t pending_depth_event_ts_ns_ = 0;
    websocket::msg::EventType pending_depth_event_type_{};
    uint16_t pending_depth_extra_flags_ = 0;
    uint8_t pending_depth_flush_count_ = 0;
    websocket::pipeline::WSFrameInfo pending_depth_info_{};

    // Per-connection streaming SBE parse state
    SBEParseState sbe_state_[PIPELINE_MAX_CONN]{};

    // ── Streaming SBE parser — single code path for fragments + complete frames ──
    //
    // Called for every data delivery: intermediate fragments, final fragments,
    // and complete non-fragmented frames.
    // payload + len = full accumulated data from the start of the WS message.
    // State machine resumes from state.bytes_consumed, only processes new bytes.
    // Naturally idempotent: re-calling with the same len is a no-op.
    void on_ws_data(SBEParseState& state, uint8_t ci,
                    const uint8_t* payload, uint32_t len,
                    websocket::pipeline::WSFrameInfo& info) {
        pending_ring_seq_slot_ = nullptr;  // reset per call; WSCore fills after ring publish

        // If state already past IDLE, repopulate info from state (caller may pass fresh info)
        if (state.phase != SBEParseState::IDLE) {
            switch (state.msg_type) {
            case TRADES_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
                break;
            case BEST_BID_ASK_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY);
                break;
            case DEPTH_SNAPSHOT_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
                break;
            case DEPTH_DIFF_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
                break;
            }
            info.exchange_event_time_us = state.event_time_us;
            info.mkt_event_seq = state.sequence;
            info.mkt_event_count = state.group_count;
            if (state.bids_count > 0 || state.asks_count > 0)
                info.mkt_event_count = state.bids_count + state.asks_count;
            if (state.phase == SBEParseState::DONE) {
                if (state.deduped) info.set_discard_early(true);
                return;  // fully parsed, just repopulated info
            }

            // Re-check dedup: another connection may have superseded while streaming
            if (state.msg_type == DEPTH_SNAPSHOT_STREAM || state.msg_type == DEPTH_DIFF_STREAM) {
                if (state.sequence < last_book_seq_) {
                    state.deduped = true;
                    state.phase = SBEParseState::DONE;
                    info.set_discard_early(true);
                    return;
                }
                if (state.msg_type == DEPTH_DIFF_STREAM &&
                    state.sequence == last_book_seq_ &&
                    interleave_.seq == state.sequence && interleave_.finished) {
                    state.deduped = true;
                    state.phase = SBEParseState::DONE;
                    info.set_discard_early(true);
                    return;
                }
            }
        }

        // ── Phase IDLE → HEADER_PARSED ──────────────────────────────────────
        if (state.phase == SBEParseState::IDLE) {
            if (len < HEADER_SIZE) return;  // not enough for SBE header

            SBEHeader hdr;
            if (!decode_header(payload, len, hdr)) return;

            state.msg_type = hdr.template_id;
            state.root_block_len = hdr.block_length;

            // Need at least header + root block to extract essential fields
            uint32_t min_root = HEADER_SIZE + hdr.block_length;
            if (len < min_root) return;

            const uint8_t* body = payload + HEADER_SIZE;
            size_t body_len = len - HEADER_SIZE;

            // Extract event_time (always at body+0 for all msg types)
            state.event_time_us = read_i64(body);

            // Extract sequence per message type
            switch (state.msg_type) {
            case TRADES_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
                info.exchange_event_time_us = state.event_time_us;
                // sequence (last trade_id) deferred to TRADES_ENTRIES
                break;
            case BEST_BID_ASK_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY);
                info.exchange_event_time_us = state.event_time_us;
                state.sequence = read_i64(body + 8);  // book_update_id
                info.mkt_event_seq = state.sequence;
                break;
            case DEPTH_SNAPSHOT_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
                info.exchange_event_time_us = state.event_time_us;
                state.sequence = read_i64(body + 8);  // book_update_id
                info.mkt_event_seq = state.sequence;
                break;
            case DEPTH_DIFF_STREAM:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
                info.exchange_event_time_us = state.event_time_us;
                if (body_len >= 24)
                    state.sequence = read_i64(body + 16);  // last_book_update_id
                info.mkt_event_seq = state.sequence;
                break;
            default:
                info.mkt_event_type = static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS);
                state.phase = SBEParseState::DONE;
                return;
            }

            // Cross-type flush (same as original on_ws_frame)
            if (has_pending_trades_ && state.msg_type != TRADES_STREAM)
                flush_pending_trades();
            if (has_pending_bbo_ && state.msg_type != BEST_BID_ASK_STREAM)
                flush_pending_bbo();
            if (has_pending_depth_ && state.msg_type != DEPTH_DIFF_STREAM)
                publish_pending_depth(true);

            // Stale detection (once, at header parse)
            // Trade stale check is deferred to TRADES_HEADER when we know the last trade_id
            if (state.sequence > 0 && state.msg_type != TRADES_STREAM
                && state.msg_type != BEST_BID_ASK_STREAM) {
                if (state.msg_type == DEPTH_DIFF_STREAM) {
                    if (state.sequence < last_book_seq_) {
                        // Strictly older — discard
                        info.set_discard_early(true);
                        state.deduped = true;
                        state.phase = SBEParseState::DONE;
                        return;
                    }
                    if (state.sequence == last_book_seq_) {
                        if (interleave_.seq == state.sequence && interleave_.finished) {
                            // Fully parsed already — discard
                            info.set_discard_early(true);
                            state.deduped = true;
                            state.phase = SBEParseState::DONE;
                            return;
                        }
                        // Same seq, not finished — allow interleaving
                    } else {
                        // New seq — claim and reset interleave
                        last_book_seq_ = state.sequence;
                        interleave_.reset(state.sequence);
                    }
                } else if (state.msg_type == DEPTH_SNAPSHOT_STREAM) {
                    if (state.sequence <= last_book_seq_) {
                        info.set_discard_early(true);
                        state.deduped = true;
                        state.phase = SBEParseState::DONE;
                        return;
                    }
                    last_book_seq_ = state.sequence;
                    interleave_.reset(state.sequence);
                    interleave_.finished = true;  // snapshot claims seq
                } else {
                    if (state.sequence <= last_book_seq_) {
                        info.set_discard_early(true);
                        state.deduped = true;
                        state.phase = SBEParseState::DONE;
                        return;
                    }
                }
            }

            state.bytes_consumed = min_root;
            state.phase = SBEParseState::HEADER_PARSED;
            current_info_ = &info;

            // BBO: root block has all data, publish immediately
            if (state.msg_type == BEST_BID_ASK_STREAM) {
                on_ws_data_bbo(state, ci, payload, len, info);
                current_info_ = nullptr;
                return;
            }
        }

        // ── Resume from HEADER_PARSED or group phases ───────────────────────
        current_info_ = &info;

        switch (state.msg_type) {
        case TRADES_STREAM:
            on_ws_data_trades(state, ci, payload, len, info);
            break;
        case DEPTH_SNAPSHOT_STREAM:
            on_ws_data_depth(state, ci, payload, len, info,
                             websocket::msg::EventType::BOOK_SNAPSHOT,
                             websocket::msg::EventFlags::SNAPSHOT);
            break;
        case DEPTH_DIFF_STREAM:
            on_ws_data_depth(state, ci, payload, len, info,
                             websocket::msg::EventType::BOOK_DELTA, 0);
            break;
        }

        current_info_ = nullptr;
    }

private:
    // ── BBO streaming handler ───────────────────────────────────────────────
    void on_ws_data_bbo(SBEParseState& state, uint8_t ci,
                        const uint8_t* payload, uint32_t len,
                        websocket::pipeline::WSFrameInfo& info) {
        const uint8_t* body = payload + HEADER_SIZE;
        size_t body_len = len - HEADER_SIZE;

        BestBidAskView bv;
        if (!BestBidAskView::decode(body, body_len, state.root_block_len, bv)) {
            state.phase = SBEParseState::DONE;
            return;
        }

        int64_t seq = bv.book_update_id();
        int64_t eff_bbo_seq = has_pending_bbo_
            ? std::max(last_bbo_seq_, pending_bbo_max_seq_)
            : last_bbo_seq_;
        if (seq <= eff_bbo_seq) {
            info.mkt_event_count = 1;
            info.set_discard_early(true);
            state.phase = SBEParseState::DONE;
            return;
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

        state.phase = SBEParseState::DONE;
    }

    // ── Trades streaming handler ────────────────────────────────────────────
    void on_ws_data_trades(SBEParseState& state, uint8_t ci,
                           const uint8_t* payload, uint32_t len,
                           websocket::pipeline::WSFrameInfo& info) {
        // Parse group header if needed
        if (state.phase == SBEParseState::HEADER_PARSED) {
            if (len < state.bytes_consumed + 6) return;  // need GroupSize (6 bytes)
            const uint8_t* cursor = payload + state.bytes_consumed;
            GroupSize gs;
            if (!read_group_size(cursor, len - state.bytes_consumed, gs)) return;
            state.group_block_len = gs.block_length;
            state.group_count = static_cast<uint16_t>(std::min(gs.num_in_group, (uint32_t)65535));
            state.group_published = 0;
            state.bytes_consumed += 6;
            info.mkt_event_count = state.group_count;
            state.phase = SBEParseState::TRADES_HEADER;

            if (state.group_count == 0) {
                state.phase = SBEParseState::DONE;
                return;
            }

            // Now that we know total trade count, compute sequence (last trade_id)
            // and check for stale
            uint32_t entries_end = state.bytes_consumed +
                static_cast<uint32_t>(state.group_count) * state.group_block_len;
            if (len >= entries_end) {
                // Can read last entry's trade_id
                const uint8_t* last_entry = payload + entries_end -
                    state.group_block_len;
                state.sequence = read_i64(last_entry);  // trade_id at offset 0
                info.mkt_event_seq = state.sequence;
            }

            // Stale check for trades
            if (state.sequence > 0) {
                int64_t eff_tid = has_pending_trades_
                    ? std::max(last_trade_id_, pending_trades_max_id_)
                    : last_trade_id_;
                if (state.sequence <= eff_tid) {
                    info.set_discard_early(true);
                    state.deduped = true;
                    state.phase = SBEParseState::DONE;
                    return;
                }
            }
            // First-entry lower-bound stale check.  Catches both:
            // (a) fragmented messages (state.sequence==0, last entry unreadable)
            // (b) full messages where last_trade_id_ is partial (winning conn
            //     mid-fragment, only first N entries flushed — state.sequence
            //     barely exceeds the partial eff_tid but first_tid does not)
            if (state.group_count > 0 &&
                state.bytes_consumed + state.group_block_len <= len) {
                int64_t first_tid = read_i64(payload + state.bytes_consumed);
                int64_t eff_tid = has_pending_trades_
                    ? std::max(last_trade_id_, pending_trades_max_id_)
                    : last_trade_id_;
                if (first_tid > 0 && first_tid <= eff_tid) {
                    info.set_discard_early(true);
                    state.deduped = true;
                    state.phase = SBEParseState::DONE;
                    return;
                }
            }
        }

        // Parse trade entries
        if (state.phase == SBEParseState::TRADES_HEADER ||
            state.phase == SBEParseState::TRADES_ENTRIES) {
            state.phase = SBEParseState::TRADES_ENTRIES;

            const uint8_t* body = payload + HEADER_SIZE;
            int64_t transact_ns = read_i64(body + 8) * 1000;  // transact_time_us at body+8
            int64_t event_ts_ns = state.event_time_us * 1000;

            // Cross-connection: flush pending trades from a different connection
            // before adding entries from this connection, preventing mixed batches
            if (merge_enabled && has_pending_trades_ && pending_trades_ci_ != ci) {
                flush_pending_trades(false);
            }

            // Stale re-check after cross-conn flush and on fragment resumption.
            // Catches: (a) header-only fragments where no entry was readable,
            // (b) resumed fragments where last_trade_id_ advanced between calls,
            // (c) messages that passed HEADER_PARSED stale check before cross-conn flush
            if (state.group_published < state.group_count) {
                uint32_t next_offset = state.bytes_consumed +
                    static_cast<uint32_t>(state.group_published) * state.group_block_len;
                if (next_offset + state.group_block_len <= len) {
                    int64_t next_tid = read_i64(payload + next_offset);
                    int64_t eff_tid = has_pending_trades_
                        ? std::max(last_trade_id_, pending_trades_max_id_)
                        : last_trade_id_;
                    if (next_tid > 0 && next_tid <= eff_tid) {
                        state.phase = SBEParseState::DONE;
                        info.set_discard_early(true);
                        return;
                    }
                }
            }

            // Non-merge local batch (stack-local, no member state needed)
            websocket::msg::TradeEntry nm_batch[websocket::msg::MAX_TRADES];
            uint8_t nm_count = 0;

            while (state.group_published < state.group_count) {
                uint32_t entry_offset = state.bytes_consumed +
                    static_cast<uint32_t>(state.group_published) * state.group_block_len;
                if (entry_offset + state.group_block_len > len) break;  // not enough data

                TradeEntryView te_view{ payload + entry_offset };
                int64_t trade_id = te_view.id();

                if (merge_enabled) {
                    pending_trades_event_ts_ns_ = event_ts_ns;
                    if (state.sequence > 0)
                        pending_trades_max_id_ = std::max(pending_trades_max_id_, state.sequence);
                    else
                        pending_trades_max_id_ = std::max(pending_trades_max_id_, trade_id);

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
                    te.price = te_view.price_mantissa();
                    te.qty = te_view.qty_mantissa();
                    te.trade_id = trade_id;
                    te.trade_time_ns = transact_ns;
                    te.flags = te_view.is_buyer_maker() ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                } else {
                    // Non-merge: batch up to MAX_TRADES, publish when full
                    auto& te = nm_batch[nm_count++];
                    te.price = te_view.price_mantissa();
                    te.qty = te_view.qty_mantissa();
                    te.trade_id = trade_id;
                    te.trade_time_ns = transact_ns;
                    te.flags = te_view.is_buyer_maker() ? 0 : websocket::msg::TradeFlags::IS_BUYER;
                    if (nm_count >= websocket::msg::MAX_TRADES) {
                        last_trade_id_ = std::max(last_trade_id_, nm_batch[nm_count - 1].trade_id);
                        record_win(ci);
                        uint8_t count = nm_count;
                        publish_event([&](websocket::msg::MktEvent& ev) {
                            ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY));
                            ev.src_seq = nm_batch[count - 1].trade_id;
                            ev.event_ts_ns = event_ts_ns;
                            ev.count = count;
                            std::memcpy(ev.payload.trades.entries, nm_batch,
                                        count * sizeof(websocket::msg::TradeEntry));
                        });
                        nm_count = 0;
                    }
                }

                state.group_published++;
            }

            // Flush non-merge remainder
            if (!merge_enabled && nm_count > 0) {
                last_trade_id_ = std::max(last_trade_id_, nm_batch[nm_count - 1].trade_id);
                record_win(ci);
                uint8_t count = nm_count;
                publish_event([&](websocket::msg::MktEvent& ev) {
                    ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY));
                    ev.src_seq = nm_batch[count - 1].trade_id;
                    ev.event_ts_ns = event_ts_ns;
                    ev.count = count;
                    std::memcpy(ev.payload.trades.entries, nm_batch,
                                count * sizeof(websocket::msg::TradeEntry));
                });
            }

            if (state.group_published >= state.group_count) {
                if (merge_enabled) {
                    info.set_merged(true);
                    pending_ring_seq_slot_ = &pending_trades_ring_seq_;
                }
                // Update sequence from last published trade
                if (state.group_published > 0) {
                    uint32_t last_offset = state.bytes_consumed +
                        static_cast<uint32_t>(state.group_published - 1) * state.group_block_len;
                    if (last_offset + 8 <= len) {
                        state.sequence = read_i64(payload + last_offset);
                        info.mkt_event_seq = state.sequence;
                    }
                }
                state.phase = SBEParseState::DONE;
            }
        }
    }

    // ── Depth streaming handler (shared by snapshot + diff) ─────────────────
    static constexpr uint8_t SNAPSHOT_HALF = websocket::msg::MAX_BOOK_LEVELS / 2;  // 15

    void on_ws_data_depth(SBEParseState& state, uint8_t ci,
                          const uint8_t* payload, uint32_t len,
                          websocket::pipeline::WSFrameInfo& info,
                          websocket::msg::EventType event_type,
                          uint16_t extra_flags) {
        // Parse bids group header
        if (state.phase == SBEParseState::HEADER_PARSED) {
            if (len < state.bytes_consumed + 4) return;  // need GroupSize16 (4 bytes)
            const uint8_t* cursor = payload + state.bytes_consumed;
            GroupSize16 gs;
            if (!read_group_size16(cursor, len - state.bytes_consumed, gs)) return;
            state.bids_count = gs.num_in_group;
            state.bids_published = 0;
            state.group_block_len = gs.block_length;
            state.bytes_consumed += 4;
            state.phase = SBEParseState::BIDS_HEADER;
        }

        // Parse bid entries
        if (state.phase == SBEParseState::BIDS_HEADER ||
            state.phase == SBEParseState::BIDS_ENTRIES) {
            state.phase = SBEParseState::BIDS_ENTRIES;
            while (state.bids_published < state.bids_count) {
                uint32_t entry_offset = state.bytes_consumed +
                    static_cast<uint32_t>(state.bids_published) * state.group_block_len;
                if (entry_offset + state.group_block_len > len) break;

                PriceLevelView lv{ payload + entry_offset };
                if (event_type == websocket::msg::EventType::BOOK_SNAPSHOT) {
                    if (state.delta_count < SNAPSHOT_HALF) {
                        auto& de = state.delta_buf[state.delta_count++];
                        de.price = lv.price_mantissa();
                        de.qty = lv.qty_mantissa();
                        de.flags = 0;  // bid
                    }
                    // else: beyond cap, discard but keep parsing
                } else {
                    if (state.delta_count >= websocket::msg::MAX_DELTAS)
                        flush_depth_deltas(state, ci, info, event_type, extra_flags);
                    auto& de = state.delta_buf[state.delta_count++];
                    de.price = lv.price_mantissa();
                    de.qty = lv.qty_mantissa();
                    de.action = (lv.qty_mantissa() == 0)
                        ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                        : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                    de.flags = 0;  // bid
                }

                state.bids_published++;
            }

            if (state.bids_published >= state.bids_count) {
                state.bytes_consumed += static_cast<uint32_t>(state.bids_count) * state.group_block_len;
                state.phase = SBEParseState::ASKS_HEADER;
            }
        }

        // Parse asks group header
        if (state.phase == SBEParseState::ASKS_HEADER) {
            if (len < state.bytes_consumed + 4) {
                if (state.delta_count > 0 && event_type != websocket::msg::EventType::BOOK_SNAPSHOT)
                    flush_depth_deltas(state, ci, info, event_type, extra_flags);
                return;
            }
            const uint8_t* cursor = payload + state.bytes_consumed;
            GroupSize16 gs;
            if (!read_group_size16(cursor, len - state.bytes_consumed, gs)) {
                if (state.delta_count > 0 && event_type != websocket::msg::EventType::BOOK_SNAPSHOT)
                    flush_depth_deltas(state, ci, info, event_type, extra_flags);
                return;
            }
            state.asks_count = gs.num_in_group;
            state.asks_published = 0;
            // group_block_len for asks (should be same as bids, but read from wire)
            state.group_block_len = gs.block_length;
            state.bytes_consumed += 4;

            // Update total count now that we know both
            info.mkt_event_count = state.bids_count + state.asks_count;
            // Save bid count for snapshot bid/ask split
            state.snapshot_bid_count = state.delta_count;
        }

        // Parse ask entries
        if (state.phase == SBEParseState::ASKS_HEADER ||
            state.phase == SBEParseState::ASKS_ENTRIES) {
            state.phase = SBEParseState::ASKS_ENTRIES;
            while (state.asks_published < state.asks_count) {
                uint32_t entry_offset = state.bytes_consumed +
                    static_cast<uint32_t>(state.asks_published) * state.group_block_len;
                if (entry_offset + state.group_block_len > len) break;

                PriceLevelView lv{ payload + entry_offset };
                if (event_type == websocket::msg::EventType::BOOK_SNAPSHOT) {
                    uint8_t asks_stored = state.delta_count - state.snapshot_bid_count;
                    if (asks_stored < SNAPSHOT_HALF) {
                        auto& de = state.delta_buf[state.delta_count++];
                        de.price = lv.price_mantissa();
                        de.qty = lv.qty_mantissa();
                        de.flags = websocket::msg::DeltaFlags::SIDE_ASK;
                    }
                    // else: beyond cap, discard but keep parsing
                } else {
                    if (state.delta_count >= websocket::msg::MAX_DELTAS)
                        flush_depth_deltas(state, ci, info, event_type, extra_flags);
                    auto& de = state.delta_buf[state.delta_count++];
                    de.price = lv.price_mantissa();
                    de.qty = lv.qty_mantissa();
                    de.action = (lv.qty_mantissa() == 0)
                        ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                        : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                    de.flags = websocket::msg::DeltaFlags::SIDE_ASK;
                }

                state.asks_published++;
            }

            if (state.asks_published >= state.asks_count) {
                // Flush remaining: snapshot → flush_depth_snapshot, delta → flush_depth_deltas
                if (state.delta_count > 0) {
                    if (event_type == websocket::msg::EventType::BOOK_SNAPSHOT)
                        flush_depth_snapshot(state, ci, info);
                    else
                        flush_depth_deltas(state, ci, info, event_type, extra_flags, /*is_final=*/true);
                }
                state.phase = SBEParseState::DONE;
            }
        }

        // Fragment boundary: flush partial deltas so downstream gets parsed data immediately.
        // Skipped for snapshots (different flush path, capped at SNAPSHOT_HALF).
        if (state.phase != SBEParseState::DONE && state.delta_count > 0 &&
            event_type != websocket::msg::EventType::BOOK_SNAPSHOT) {
            flush_depth_deltas(state, ci, info, event_type, extra_flags);
        }
    }

    void flush_depth_deltas(SBEParseState& state, uint8_t ci,
                            websocket::pipeline::WSFrameInfo& info,
                            websocket::msg::EventType event_type,
                            uint16_t extra_flags,
                            bool is_final = false) {
        if (state.delta_count == 0) {
            if (is_final && interleave_.seq == state.sequence)
                interleave_.finished = true;
            return;
        }
        uint8_t count = state.delta_count;

        // ── Interleave skip + verify ──
        if (interleave_.seq != state.sequence) interleave_.reset(state.sequence);

        uint16_t cumul = state.bids_published + state.asks_published;
        uint16_t prev_cumul = cumul - count;
        uint8_t skip = 0;

        if (cumul <= interleave_.committed_count) {
            // All entries already committed — skip entirely
            state.flush_count++;
            state.delta_count = 0;
            info.set_discard_early(true);
            if (is_final) interleave_.finished = true;
            return;
        }

        if (prev_cumul < interleave_.committed_count && interleave_.committed_count > 0) {
            // Boundary crossing — verify entry at committed_count - 1
            uint16_t boundary_idx = interleave_.committed_count - 1 - prev_cumul;
            auto& cached = interleave_.boundary_entry;
            auto& check = state.delta_buf[boundary_idx];
            if (check.price != cached.price || check.qty != cached.qty) {
                std::fprintf(stderr, "WARN: interleave mismatch seq=%lld at entry %u\n",
                        (long long)state.sequence, interleave_.committed_count - 1);
                state.deduped = true;
                state.phase = SBEParseState::DONE;
                state.delta_count = 0;
                return;
            }
            skip = static_cast<uint8_t>(interleave_.committed_count - prev_cumul);
        }

        uint8_t publish_count = count - skip;
        info.set_discard_early(false);

        // Connection switch: if pending has entries from a different connection, flush first
        if (has_pending_depth_ && pending_depth_ci_ != ci) {
            publish_pending_depth(false);
            has_pending_depth_ = false;  // force re-init for new connection
        }

        // Sequence change: flush old seq's pending entries before starting new seq
        if (has_pending_depth_ && pending_depth_seq_ != state.sequence) {
            publish_pending_depth(true);
            has_pending_depth_ = false;
        }

        // Overflow: pending + new > MAX_DELTAS → publish pending first
        if (has_pending_depth_ && pending_depth_count_ + publish_count > websocket::msg::MAX_DELTAS)
            publish_pending_depth(false);

        // Initialize pending on first entry in batch
        if (!has_pending_depth_) {
            has_pending_depth_ = true;
            pending_depth_ci_ = ci;
            pending_depth_count_ = 0;
            pending_depth_event_type_ = event_type;
            pending_depth_extra_flags_ = extra_flags;
            pending_depth_flush_count_ = (interleave_.seq == state.sequence)
                ? interleave_.flush_count : 0;
            pending_depth_info_ = info;
        }

        // Append only the new entries (past the skip boundary)
        std::memcpy(pending_depth_entries_ + pending_depth_count_, state.delta_buf + skip,
                    publish_count * sizeof(websocket::msg::DeltaEntry));
        pending_depth_count_ += publish_count;
        pending_depth_seq_ = state.sequence;
        pending_depth_event_ts_ns_ = state.event_time_us * 1000;

        // Update interleave state
        interleave_.boundary_entry = state.delta_buf[count - 1];
        interleave_.committed_count = cumul;
        if (is_final) interleave_.finished = true;

        state.flush_count++;
        state.delta_count = 0;
    }

    void publish_pending_depth(bool is_final) {
        if (!has_pending_depth_ || pending_depth_count_ == 0) return;
        record_win(pending_depth_ci_);
        current_info_ = &pending_depth_info_;
        uint8_t count = pending_depth_count_;
        uint8_t fc = pending_depth_flush_count_;
        publish_event([&](websocket::msg::MktEvent& e) {
            e.set_event_type(static_cast<uint8_t>(pending_depth_event_type_));
            uint16_t f = pending_depth_extra_flags_;
            if (fc > 0)    f |= websocket::msg::EventFlags::CONTINUATION;
            if (is_final)  f |= websocket::msg::EventFlags::LAST_IN_BATCH;
            e.flags |= f;
            e.src_seq = pending_depth_seq_;
            e.event_ts_ns = pending_depth_event_ts_ns_;
            e.count = count;
            e.count2 = fc;  // flush_index
            std::memcpy(e.payload.deltas.entries, pending_depth_entries_,
                        count * sizeof(websocket::msg::DeltaEntry));
        });
        current_info_ = nullptr;
        pending_depth_flush_count_++;
        if (interleave_.seq == pending_depth_seq_)
            interleave_.flush_count = pending_depth_flush_count_;
        pending_depth_count_ = 0;
        if (is_final) {
            has_pending_depth_ = false;
            pending_depth_flush_count_ = 0;
        }
    }

    void flush_depth_snapshot(SBEParseState& state, uint8_t ci,
                              [[maybe_unused]] websocket::pipeline::WSFrameInfo& info) {
        if (state.delta_count == 0) return;
        record_win(ci);
        uint8_t total = state.delta_count;
        int64_t seq = state.sequence;
        uint8_t bid_n = state.snapshot_bid_count;
        uint8_t ask_n = total - bid_n;
        publish_event([&](websocket::msg::MktEvent& e) {
            e.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT));
            e.flags |= websocket::msg::EventFlags::SNAPSHOT;
            e.src_seq = seq;
            e.event_ts_ns = state.event_time_us * 1000;
            e.count = bid_n;
            e.count2 = ask_n;
            // Write bids first (indices 0..bid_n-1), then asks (indices bid_n..total-1)
            for (uint8_t i = 0; i < total; i++)
                e.payload.snapshot.levels[i] = { state.delta_buf[i].price, state.delta_buf[i].qty };
        });
        state.delta_count = 0;
    }

public:

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
            ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY));
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

    void on_batch_end(uint8_t) {
        publish_pending_depth(true);
        flush_pending_bbo();
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

    void publish_status(websocket::msg::SystemStatusType status, uint8_t ci,
                        int64_t detail = 0, const char* msg = nullptr) {
        if (!mkt_event_prod) return;
        int64_t slot = mkt_event_prod->try_claim();
        if (slot < 0) return;
        auto& e = (*mkt_event_prod)[slot];
        e.clear();
        e.set_venue_id(static_cast<uint8_t>(websocket::msg::VenueId::BINANCE));
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

    void publish_bbo_single(uint8_t ci, const BestBidAskView& bv) {
        int64_t seq = bv.book_update_id();
        if (seq <= last_bbo_seq_) return;
        last_bbo_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& ev) {
            ev.set_event_type(static_cast<uint8_t>(websocket::msg::EventType::BBO_ARRAY));
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

    template<typename F>
    void publish_event(F&& build) {
        if (!mkt_event_prod) return;
        int64_t slot = mkt_event_prod->try_claim();
        if (slot < 0) return;
        auto& e = (*mkt_event_prod)[slot];
        e.clear();
        e.set_venue_id(static_cast<uint8_t>(websocket::msg::VenueId::BINANCE));
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

}  // namespace websocket::sbe

#endif  // PIPELINE_DATA_HPP_INCLUDED
