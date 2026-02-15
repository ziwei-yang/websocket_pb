// msg/binance_sbe.hpp
// Zero-copy SBE (Simple Binary Encoding) decoders for Binance binary market data
//
// All little-endian (x86 native — no byte swap). Reads directly from WS
// payload buffer via const uint8_t* — no copies, no allocations.
//
// Supported messages:
//   templateId 10000 = TradesStreamEvent
//   templateId 10001 = BestBidAskStreamEvent
//   templateId 10002 = DepthSnapshotStreamEvent
//   templateId 10003 = DepthDiffStreamEvent
//
// Usage:
//   sbe::SBEHeader hdr;
//   if (!sbe::decode_header(payload, len, hdr)) return;
//   const uint8_t* body = payload + sbe::HEADER_SIZE;
//   size_t body_len = len - sbe::HEADER_SIZE;
//   switch (hdr.template_id) {
//     case sbe::TRADES_STREAM: { sbe::TradesView tv; ... }
//   }
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <string_view>

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
        1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1.0
    };
    int idx = exponent + 8;
    if (idx >= 0 && idx <= 8) return mantissa * pow10[idx];
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

    int64_t event_time_us()      const { return read_i64(buf_ + 0); }
    int64_t book_update_id()     const { return read_i64(buf_ + 8); }
    int8_t  price_exponent()     const { return read_i8(buf_ + 16); }
    int8_t  qty_exponent()       const { return read_i8(buf_ + 17); }
    int64_t bid_price_mantissa() const { return read_i64(buf_ + 18); }
    int64_t bid_qty_mantissa()   const { return read_i64(buf_ + 26); }
    int64_t ask_price_mantissa() const { return read_i64(buf_ + 34); }
    int64_t ask_qty_mantissa()   const { return read_i64(buf_ + 42); }

    std::string_view symbol() const {
        const uint8_t* sym_ptr = buf_ + 50;
        size_t remaining = (len_ > 50) ? len_ - 50 : 0;
        return read_var_string8(sym_ptr, remaining);
    }

    static bool decode(const uint8_t* body, size_t body_len,
                       uint16_t root_block_len, BestBidAskView& out) {
        if (body_len < root_block_len) return false;
        out.buf_ = body;
        out.len_ = body_len;
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

}  // namespace websocket::sbe
