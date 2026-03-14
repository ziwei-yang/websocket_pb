// msg/mkt_event.hpp
// Fixed-size market data event for disruptor ring IPC
// 512 bytes aligned — fits depth10 snapshots, 12 trades, 20 deltas per event
// 32-byte header + 480-byte payload. C++20, zero-copy, trivially copyable
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <type_traits>

namespace websocket::msg {

// ============================================================================
// Enums
// ============================================================================

enum class EventType : uint8_t {
    BOOK_DELTA    = 0,
    BOOK_SNAPSHOT = 1,
    TRADE_ARRAY   = 2,
    SYSTEM_STATUS = 3,
    BBO_ARRAY     = 4,
    LIQUIDATION   = 5,
    MARK_PRICE    = 6,
};

enum class VenueId : uint8_t {
    UNKNOWN      = 0,
    BINANCE      = 1,
    OKX          = 2,
    BINANCE_USDM = 3,
};

enum class DeltaAction : uint8_t {
    NEW    = 0,
    UPDATE = 1,
    DELETE = 2,
};

enum class SystemStatusType : uint8_t {
    HEARTBEAT    = 0,
    DISCONNECTED = 1,
    RECONNECTED  = 2,
};

// ============================================================================
// Flag namespaces (bitsets)
// ============================================================================

namespace EventFlags {
    inline constexpr uint16_t SNAPSHOT      = 1 << 0;
    inline constexpr uint16_t CONTINUATION  = 1 << 1;  // not first in multi-event batch
    inline constexpr uint16_t LAST_IN_BATCH = 1 << 2;  // last in multi-event batch
    inline constexpr uint16_t DEPTH_CH_SHIFT = 3;
    inline constexpr uint16_t DEPTH_CH_MASK  = 0x0038;  // bits 3-5 (3 bits, 0-7)
    inline constexpr uint16_t EVT_TYPE_SHIFT = 6;
    inline constexpr uint16_t EVT_TYPE_MASK  = 0x01C0;  // bits 6-8 (3 bits, 0-7)
    inline constexpr uint16_t CONN_ID_SHIFT = 9;
    inline constexpr uint16_t CONN_ID_MASK  = 0xFE00;   // bits 9-15 (7 bits, 0-127)
}

static constexpr uint8_t MAX_DEPTH_CHANNELS = 8;  // bits 3-5 support 0-7

namespace DeltaFlags {
    inline constexpr uint8_t SIDE_ASK = 0x01;  // 0=bid, 1=ask
}

namespace TradeFlags {
    inline constexpr uint8_t IS_BUYER    = 0x01;
    inline constexpr uint8_t AUCTION     = 0x02;
    inline constexpr uint8_t SELF_TRADE  = 0x04;
    inline constexpr uint8_t LIQUIDATION = 0x08;
}

namespace LiqFlags {
    inline constexpr uint8_t SIDE_SELL = 0x01;  // 0=buy, 1=sell
}

// ============================================================================
// Payload entry types
// ============================================================================

struct DeltaEntry {
    int64_t price;      // price mantissa
    int64_t qty;        // qty mantissa (0 for DELETE)
    uint8_t action;     // DeltaAction
    uint8_t flags;      // DeltaFlags (bit0 = SIDE_ASK)
    uint8_t _pad[6];

    bool is_bid() const { return (flags & DeltaFlags::SIDE_ASK) == 0; }
    bool is_ask() const { return (flags & DeltaFlags::SIDE_ASK) != 0; }
};
static_assert(sizeof(DeltaEntry) == 24);

struct BookLevel {
    int64_t price;      // price mantissa
    int64_t qty;        // qty mantissa
};
static_assert(sizeof(BookLevel) == 16);

struct TradeEntry {
    int64_t price;          // price mantissa
    int64_t qty;            // qty mantissa
    int64_t trade_time_ns;  // per-trade exchange timestamp (ns)
    int64_t trade_id;       // exchange trade ID (0 = N/A)
    uint8_t flags;          // TradeFlags
    uint8_t _pad[7];

    bool is_buyer()      const { return flags & TradeFlags::IS_BUYER; }
    bool is_auction()    const { return flags & TradeFlags::AUCTION; }
    bool is_self_trade() const { return flags & TradeFlags::SELF_TRADE; }
    bool is_liquidation() const { return flags & TradeFlags::LIQUIDATION; }
};
static_assert(sizeof(TradeEntry) == 40);

struct BboEntry {
    int64_t bid_price;      // bid price mantissa
    int64_t bid_qty;        // bid qty mantissa
    int64_t ask_price;      // ask price mantissa
    int64_t ask_qty;        // ask qty mantissa
    int64_t event_time_ns;  // per-BBO exchange timestamp (ns)
    int64_t book_update_id; // exchange sequence
};
static_assert(sizeof(BboEntry) == 48);

struct LiquidationEntry {
    int64_t price;           // order price mantissa
    int64_t avg_price;       // average fill price mantissa
    int64_t orig_qty;        // original quantity mantissa
    int64_t filled_qty;      // accumulated filled quantity mantissa
    int64_t trade_time_ns;   // trade timestamp (ns)
    uint8_t flags;           // LiqFlags (SIDE_SELL=0x01)
    uint8_t _pad[7];
};
static_assert(sizeof(LiquidationEntry) == 48);

struct MarkPriceEntry {
    int64_t mark_price;      // mark price mantissa
    int64_t index_price;     // index price mantissa
    int64_t settle_price;    // est. settlement price mantissa
    int64_t funding_rate;    // funding rate mantissa (all digits, no dot)
    int64_t next_funding_ns; // next funding time (ns)
    uint8_t _pad[8];
};
static_assert(sizeof(MarkPriceEntry) == 48);

// ============================================================================
// Payload types (all exactly 480 bytes)
// ============================================================================

static constexpr size_t PAYLOAD_SIZE = 480;

// BOOK_DELTA: header.count = number of deltas (max 20)
static constexpr size_t MAX_DELTAS = PAYLOAD_SIZE / sizeof(DeltaEntry);  // 20

struct BookDeltaPayload {
    DeltaEntry entries[MAX_DELTAS];
};
static_assert(sizeof(BookDeltaPayload) == PAYLOAD_SIZE);

// BOOK_SNAPSHOT: header.count = bid_count, header.count2 = ask_count
// bids first (best→worst), then asks (best→worst)
static constexpr size_t MAX_BOOK_LEVELS = PAYLOAD_SIZE / sizeof(BookLevel);  // 30

struct BookSnapshotPayload {
    BookLevel levels[MAX_BOOK_LEVELS];
};
static_assert(sizeof(BookSnapshotPayload) == PAYLOAD_SIZE);

// TRADE_ARRAY: header.count = number of trades (max 12)
static constexpr size_t MAX_TRADES = PAYLOAD_SIZE / sizeof(TradeEntry);  // 12

struct TradeArrayPayload {
    TradeEntry entries[MAX_TRADES];
};
static_assert(sizeof(TradeArrayPayload) == PAYLOAD_SIZE);

// BBO: header.count = number of BBOs (max 10)
static constexpr size_t MAX_BBOS = PAYLOAD_SIZE / sizeof(BboEntry);  // 10

struct BboArrayPayload {
    BboEntry entries[MAX_BBOS];
};
static_assert(sizeof(BboArrayPayload) == PAYLOAD_SIZE);

// LIQUIDATION: header.count = number of liquidation orders (max 10)
static constexpr size_t MAX_LIQUIDATIONS = PAYLOAD_SIZE / sizeof(LiquidationEntry);  // 10

struct LiquidationPayload {
    LiquidationEntry entries[MAX_LIQUIDATIONS];
};
static_assert(sizeof(LiquidationPayload) == PAYLOAD_SIZE);

// MARK_PRICE: header.count = number of mark price updates (max 10)
static constexpr size_t MAX_MARK_PRICES = PAYLOAD_SIZE / sizeof(MarkPriceEntry);  // 10

struct MarkPricePayload {
    MarkPriceEntry entries[MAX_MARK_PRICES];
};
static_assert(sizeof(MarkPricePayload) == PAYLOAD_SIZE);

// SYSTEM_STATUS: header.count = 0
struct SystemStatusPayload {
    uint8_t  status_type;      // SystemStatusType
    uint8_t  connection_id;    // 0=A, 1=B
    uint8_t  _pad[6];
    int64_t  detail_code;      // status-specific code
    char     message[464];     // null-terminated status text
};
static_assert(sizeof(SystemStatusPayload) == PAYLOAD_SIZE);

// ============================================================================
// MktEvent — 512 bytes, alignas(512)
// ============================================================================

struct alignas(512) MktEvent {
    // --- Header (32 bytes, offset 0-31) ---
    uint16_t venue_instrument;       // [15:12]=venue_id (4b) [11:0]=instrument_id (12b)
    uint16_t flags;                  // EventFlags: [2:0] snap/cont/last [5:3] depth_ch [8:6] event_type [15:9] conn_id
    uint8_t  count;                  // primary count (deltas/trades/bid_levels)
    uint8_t  count2;                 // BOOK_SNAPSHOT: ask_level_count | BOOK_DELTA/TRADE: flush_index (0-based)
    uint16_t recv_local_latency_ns;  // min(recv_ts - nic_ts, 65535), 0 = none
    int64_t  src_seq;                // exchange sequence number
    int64_t  nic_ts_ns;              // NIC HW receive timestamp (ns, CLOCK_REALTIME)
    int64_t  event_ts_ns;            // exchange event timestamp (ns)

    // --- Payload (480 bytes, offset 32-511) ---
    union {
        BookDeltaPayload    deltas;
        BookSnapshotPayload snapshot;
        TradeArrayPayload   trades;
        BboArrayPayload     bbo_array;
        SystemStatusPayload status;
        LiquidationPayload  liquidations;
        MarkPricePayload    mark_prices;
    } payload;

    // ========================================================================
    // Packed field accessors
    // ========================================================================

    uint8_t event_type() const {
        return (flags & EventFlags::EVT_TYPE_MASK) >> EventFlags::EVT_TYPE_SHIFT;
    }
    void set_event_type(uint8_t t) {
        flags = (flags & ~EventFlags::EVT_TYPE_MASK) |
                (static_cast<uint16_t>(t) << EventFlags::EVT_TYPE_SHIFT);
    }

    uint8_t venue_id() const { return venue_instrument >> 12; }
    void set_venue_id(uint8_t v) {
        venue_instrument = (venue_instrument & 0x0FFF) | (static_cast<uint16_t>(v) << 12);
    }

    uint16_t instrument_id() const { return venue_instrument & 0x0FFF; }
    void set_instrument_id(uint16_t id) {
        venue_instrument = (venue_instrument & 0xF000) | (id & 0x0FFF);
    }

    int64_t recv_ts_ns() const { return nic_ts_ns + recv_local_latency_ns; }

    // ========================================================================
    // Type queries
    // ========================================================================

    bool is_book_delta()    const { return event_type() == static_cast<uint8_t>(EventType::BOOK_DELTA); }
    bool is_book_snapshot() const { return event_type() == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT); }
    bool is_trade_array()   const { return event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY); }
    bool is_system_status() const { return event_type() == static_cast<uint8_t>(EventType::SYSTEM_STATUS); }
    bool is_bbo_array()   const { return event_type() == static_cast<uint8_t>(EventType::BBO_ARRAY); }
    bool is_liquidation() const { return event_type() == static_cast<uint8_t>(EventType::LIQUIDATION); }
    bool is_mark_price()  const { return event_type() == static_cast<uint8_t>(EventType::MARK_PRICE); }

    // ========================================================================
    // Event flag queries
    // ========================================================================

    bool is_snapshot()      const { return flags & EventFlags::SNAPSHOT; }
    bool is_continuation()  const { return flags & EventFlags::CONTINUATION; }
    bool is_last_in_batch() const { return flags & EventFlags::LAST_IN_BATCH; }

    uint8_t connection_id() const {
        return static_cast<uint8_t>((flags & EventFlags::CONN_ID_MASK) >> EventFlags::CONN_ID_SHIFT);
    }
    void set_connection_id(uint8_t ci) {
        flags = (flags & ~EventFlags::CONN_ID_MASK) | (static_cast<uint16_t>(ci) << EventFlags::CONN_ID_SHIFT);
    }

    uint8_t depth_channel() const {
        return static_cast<uint8_t>((flags & EventFlags::DEPTH_CH_MASK) >> EventFlags::DEPTH_CH_SHIFT);
    }
    void set_depth_channel(uint8_t ch) {
        flags = (flags & ~EventFlags::DEPTH_CH_MASK) | (static_cast<uint16_t>(ch) << EventFlags::DEPTH_CH_SHIFT);
    }

    uint8_t flush_index() const { return count2; }       // delta/trade: 0-based chunk index
    uint8_t ask_level_count() const { return count2; }   // snapshot: ask level count

    // ========================================================================
    // Snapshot accessors — return {pointer, count} for bids/asks
    // Bids: levels[0..count-1], Asks: levels[count..count+count2-1]
    // ========================================================================

    struct Span {
        const BookLevel* data;
        uint8_t count;
    };

    Span bids() const {
        return { payload.snapshot.levels, count };
    }

    Span asks() const {
        return { payload.snapshot.levels + count, count2 };
    }

    struct BboSpan {
        const BboEntry* data;
        uint8_t count;
    };
    BboSpan bbo_entries() const {
        return { payload.bbo_array.entries, count };
    }

    // ========================================================================
    // Print — dim MKT line aligned with WSFrameInfo::print_timeline() tail
    // Σ = total latency: NIC/BPF arrival to event publish
    // ========================================================================

    void print(int padding = 101) const {
        if (is_system_status()) {
            const char* st_name =
                payload.status.status_type == 0 ? "HEARTBEAT" :
                payload.status.status_type == 1 ? "DISCONNECTED" :
                payload.status.status_type == 2 ? "RECONNECTED" : "UNKNOWN";
            std::fprintf(stderr,
                "\033[2m%*s  STATUS %s conn=%u %s\033[0m\n",
                padding, "", st_name, payload.status.connection_id,
                payload.status.message);
            return;
        }

        char mkt_cnt[4] = "";
        char mkt_typ[4] = "";
        switch (event_type()) {
        case 0: {
            std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count);
            std::snprintf(mkt_typ, sizeof(mkt_typ), "D%u", depth_channel());
            break;
        }
        case 1: std::snprintf(mkt_typ, sizeof(mkt_typ), "OB"); break;
        case 2: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Td"); break;
        case 4: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Bo"); break;
        case 5: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Lq"); break;
        case 6: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Mp"); break;
        }

        char lat[16] = "     -";
        if (nic_ts_ns > 0 && recv_local_latency_ns > 0) {
            double us = static_cast<double>(recv_local_latency_ns) / 1000.0;
            double a = std::fabs(us);
            if (a < 1000.0)         std::snprintf(lat, 16, a >= 100.0 ? "%4.0fus" : "%4.1fus", us);
            else if (a < 1000000.0) { double v = us / 1000.0; std::snprintf(lat, 16, std::fabs(v) >= 100.0 ? "%4.0fms" : "%4.1fms", v); }
            else                    std::snprintf(lat, 16, "%4.2fs", us / 1000000.0);
        }

        int64_t server_ms = 0;
        int64_t recv = recv_ts_ns();
        if (event_ts_ns > 0 && recv > 0)
            server_ms = (recv - event_ts_ns) / 1000000;

        char flush_id[20] = "";
        {
            uint8_t ci = connection_id();
            char cc = (ci < 10) ? ('0' + ci) : ('a' + ci - 10);
            if (event_type() == 0)
                std::snprintf(flush_id, sizeof(flush_id), "  %c %s ID %3u ",
                              cc, is_last_in_batch() ? "last" : "    ", count2);
            else
                std::snprintf(flush_id, sizeof(flush_id), "  %c             ", cc);
        }

        std::fprintf(stderr,
                "\033[2m%*s%s %3s %-2s \xce\xa3%6s   %+ldms #%ld\033[0m\n",
                padding - static_cast<int>(std::strlen(flush_id)), "",
                flush_id, mkt_cnt, mkt_typ, lat, server_ms, src_seq);
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    void clear() { std::memset(this, 0, sizeof(*this)); }
};

// ============================================================================
// Static asserts — layout verification
// ============================================================================

static_assert(sizeof(MktEvent) == 512, "MktEvent must be 512 bytes");
static_assert(alignof(MktEvent) == 512, "MktEvent must be 512-byte aligned");

static_assert(offsetof(MktEvent, src_seq) == 8);
static_assert(offsetof(MktEvent, nic_ts_ns) == 16);
static_assert(offsetof(MktEvent, event_ts_ns) == 24);
static_assert(offsetof(MktEvent, payload) == 32);

static_assert(std::is_trivially_copyable_v<MktEvent>);
static_assert(std::is_standard_layout_v<MktEvent>);

static_assert(std::is_trivially_copyable_v<DeltaEntry>);
static_assert(std::is_trivially_copyable_v<BookLevel>);
static_assert(std::is_trivially_copyable_v<TradeEntry>);
static_assert(std::is_trivially_copyable_v<BboEntry>);
static_assert(std::is_trivially_copyable_v<LiquidationEntry>);
static_assert(std::is_trivially_copyable_v<MarkPriceEntry>);

}  // namespace websocket::msg
