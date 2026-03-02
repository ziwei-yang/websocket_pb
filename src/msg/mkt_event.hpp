// msg/mkt_event.hpp
// Fixed-size market data event for disruptor ring IPC
// 512 bytes aligned — fits depth10 snapshots, 11 trades, 19 deltas per event
// C++20, zero-copy, trivially copyable
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
};

enum class VenueId : uint8_t {
    UNKNOWN  = 0,
    BINANCE  = 1,
    OKX      = 2,
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
}

namespace DeltaFlags {
    inline constexpr uint8_t SIDE_ASK = 0x01;  // 0=bid, 1=ask
}

namespace TradeFlags {
    inline constexpr uint8_t IS_BUYER    = 0x01;
    inline constexpr uint8_t AUCTION     = 0x02;
    inline constexpr uint8_t SELF_TRADE  = 0x04;
    inline constexpr uint8_t LIQUIDATION = 0x08;
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

// ============================================================================
// Payload types (all exactly 472 bytes)
// ============================================================================

static constexpr size_t PAYLOAD_SIZE = 472;

// BOOK_DELTA: header.count = number of deltas (max 19)
static constexpr size_t MAX_DELTAS = PAYLOAD_SIZE / sizeof(DeltaEntry);  // 19

struct BookDeltaPayload {
    DeltaEntry entries[MAX_DELTAS];
    uint8_t _pad[PAYLOAD_SIZE - MAX_DELTAS * sizeof(DeltaEntry)];
};
static_assert(sizeof(BookDeltaPayload) == PAYLOAD_SIZE);

// BOOK_SNAPSHOT: header.count = bid_count, header.count2 = ask_count
// bids first (best→worst), then asks (best→worst)
static constexpr size_t MAX_BOOK_LEVELS = PAYLOAD_SIZE / sizeof(BookLevel);  // 29

struct BookSnapshotPayload {
    BookLevel levels[MAX_BOOK_LEVELS];
    uint8_t _pad[PAYLOAD_SIZE - MAX_BOOK_LEVELS * sizeof(BookLevel)];
};
static_assert(sizeof(BookSnapshotPayload) == PAYLOAD_SIZE);

// TRADE_ARRAY: header.count = number of trades (max 11)
static constexpr size_t MAX_TRADES = PAYLOAD_SIZE / sizeof(TradeEntry);  // 11

struct TradeArrayPayload {
    TradeEntry entries[MAX_TRADES];
    uint8_t _pad[PAYLOAD_SIZE - MAX_TRADES * sizeof(TradeEntry)];
};
static_assert(sizeof(TradeArrayPayload) == PAYLOAD_SIZE);

// BBO: header.count = number of BBOs (max 9)
static constexpr size_t MAX_BBOS = PAYLOAD_SIZE / sizeof(BboEntry);  // 9

struct BboArrayPayload {
    BboEntry entries[MAX_BBOS];
    uint8_t _pad[PAYLOAD_SIZE - MAX_BBOS * sizeof(BboEntry)];
};
static_assert(sizeof(BboArrayPayload) == PAYLOAD_SIZE);

// SYSTEM_STATUS: header.count = 0
struct SystemStatusPayload {
    uint8_t  status_type;      // SystemStatusType
    uint8_t  connection_id;    // 0=A, 1=B
    uint8_t  _pad[6];
    int64_t  detail_code;      // status-specific code
    char     message[456];     // null-terminated status text
};
static_assert(sizeof(SystemStatusPayload) == PAYLOAD_SIZE);

// ============================================================================
// MktEvent — 512 bytes, alignas(512)
// ============================================================================

struct alignas(512) MktEvent {
    // --- Header (40 bytes, offset 0-39) ---
    uint8_t  event_type;       // EventType enum
    uint8_t  venue_id;         // VenueId enum
    uint16_t instrument_id;    // pair index (externally mapped)
    uint16_t flags;            // EventFlags bitset
    uint8_t  count;            // primary count (deltas/trades/bid_levels)
    uint8_t  count2;           // secondary count (ask_levels for snapshot, else 0)
    int64_t  src_seq;          // exchange sequence number
    int64_t  recv_ts_ns;       // local receive timestamp (ns)
    int64_t  event_ts_ns;      // exchange event timestamp (ns)
    int64_t  nic_ts_ns;        // NIC HW receive timestamp (ns, CLOCK_REALTIME)

    // --- Payload (472 bytes, offset 40-511) ---
    union {
        BookDeltaPayload    deltas;
        BookSnapshotPayload snapshot;
        TradeArrayPayload   trades;
        BboArrayPayload     bbo_array;
        SystemStatusPayload status;
    } payload;

    // ========================================================================
    // Type queries
    // ========================================================================

    bool is_book_delta()    const { return event_type == static_cast<uint8_t>(EventType::BOOK_DELTA); }
    bool is_book_snapshot() const { return event_type == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT); }
    bool is_trade_array()   const { return event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY); }
    bool is_system_status() const { return event_type == static_cast<uint8_t>(EventType::SYSTEM_STATUS); }
    bool is_bbo_array()   const { return event_type == static_cast<uint8_t>(EventType::BBO_ARRAY); }

    // ========================================================================
    // Event flag queries
    // ========================================================================

    bool is_snapshot()      const { return flags & EventFlags::SNAPSHOT; }
    bool is_continuation()  const { return flags & EventFlags::CONTINUATION; }
    bool is_last_in_batch() const { return flags & EventFlags::LAST_IN_BATCH; }

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

    void print(int padding = 93) const {
        if (is_system_status()) {
            const char* st_name =
                payload.status.status_type == 0 ? "HEARTBEAT" :
                payload.status.status_type == 1 ? "DISCONNECTED" :
                payload.status.status_type == 2 ? "RECONNECTED" : "UNKNOWN";
            std::fprintf(stderr,
                "\033[2m%*s| STATUS %s conn=%u %s\033[0m\n",
                padding, "", st_name, payload.status.connection_id,
                payload.status.message);
            return;
        }

        char mkt_cnt[4] = "";
        char mkt_typ[4] = "";
        switch (event_type) {
        case 0: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Dp"); break;
        case 1: std::snprintf(mkt_typ, sizeof(mkt_typ), "OB"); break;
        case 2: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Td"); break;
        case 4: std::snprintf(mkt_cnt, sizeof(mkt_cnt), "%u", count); std::snprintf(mkt_typ, sizeof(mkt_typ), "Bo"); break;
        }

        char lat[16] = "     -";
        if (nic_ts_ns > 0 && recv_ts_ns > nic_ts_ns) {
            double us = static_cast<double>(recv_ts_ns - nic_ts_ns) / 1000.0;
            double a = std::fabs(us);
            if (a < 1000.0)         std::snprintf(lat, 16, a >= 100.0 ? "%4.0fus" : "%4.1fus", us);
            else if (a < 1000000.0) { double v = us / 1000.0; std::snprintf(lat, 16, std::fabs(v) >= 100.0 ? "%4.0fms" : "%4.1fms", v); }
            else                    std::snprintf(lat, 16, "%4.2fs", us / 1000000.0);
        }

        int64_t server_ms = 0;
        if (event_ts_ns > 0 && recv_ts_ns > 0)
            server_ms = (recv_ts_ns - event_ts_ns) / 1000000;

        std::fprintf(stderr,
                "\033[2m%*s| %2s %-2s \xce\xa3%6s | %+ldms | seq %ld\033[0m\n",
                padding, "", mkt_cnt, mkt_typ, lat, server_ms, src_seq);
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
static_assert(offsetof(MktEvent, recv_ts_ns) == 16);
static_assert(offsetof(MktEvent, event_ts_ns) == 24);
static_assert(offsetof(MktEvent, nic_ts_ns) == 32);
static_assert(offsetof(MktEvent, payload) == 40);

static_assert(std::is_trivially_copyable_v<MktEvent>);
static_assert(std::is_standard_layout_v<MktEvent>);

static_assert(std::is_trivially_copyable_v<DeltaEntry>);
static_assert(std::is_trivially_copyable_v<BookLevel>);
static_assert(std::is_trivially_copyable_v<TradeEntry>);
static_assert(std::is_trivially_copyable_v<BboEntry>);

}  // namespace websocket::msg
