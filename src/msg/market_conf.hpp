// msg/market_conf.hpp
// Per-market fixed scale factors for mantissa normalization to exponent -8
#pragma once
#include <cstdint>

namespace websocket::market {

// Binance SPOT (SBE binary) — mantissa arrives at exponent -8 from wire
struct BinanceSpot {
    static constexpr int8_t  price_exp   = -8;
    static constexpr int8_t  qty_exp     = -8;
    static constexpr int64_t price_scale = 1;   // already normalized
    static constexpr int64_t qty_scale   = 1;
};

// Binance USD-M Futures (JSON) — BTCUSDT: price 2 dec, qty 3 dec
// Scale = 10^(8 - decimal_places) to normalize to exponent -8
struct BinanceUSDM {
    static constexpr int8_t  price_exp   = -8;
    static constexpr int8_t  qty_exp     = -8;

    struct BTCUSDT {
        // Trade/depth/forceOrder: 2dp price, 3dp qty
        static constexpr int64_t price_scale = 1000000;   // 10^(8-2)
        static constexpr int64_t qty_scale   = 100000;    // 10^(8-3)
        // markPriceUpdate: 8dp prices — already at exp -8
        static constexpr int64_t mp_price_scale = 1;      // 10^(8-8)
        static constexpr int64_t mp_rate_scale  = 1;      // 10^(8-8)
    };

    // Default (backward compat) — uses BTCUSDT config
    static constexpr int64_t price_scale = BTCUSDT::price_scale;
    static constexpr int64_t qty_scale   = BTCUSDT::qty_scale;
};

}  // namespace websocket::market
