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
    static constexpr int64_t price_scale = 1000000;   // 10^(8-2) = 10^6
    static constexpr int64_t qty_scale   = 100000;    // 10^(8-3) = 10^5
};

}  // namespace websocket::market
