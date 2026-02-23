// msg/stream_decoder.hpp
// StreamDecoderPolicy concept for policy-based two-step decode:
//   1. decode_essential() — extract message type + sequence from raw bytes (fast)
//   2. Full decode — only if sequence is fresh (caller decides)
#pragma once

#include <cstdint>
#include <concepts>

namespace websocket::msg {

template<typename T>
concept StreamDecoderPolicy = requires {
    typename T::Essential;
} && requires(const uint8_t* payload, uint32_t len) {
    { T::decode_essential(payload, len) } -> std::same_as<typename T::Essential>;
} && requires(const typename T::Essential& e) {
    { e.msg_type } -> std::convertible_to<uint16_t>;
    { e.sequence } -> std::convertible_to<int64_t>;
    { e.valid } -> std::convertible_to<bool>;
};

}  // namespace websocket::msg
