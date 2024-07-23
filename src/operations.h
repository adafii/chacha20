#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace chacha20::operations {

using chacha20_out_state_t = std::span<uint32_t, 16>;
using chacha20_in_state_t = std::span<const uint32_t, 16>;
using chacha20_key_t = std::span<const uint32_t, 8>;
using chacha20_counter_t = uint32_t;
using chacha20_nonce_t = std::array<const uint32_t, 3>;

constexpr auto chacha20_constant = std::array<uint32_t, 4>{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

constexpr auto constant_position = 0;
constexpr auto key_position = 4;
constexpr auto counter_position = 12;
constexpr auto nonce_position = 13;

constexpr void create_initial_state(chacha20_key_t key, chacha20_counter_t counter, chacha20_nonce_t nonce, chacha20_out_state_t out_state) {
    std::ranges::copy(chacha20_constant, std::ranges::next(out_state.begin(), constant_position));
    std::ranges::copy(key, std::ranges::next(out_state.begin(), key_position));
    out_state[counter_position] = counter;
    std::ranges::copy(nonce, std::ranges::next(out_state.begin(), nonce_position));
}

constexpr void quarter_round(chacha20_out_state_t state, size_t a, size_t b, size_t c, size_t d) {
    constexpr auto round = [](auto& op1, auto& op2, auto& op3, auto rotation) constexpr {
        op1 += op2;
        op3 ^= op1;
        op3 = std::rotl(op3, rotation);
    };

    round(state[a], state[b], state[d], 16);
    round(state[c], state[d], state[b], 12);
    round(state[a], state[b], state[d], 8);
    round(state[c], state[d], state[b], 7);
}

constexpr void chacha20_block(chacha20_in_state_t in_state, chacha20_out_state_t out_state) {
    std::ranges::copy(in_state, out_state.begin());

    for (auto i = 0; i < 10; ++i) {
        quarter_round(out_state, 0, 4, 8, 12);
        quarter_round(out_state, 1, 5, 9, 13);
        quarter_round(out_state, 2, 6, 10, 14);
        quarter_round(out_state, 3, 7, 11, 15);

        quarter_round(out_state, 0, 5, 10, 15);
        quarter_round(out_state, 1, 6, 11, 12);
        quarter_round(out_state, 2, 7, 8, 13);
        quarter_round(out_state, 3, 4, 9, 14);
    }

    std::ranges::transform(in_state, out_state, out_state.begin(), [](auto in, auto out) constexpr { return std::byteswap<uint32_t>(in + out); });
}

}  // namespace chacha20::operations