#pragma once
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <ranges>

namespace chacha20::operations {

using chacha20_t = uint32_t;

using chacha20_state_t = std::array<chacha20_t, 512 / 32>;
using chacha20_constant_t = std::array<chacha20_t, 128 / 32>;
using chacha20_key_t = std::array<chacha20_t, 256 / 32>;
using chacha20_counter_t = chacha20_t;
using chacha20_nonce_t = std::array<chacha20_t, 96 / 32>;

constexpr auto get_position = [] [[nodiscard]] (auto position) consteval {
    return [position] [[nodiscard]] (auto& state) constexpr { return std::ranges::next(state.begin(), position); };
};

constexpr auto constant_position = get_position(0);
constexpr auto key_position = get_position(4);
constexpr auto counter_position = 12;
constexpr auto nonce_position = get_position(13);
constexpr auto chacha20_constant = chacha20_constant_t{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

[[nodiscard]] constexpr chacha20_state_t create_initial_state(const chacha20_key_t& key, chacha20_counter_t counter, const chacha20_nonce_t& nonce) {
    chacha20_state_t state;

    std::ranges::copy(chacha20_constant, constant_position(state));
    std::ranges::transform(key, key_position(state), std::byteswap<chacha20_t>);
    state[counter_position] = counter;
    std::ranges::transform(nonce, nonce_position(state), std::byteswap<chacha20_t>);

    return state;
}

constexpr void quarter_round(chacha20_state_t& state, size_t a, size_t b, size_t c, size_t d) {
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

[[nodiscard]] constexpr chacha20_state_t chacha20_block(const chacha20_state_t& in_state) {
    auto out_state = chacha20_state_t{in_state};

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

    std::ranges::transform(in_state, out_state, out_state.begin(), [](auto in, auto out) constexpr { return std::byteswap<chacha20_t>(in + out); });
    return out_state;
}

}  // namespace chacha20::operations