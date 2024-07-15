#include <array>
#include <cstdint>
#include <print>

namespace chacha20 {

constexpr uint32_t left_rotation(uint32_t input, uint8_t bits) {
    return (input << bits) | (input >> (32 - bits));
}

std::array<uint32_t, 4> quarter_round(std::array<uint32_t, 4> input) {
    auto& [a, b, c, d] = input;

    a += b;
    d ^= a;
    d = left_rotation(d, 16);

    c += d;
    b ^= c;
    b = left_rotation(b, 12);

    a += b;
    d ^= a;
    d = left_rotation(d, 8);

    c += d;
    b ^= c;
    b = left_rotation(b, 7);

    return {a, b, c, d};
}

}  // namespace chacha20
