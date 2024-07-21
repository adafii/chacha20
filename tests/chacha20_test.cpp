#include "operations.h"
#include <gtest/gtest.h>

TEST(Operations, CreateInitialState) {
    using chacha20::operations::chacha20_counter_t;
    using chacha20::operations::chacha20_key_t;
    using chacha20::operations::chacha20_nonce_t;
    using chacha20::operations::chacha20_state_t;

    constexpr auto key = chacha20_key_t{0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                        0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f};
    constexpr auto counter = chacha20_counter_t{1};
    constexpr auto nonce = chacha20_nonce_t{0x00000009, 0x0000004a, 0x00000000};

    auto state = chacha20::operations::create_initial_state(key, counter, nonce);

    auto expected_output = chacha20_state_t{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                            0x00000001, 0x09000000, 0x4a000000, 0x00000000};

    ASSERT_EQ(state, expected_output);
}

TEST(Operations, QuarterRound) {
    auto input = std::array<uint32_t, 16>{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
    auto expected_output = std::array<uint32_t, 16>{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb};

    chacha20::operations::quarter_round(input, 0, 1, 2, 3);
    ASSERT_EQ(input, expected_output);
}

TEST(Operations, ChaChaBlock) {
    using chacha20::operations::chacha20_state_t;

    auto input = chacha20_state_t{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                  0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                  0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                  0x00000001, 0x09000000, 0x4a000000, 0x00000000};

    auto expected_output = chacha20_state_t{0x10f1e7e4, 0xd13b5915, 0x500fdd1f, 0xa32071c4,
                                            0xc7d1f4c7, 0x33c06803, 0x0422aa9a, 0xc3d46c4e,
                                            0xd2826446, 0x079faa09, 0x14c2d705, 0xd98b02a2,
                                            0xb5129cd1, 0xde164eb9, 0xcbd083e8, 0xa2503c4e};

    auto output = chacha20::operations::chacha20_block(input);

    ASSERT_EQ(output, expected_output);
}