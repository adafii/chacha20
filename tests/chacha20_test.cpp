#include "operations.h"
#include <gtest/gtest.h>

TEST(Operations, CreateInitialState) {
    constexpr auto key = std::bit_cast<std::array<const uint32_t, 8>, std::array<const uint8_t, 32>>(
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});

    constexpr uint32_t counter = 1;
    constexpr auto nonce = std::bit_cast<std::array<const uint32_t, 3>, std::array<const uint8_t, 12>>(
        {0x00, 0x00, 0x00, 0x09,
         0x00, 0x00, 0x00, 0x4a,
         0x00, 0x00, 0x00, 0x00});

    auto output = std::array<uint32_t, 16>{};
    chacha20::operations::create_initial_state(key, counter, nonce, output);

    auto expected_output = std::array<uint32_t, 16>{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                                    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                                    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                                    0x00000001, 0x09000000, 0x4a000000, 0x00000000};

    ASSERT_EQ(output, expected_output);
}

TEST(Operations, QuarterRound) {
    auto input = std::array<uint32_t, 16>{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
    auto expected_output = std::array<uint32_t, 16>{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb};

    chacha20::operations::quarter_round(input, 0, 1, 2, 3);
    ASSERT_EQ(input, expected_output);
}

TEST(Operations, ChaChaBlock) {
    constexpr auto input = std::array<const uint32_t, 16>{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                                          0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                                                          0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                                                          0x00000001, 0x09000000, 0x4a000000, 0x00000000};

    constexpr auto expected_output = std::array<uint32_t, 16>{0x10f1e7e4, 0xd13b5915, 0x500fdd1f, 0xa32071c4,
                                                              0xc7d1f4c7, 0x33c06803, 0x0422aa9a, 0xc3d46c4e,
                                                              0xd2826446, 0x079faa09, 0x14c2d705, 0xd98b02a2,
                                                              0xb5129cd1, 0xde164eb9, 0xcbd083e8, 0xa2503c4e};

    auto output = std::array<uint32_t, 16>{};
    chacha20::operations::chacha20_block(input, output);

    ASSERT_EQ(output, expected_output);
}