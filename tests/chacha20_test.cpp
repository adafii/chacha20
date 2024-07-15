#include "chacha20.h"
#include <gtest/gtest.h>

TEST(ChaCha20, QuarterRound) {
    auto test = std::array<uint32_t, 4>{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
    auto expected = std::array<uint32_t, 4>{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb};
    auto result = chacha20::quarter_round(test);
    
    ASSERT_EQ(result, expected);
}
