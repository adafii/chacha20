#pragma once
#include <array>
#include <cstdint>

namespace chacha20 {

std::array<uint32_t, 4> quarter_round(std::array<uint32_t, 4> input);

}
