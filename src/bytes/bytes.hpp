// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace mcxanon {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;
using MutByteView = std::span<std::uint8_t>;

}  // namespace mcxanon
