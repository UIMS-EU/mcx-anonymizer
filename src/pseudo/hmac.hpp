// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pseudonym candidates: HMAC-SHA-256 keyed by the project secret.
#pragma once

#include "bytes/bytes.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace mcxanon {

using Secret = std::array<std::uint8_t, 32>;
using Digest32 = std::array<std::uint8_t, 32>;

Digest32 hmac_sha256(ByteView key, ByteView data);

// "mcxanon/v1" 0x00 category 0x00 original counter_be32
Bytes derivation_message(std::string_view category, ByteView original, std::uint32_t counter);
Digest32 derive(const Secret& secret, std::string_view category, ByteView original,
                std::uint32_t counter);

}  // namespace mcxanon
