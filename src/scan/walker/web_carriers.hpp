// SPDX-License-Identifier: GPL-3.0-or-later
//
// The web carriers of an output payload, located and decoded by the scanner itself (feature 007,
// FR-024): JWT header and claim segments (base64url) and Huffman-coded HPACK
// strings of h2 header blocks. The anonymiser never writes Huffman strings; an original inside
// one (or inside a JWT segment) is a hit at the carrier's offset. Shares no code with the
// anonymiser.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mcxanon::scan::detail {

struct WebCarrierSpan {
  std::size_t offset = 0;
  std::size_t length = 0;
  std::string carrier;  // jwt, hpack
  std::vector<std::uint8_t> decoded;
};

std::vector<WebCarrierSpan> find_web_carriers(std::span<const std::uint8_t> payload);

}  // namespace mcxanon::scan::detail
