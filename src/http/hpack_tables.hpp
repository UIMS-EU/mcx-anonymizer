// SPDX-License-Identifier: GPL-3.0-or-later
//
// The HPACK static table and Huffman code (RFC 7541 Appendices A and B), generated into
// hpack_tables.cpp from the RFC text.
#pragma once

#include <cstdint>
#include <string_view>

namespace mcxanon::http {

struct StaticEntry {
  std::string_view name;
  std::string_view value;
};
struct HuffmanCode {
  std::uint32_t code;  // right-aligned
  std::uint8_t bits;
};

extern const StaticEntry kStaticTable[61];   // index 1..61 at [0..60]
extern const HuffmanCode kHuffman[257];      // symbols 0..255 and EOS (256)

}  // namespace mcxanon::http
