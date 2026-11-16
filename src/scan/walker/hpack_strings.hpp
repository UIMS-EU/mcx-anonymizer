// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own HPACK string reader (feature 007): the literal field
// representations of a header block (RFC 7541 §6.2) with Huffman-coded strings decoded by its own
// copy of the Appendix B code. No dynamic table: a name indexed from it is reported empty. Shares
// no code with the anonymiser.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon::scan::detail {

struct StaticEntry {
  std::string_view name;
  std::string_view value;
};
struct HuffmanCode {
  std::uint32_t code;
  std::uint8_t bits;
};
extern const StaticEntry kStaticTable[61];
extern const HuffmanCode kHuffman[257];

std::optional<std::string> hpack_huffman(std::string_view s);

struct HpackLiteral {
  std::string name;   // empty when indexed from the dynamic table
  std::string value;
  bool huffman = false;  // the value was Huffman-coded in the block
};
// Every literal of a block, as far as it parses; stops at the first representation it cannot read.
std::vector<HpackLiteral> hpack_literals(std::string_view block);

}  // namespace mcxanon::scan::detail
