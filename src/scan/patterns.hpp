// SPDX-License-Identifier: GPL-3.0-or-later
// Token -> search patterns in every encoding of FR-032. Own encoders: nothing
// here is shared with the anonymiser.
#pragma once

#include "mcxanon/scan.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mcxanon::scan::detail {

struct Pattern {
  std::vector<std::uint8_t> bytes;  // lowercase when fold is set
  std::string encoding;
  bool fold = false;          // ASCII case-insensitive
  bool short_binary = false;  // binary form shorter than 6 bytes (FR-032a)
  std::uint32_t token = 0;    // index of the token
  bool digits = false;        // matches only when not adjacent to a decimal digit
};

inline constexpr std::size_t kMinPattern = 4;

// Expands one token; `scannable` is false when no pattern of at least 4 bytes exists.
std::vector<Pattern> expand(const Token& token, std::uint32_t index, bool& scannable);

std::string format_ipv4(const std::uint8_t* a);
std::string format_ipv6(const std::uint8_t* a);  // RFC 5952

}  // namespace mcxanon::scan::detail
