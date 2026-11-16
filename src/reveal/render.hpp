// SPDX-License-Identifier: GPL-3.0-or-later
//
// Writing an original in the textual style of the matched pseudonym (FR-014).
#pragma once

#include "bytes/bytes.hpp"
#include "pseudo/ranges.hpp"
#include "reveal/index.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace mcxanon::reveal {

struct Ipv6Style {
  bool compressed = false;  // "::" used
  bool full = false;        // every group written with 4 digits
  bool upper = false;       // upper-case hex letters
  bool dotted = false;      // the last 32 bits as dotted IPv4
};

// RFC 5952 §4.2 compression when `compressed`; otherwise all eight groups.
std::string format_ipv6(ByteView a, const Ipv6Style& st);

// Parsers shared by the recognisers and lookup: a dotted IPv4 address starting at t[i]
// (j receives the end), and a whole IPv6 token in any RFC 4291 §2.2 text form.
bool parse_ipv4(std::string_view t, std::size_t i, std::size_t& j, std::array<std::uint8_t, 4>& a);
bool parse_ipv6(std::string_view tok, Ipv6& a, Ipv6Style& st);

// Upper case when the text has upper-case letters and no lower-case ones.
bool all_upper(std::string_view s);
std::string upper(std::string_view s);

// `v` in hex with at least `width` digits (zero-padded), in the given case.
std::string hex_width(std::uint64_t v, std::size_t width, bool upper_case);

// The escape layer (FR-011, P4): the original is re-encoded with the scheme of the match.
// `escaped` holds, for every byte value, the escape text the match used for it (empty when the
// match did not escape it).
struct EscapeStyle {
  Escape scheme = Escape::none;
  std::string escaped[256];
  bool lower_hex = false;  // percent-escapes of the match used lower-case hex digits
};
std::string encode_like(std::string_view original, const EscapeStyle& st);

}  // namespace mcxanon::reveal
