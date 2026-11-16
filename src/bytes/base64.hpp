// SPDX-License-Identifier: GPL-3.0-or-later
//
// Strict base64 (RFC 4648 §4, and the URL-safe alphabet of §5) for the MIKEY carriers of feature
// 005. Decoding accepts only the alphabet, correct padding (optional for the URL-safe
// alphabet), zero pad bits and line breaks (CRLF or LF) between lines of equal length; it records
// the layout so that `encode` reproduces the same text for the same bytes. The scanner keeps its
// own encoder.
#pragma once

#include "bytes/bytes.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::base64 {

enum class Alphabet { standard, url };

struct Layout {
  std::size_t line = 0;      // characters per line; 0 = one line
  bool crlf = true;          // line break CRLF (true) or LF
  bool final_break = false;  // the text ends with a line break
  bool padded = true;        // '=' padding present
};

struct Decoded {
  Bytes bytes;
  Layout layout;
};

std::optional<Decoded> decode(std::string_view text, Alphabet a = Alphabet::standard);
std::string encode(ByteView b, const Layout& layout = {}, Alphabet a = Alphabet::standard);

// True when every character is in the alphabet, '=' or a line break (a cheap pre-check).
bool alphabet_only(std::string_view text, Alphabet a = Alphabet::standard);

}  // namespace mcxanon::base64
