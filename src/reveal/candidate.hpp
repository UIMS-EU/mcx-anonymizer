// SPDX-License-Identifier: GPL-3.0-or-later
//
// Candidates produced by the exact-string matcher and the lexical recognisers,
// over a decoded view of the input (percent-escapes and XML character references
// decoded, with a map back to the source offsets).
#pragma once

#include "reveal/index.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::reveal {

// The input buffer with escapes decoded. src[i] is the source offset of decoded byte i, and
// src[size] the source offset just past the last decoded byte. esc[i] tells whether decoded
// byte i came from an escape, and of which scheme.
struct View {
  std::string text;
  std::vector<std::uint32_t> src;
  std::vector<Escape> esc;
  bool any_escape = false;
};

// With `decode`, percent-escapes (RFC 3986 §2.1) and XML character references (the five
// predefined entities, decimal and hex references below 0x80) are decoded; otherwise the view
// is the source itself.
View make_view(std::string_view source, bool decode);
// True when the source contains anything make_view(decode) would decode.
bool has_escapes(std::string_view source);

// One possible original for a candidate.
struct Hit {
  Category category = Category::mac;
  std::string original;  // rendered in the style of the match, before escaping
};

struct Candidate {
  std::size_t start = 0;  // decoded-view offsets, half-open
  std::size_t end = 0;
  std::vector<Hit> hits;
  std::vector<std::string> forms;  // normalised forms of the matched value (pseudonym-and-original check)
  bool shaped = false;             // has the shape of a pseudonym of the tool (FR-017a)
  Category shape_category = Category::mac;
  bool small_space = false;  // every hit is in a small value-space category
  bool inconsistent = false;  // a domain chain whose labels belong to different hosts
  // Filled by the engine: the source span and the view the candidate came from.
  std::size_t src_start = 0;
  std::size_t src_end = 0;
  bool decoded = false;
};

// Exact-string candidates of the matcher in view.text, starting in [begin, limit).
void exact_candidates(const View& v, std::size_t begin, std::size_t limit, const Index& index,
                      std::vector<Candidate>& out);
// Recogniser candidates starting in [begin, limit) (domain chains, addresses, numbers,
// telephone numbers, IMEIs, location composites, unknown shapes).
void recognised_candidates(const View& v, std::size_t begin, std::size_t limit, const Index& index,
                           std::vector<Candidate>& out);

// Byte classes used by the boundary rule.
inline bool is_alnum(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline bool is_hex(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
inline bool is_digit(unsigned char c) { return c >= '0' && c <= '9'; }
inline bool is_word(unsigned char c) { return is_alnum(c) || c == '_'; }

}  // namespace mcxanon::reveal
