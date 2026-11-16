// SPDX-License-Identifier: GPL-3.0-or-later
// Big-endian helpers of the media decoders.
#pragma once

#include "bytes/bytes.hpp"

#include <algorithm>
#include <cstdint>

namespace mcxanon::media {

inline std::uint16_t get16(ByteView b, std::size_t off) {
  return static_cast<std::uint16_t>((b[off] << 8) | b[off + 1]);
}
inline std::uint32_t get32(ByteView b, std::size_t off) {
  return (std::uint32_t{b[off]} << 24) | (std::uint32_t{b[off + 1]} << 16) | (std::uint32_t{b[off + 2]} << 8) |
         b[off + 3];
}
inline void set16(Bytes& b, std::size_t off, std::uint16_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 8);
  b[off + 1] = static_cast<std::uint8_t>(v);
}
inline void set32(Bytes& b, std::size_t off, std::uint32_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 24);
  b[off + 1] = static_cast<std::uint8_t>(v >> 16);
  b[off + 2] = static_cast<std::uint8_t>(v >> 8);
  b[off + 3] = static_cast<std::uint8_t>(v);
}
inline void put16(Bytes& b, std::uint16_t v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v));
}
inline void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}
inline void zero(Bytes& b, std::size_t from, std::size_t to) {
  if (from >= to) return;
  std::fill(b.begin() + static_cast<std::ptrdiff_t>(from), b.begin() + static_cast<std::ptrdiff_t>(to),
            std::uint8_t{0});
}
inline void pad4(Bytes& b) {
  while (b.size() % 4 != 0) b.push_back(0);
}

}  // namespace mcxanon::media
