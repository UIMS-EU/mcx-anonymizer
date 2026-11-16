// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/endian.hpp"

#include <stdexcept>

namespace mcxanon {
namespace {

void require(std::size_t size, std::size_t off, std::size_t n) {
  if (off > size || size - off < n) {
    throw std::out_of_range("byte access outside buffer");
  }
}

template <class T>
T load(ByteView b, std::size_t off, Endian e) {
  require(b.size(), off, sizeof(T));
  T v = 0;
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    const std::size_t idx = (e == Endian::big) ? i : sizeof(T) - 1 - i;
    v = static_cast<T>((v << 8) | b[off + idx]);
  }
  return v;
}

template <class T>
void store(MutByteView b, std::size_t off, T v, Endian e) {
  require(b.size(), off, sizeof(T));
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    const auto byte = static_cast<std::uint8_t>((v >> (8 * (sizeof(T) - 1 - i))) & 0xFF);
    const std::size_t idx = (e == Endian::big) ? i : sizeof(T) - 1 - i;
    b[off + idx] = byte;
  }
}

}  // namespace

std::uint16_t load16(ByteView b, std::size_t off, Endian e) { return load<std::uint16_t>(b, off, e); }
std::uint32_t load32(ByteView b, std::size_t off, Endian e) { return load<std::uint32_t>(b, off, e); }
std::uint64_t load64(ByteView b, std::size_t off, Endian e) { return load<std::uint64_t>(b, off, e); }
void store16(MutByteView b, std::size_t off, std::uint16_t v, Endian e) { store(b, off, v, e); }
void store32(MutByteView b, std::size_t off, std::uint32_t v, Endian e) { store(b, off, v, e); }
void store64(MutByteView b, std::size_t off, std::uint64_t v, Endian e) { store(b, off, v, e); }

}  // namespace mcxanon
