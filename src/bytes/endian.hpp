// SPDX-License-Identifier: GPL-3.0-or-later
//
// Raw integer loads and stores. The caller guarantees the bounds; an access
// outside the buffer is a programmer error and throws std::out_of_range. Code
// that reads untrusted data uses bytes::Reader instead.
#pragma once

#include "bytes/bytes.hpp"

#include <cstddef>
#include <cstdint>

namespace mcxanon {

enum class Endian { big, little };

std::uint16_t load16(ByteView b, std::size_t off, Endian e);
std::uint32_t load32(ByteView b, std::size_t off, Endian e);
std::uint64_t load64(ByteView b, std::size_t off, Endian e);
void store16(MutByteView b, std::size_t off, std::uint16_t v, Endian e);
void store32(MutByteView b, std::size_t off, std::uint32_t v, Endian e);
void store64(MutByteView b, std::size_t off, std::uint64_t v, Endian e);

inline std::uint16_t be16(ByteView b, std::size_t off) { return load16(b, off, Endian::big); }
inline std::uint32_t be32(ByteView b, std::size_t off) { return load32(b, off, Endian::big); }

}  // namespace mcxanon
