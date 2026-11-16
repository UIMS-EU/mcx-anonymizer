// SPDX-License-Identifier: GPL-3.0-or-later
//
// Location values (TS 24.380 §8.2.3.21, Table 8.2.3.21-3; FR-020):
// the type is kept; PLMN, ECI, TAC, MBMS SAI and MBSFN Area ID are pseudonymised per component
// with format-preserving categories; coordinates and altitude are zeroed.
#include "media/app.hpp"
#include "media/wire.hpp"

#include <array>
#include <string>

namespace mcxanon::media {
namespace {

// Value sizes in octets by location type (TS 24.380 Table 8.2.3.21-3).
constexpr std::array<int, 8> kSize{0, 7, 5, 3, 2, 1, 6, 2};

// The 3-octet BCD PLMN (MCC2|MCC1, MNC3|MCC3, MNC2|MNC1; MNC3 = F for a 2-digit MNC), rewritten
// in place. False when a nibble is not a digit (the value is zeroed).
Result<bool> plmn(Bytes& b, std::size_t off, AddressMapper& mapper) {
  const auto lo = [&](std::size_t i) { return static_cast<unsigned>(b[i] & 0x0Fu); };
  const auto hi = [&](std::size_t i) { return static_cast<unsigned>(b[i] >> 4u); };
  const unsigned n[6] = {lo(off), hi(off), lo(off + 1), lo(off + 2), hi(off + 2), hi(off + 1)};
  const bool three = n[5] != 0x0F;
  std::string digits;
  for (int i = 0; i < (three ? 6 : 5); ++i) {
    if (n[i] > 9) return false;
    digits.push_back(static_cast<char>('0' + n[i]));
  }
  auto p = mapper.text(Category::plmn, digits);
  if (!p) return std::unexpected(p.error());
  const auto d = [&](int i) { return static_cast<std::uint8_t>((*p)[static_cast<std::size_t>(i)] - '0'); };
  b[off] = static_cast<std::uint8_t>((d(1) << 4) | d(0));
  b[off + 1] = static_cast<std::uint8_t>(((three ? d(5) : 0x0F) << 4) | d(2));
  b[off + 2] = static_cast<std::uint8_t>((d(4) << 4) | d(3));
  return true;
}

Result<std::uint32_t> bin(AddressMapper& m, Category c, std::uint32_t v) { return m.binary(c, v); }

}  // namespace

Result<std::optional<std::size_t>> rewrite_location_item(Bytes& b, std::size_t off, std::size_t end,
                                                         AddressMapper& mapper) {
  if (off >= end) return std::optional<std::size_t>{};
  const std::uint8_t type = b[off];
  if (type >= kSize.size()) return std::optional<std::size_t>{};
  const auto size = static_cast<std::size_t>(kSize[type]);
  if (end - off < 1 + size) return std::optional<std::size_t>{};
  const std::size_t v = off + 1;
  switch (type) {
    case 0: break;  // not provided
    case 1: {       // ECGI: PLMN + 32-bit word, ECI in the low 28 bits (TS 23.003 §19.6)
      auto ok = plmn(b, v, mapper);
      if (!ok) return std::unexpected(ok.error());
      if (!*ok) return std::optional<std::size_t>{};
      const std::uint32_t word = get32(b, v + 3);
      auto e = bin(mapper, Category::eci, word & 0x0FFFFFFFu);
      if (!e) return std::unexpected(e.error());
      set32(b, v + 3, (word & 0xF0000000u) | *e);
      break;
    }
    case 2: {  // Tracking Area: PLMN + 16-bit TAC
      auto ok = plmn(b, v, mapper);
      if (!ok) return std::unexpected(ok.error());
      if (!*ok) return std::optional<std::size_t>{};
      auto t = bin(mapper, Category::tac, get16(b, v + 3));
      if (!t) return std::unexpected(t.error());
      set16(b, v + 3, static_cast<std::uint16_t>(*t));
      break;
    }
    case 3: {  // PLMN ID
      auto ok = plmn(b, v, mapper);
      if (!ok) return std::unexpected(ok.error());
      if (!*ok) return std::optional<std::size_t>{};
      break;
    }
    case 4: {  // MBMS Service Area
      auto s = bin(mapper, Category::mbms_sai, get16(b, v));
      if (!s) return std::unexpected(s.error());
      set16(b, v, static_cast<std::uint16_t>(*s));
      break;
    }
    case 5: {  // MBSFN Area ID
      auto a = bin(mapper, Category::mbsfn_area, b[v]);
      if (!a) return std::unexpected(a.error());
      b[v] = static_cast<std::uint8_t>(*a);
      break;
    }
    default:  // 6 geographic coordinates, 7 altitude (TS 23.032 §6.1, §6.3): zeroed
      zero(b, v, v + size);
      break;
  }
  return std::optional<std::size_t>(1 + size);
}

}  // namespace mcxanon::media
