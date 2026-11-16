// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/ranges.hpp"

#include <algorithm>

namespace mcxanon {
namespace {
std::uint32_t be32_of(const Digest32& d) {
  return (static_cast<std::uint32_t>(d[0]) << 24) | (static_cast<std::uint32_t>(d[1]) << 16) |
         (static_cast<std::uint32_t>(d[2]) << 8) | d[3];
}
}  // namespace

std::optional<std::uint32_t> place_ipv4(const Digest32& d) {
  const std::uint32_t v = 0xF0000000u | (be32_of(d) & 0x0FFFFFFFu);
  if (v == 0xFFFFFFFFu) return std::nullopt;
  return v;
}

Ipv6 place_ipv6(const Digest32& d) {
  Ipv6 a{0x20, 0x01, 0x0d, 0xb8};
  std::copy_n(d.begin(), 12, a.begin() + 4);
  return a;
}

Mac place_mac(const Digest32& d, std::uint8_t original_first_octet) {
  Mac m{};
  std::copy_n(d.begin(), 6, m.begin());
  m[0] = static_cast<std::uint8_t>((m[0] & 0xFCu) | 0x02u | (original_first_octet & 0x01u));
  return m;
}

std::uint16_t place_vlan(const Digest32& d) {
  return static_cast<std::uint16_t>(1 + (be32_of(d) % 4094u));
}

std::uint16_t place_port(const Digest32& d, std::uint16_t lo, std::uint16_t hi) {
  const std::uint32_t span = static_cast<std::uint32_t>(hi - lo) + 1u;
  return static_cast<std::uint16_t>(lo + (be32_of(d) % span));
}

std::uint32_t place_ipv4_mcast(const Digest32& d) { return 0xE9FC0000u | d[0]; }

std::optional<Iid> place_iid(const Digest32& d) {
  Iid iid{};
  std::copy_n(d.begin(), 8, iid.begin());
  const bool zero = std::all_of(iid.begin(), iid.end(), [](auto v) { return v == 0x00; });
  const bool ones = std::all_of(iid.begin(), iid.end(), [](auto v) { return v == 0xFF; });
  if (zero || ones) return std::nullopt;
  return iid;
}

std::array<std::uint8_t, 3> place_sn24(const Digest32& d) { return {d[0], d[1], d[2]}; }

}  // namespace mcxanon
