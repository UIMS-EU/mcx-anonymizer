// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/prefix_preserving.hpp"

#include <string_view>

namespace mcxanon {
namespace {

// PRF bit for position i given the first i bits of the original (big-endian bytes).
std::uint8_t prf_bit(const Secret& s, std::uint8_t family, std::size_t i, const std::uint8_t* bits, std::size_t nbytes) {
  constexpr std::string_view tag = "mcxanon/pp";
  Bytes msg(tag.begin(), tag.end());
  msg.push_back(0);
  msg.push_back(family);
  msg.push_back(static_cast<std::uint8_t>(i));
  const std::size_t full = i / 8;
  for (std::size_t k = 0; k < full; ++k) msg.push_back(bits[k]);
  if (i % 8 != 0 && full < nbytes) {
    const unsigned keep = 0xFFu << (8u - static_cast<unsigned>(i % 8));
    msg.push_back(static_cast<std::uint8_t>(static_cast<unsigned>(bits[full]) & keep));
  }
  return hmac_sha256(s, msg)[31] & 1u;
}

template <std::size_t N>
std::array<std::uint8_t, N> permute(const Secret& s, std::uint8_t family, const std::array<std::uint8_t, N>& in) {
  std::array<std::uint8_t, N> out{};
  for (std::size_t i = 0; i < N * 8; ++i) {
    const unsigned shift = 7u - static_cast<unsigned>(i % 8);
    const unsigned bit = (static_cast<unsigned>(in[i / 8]) >> shift) & 1u;
    const unsigned o = bit ^ prf_bit(s, family, i, in.data(), N);
    out[i / 8] = static_cast<std::uint8_t>(static_cast<unsigned>(out[i / 8]) | (o << shift));
  }
  return out;
}

}  // namespace

std::uint32_t pp_ipv4(const Secret& secret, std::uint32_t original) {
  const std::array<std::uint8_t, 4> in{static_cast<std::uint8_t>(original >> 24), static_cast<std::uint8_t>(original >> 16),
                                       static_cast<std::uint8_t>(original >> 8), static_cast<std::uint8_t>(original)};
  const auto o = permute(secret, 4, in);
  const std::uint32_t v = (static_cast<std::uint32_t>(o[0]) << 24) | (static_cast<std::uint32_t>(o[1]) << 16) |
                          (static_cast<std::uint32_t>(o[2]) << 8) | o[3];
  return 0xF0000000u | (v & 0x0FFFFFFFu);
}

Ipv6 pp_ipv6(const Secret& secret, const Ipv6& original) {
  Ipv6 o = permute(secret, 6, original);
  o[0] = 0x20;
  o[1] = 0x01;
  o[2] = 0x0d;
  o[3] = 0xb8;
  return o;
}

}  // namespace mcxanon
