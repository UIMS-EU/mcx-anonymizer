// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/special_addresses.hpp"

#include <algorithm>

namespace mcxanon {

Ipv4Class classify_ipv4(std::uint32_t a) {
  if (a == 0x00000000u || a == 0xFFFFFFFFu) return Ipv4Class::keep;
  if ((a >> 24) == 127u) return Ipv4Class::keep;
  if ((a & 0xFFFFFF00u) == 0xE0000000u) return Ipv4Class::keep;  // 224.0.0.0/24
  if ((a & 0xFFFFFF00u) == 0xE0000100u) return Ipv4Class::keep;  // 224.0.1.0/24
  if ((a >> 28) == 0xEu) return Ipv4Class::multicast;
  return Ipv4Class::unicast;
}

Ipv6Class classify_ipv6(const Ipv6& a) {
  const auto zero_until = [&](std::size_t n) {
    return std::all_of(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(n),
                       [](auto v) { return v == 0; });
  };
  if (zero_until(15) && (a[15] == 0 || a[15] == 1)) return Ipv6Class::keep;
  if (a[0] == 0xFF) {
    // ff02::1:ff00:0/104 solicited-node (RFC 4291 §2.7.1).
    const bool solicited = a[1] == 0x02 && zero_until(0) &&
                           std::all_of(a.begin() + 2, a.begin() + 11, [](auto v) { return v == 0; }) &&
                           a[11] == 0x01 && a[12] == 0xFF;
    if (solicited) return Ipv6Class::solicited_node;
    const bool transient = (a[1] & 0x10u) != 0;  // T flag
    return transient ? Ipv6Class::multicast : Ipv6Class::keep;
  }
  if (a[0] == 0xFE && (a[1] & 0xC0u) == 0x80u) return Ipv6Class::link_local;
  // ::ffff:0:0/96 (mapped), ::/96 (compatible, deprecated), 64:ff9b::/96 (RFC 6052).
  if (zero_until(10) && a[10] == 0xFF && a[11] == 0xFF) return Ipv6Class::embedded_ipv4;
  if (zero_until(12)) return Ipv6Class::embedded_ipv4;
  if (a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xFF && a[3] == 0x9B &&
      std::all_of(a.begin() + 4, a.begin() + 12, [](auto v) { return v == 0; })) {
    return Ipv6Class::embedded_ipv4;
  }
  return Ipv6Class::unicast;
}

}  // namespace mcxanon
