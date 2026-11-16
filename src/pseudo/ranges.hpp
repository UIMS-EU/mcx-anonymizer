// SPDX-License-Identifier: GPL-3.0-or-later
//
// Placement of HMAC candidates into the pseudonym ranges:
// IPv4 240.0.0.0/4, IPv6 2001:db8::/32, locally administered MACs, VLAN
// 1-4094, ephemeral ports, IPv4 multicast 233.252.0.0/24.
#pragma once

#include "pseudo/hmac.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace mcxanon {

using Ipv6 = std::array<std::uint8_t, 16>;
using Mac = std::array<std::uint8_t, 6>;
using Iid = std::array<std::uint8_t, 8>;

// nullopt when the candidate is an excluded value (255.255.255.255).
std::optional<std::uint32_t> place_ipv4(const Digest32& d);
Ipv6 place_ipv6(const Digest32& d);
// U/L bit set, I/G bit copied from the original first octet.
Mac place_mac(const Digest32& d, std::uint8_t original_first_octet);
std::uint16_t place_vlan(const Digest32& d);
std::uint16_t place_port(const Digest32& d, std::uint16_t lo, std::uint16_t hi);
std::uint32_t place_ipv4_mcast(const Digest32& d);
// nullopt for the all-zero and all-ones identifiers.
std::optional<Iid> place_iid(const Digest32& d);
std::array<std::uint8_t, 3> place_sn24(const Digest32& d);

}  // namespace mcxanon
