// SPDX-License-Identifier: GPL-3.0-or-later
//
// Address classes that decide how an address is pseudonymised.
// Sources: RFC 6890 and the IANA special-purpose registries, RFC 4291 §2.7
// (multicast flags), RFC 5771 (IPv4 multicast blocks), RFC 6052 (NAT64).
#pragma once

#include "pseudo/ranges.hpp"

#include <cstdint>

namespace mcxanon {

enum class Ipv4Class {
  keep,       // unspecified, limited broadcast, loopback, 224.0.0.0/24, 224.0.1.0/24
  multicast,  // other 224.0.0.0/4: pseudonymised into 233.252.0.0/24
  unicast,    // everything else: pseudonymised into 240.0.0.0/4
};

enum class Ipv6Class {
  keep,            // ::, ::1, permanent (T=0) multicast other than solicited-node
  multicast,       // transient (T=1) multicast: group ID pseudonymised, scope/flags kept
  solicited_node,  // ff02::1:ffXX:XXXX: low 24 bits pseudonymised
  link_local,      // fe80::/64: interface identifier pseudonymised
  embedded_ipv4,   // IPv4-mapped, IPv4-compatible, 64:ff9b::/96: embedded IPv4 pseudonymised
  unicast,         // everything else (global, ULA, 6to4, Teredo, documentation): 2001:db8::/32
};

Ipv4Class classify_ipv4(std::uint32_t addr);
Ipv6Class classify_ipv6(const Ipv6& addr);

}  // namespace mcxanon
