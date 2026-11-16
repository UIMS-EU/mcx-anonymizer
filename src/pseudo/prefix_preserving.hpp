// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prefix-preserving pseudonyms: a Crypto-PAn style construction
// with HMAC-SHA-256 as the PRF over the full address, after which the leading
// bits are replaced by the pseudonym range prefix (240.0.0.0/4, 2001:db8::/32).
// Two originals that share a prefix of n bits (n <= free bits) give pseudonyms
// that share exactly n bits.
#pragma once

#include "pseudo/hmac.hpp"
#include "pseudo/ranges.hpp"

#include <cstdint>

namespace mcxanon {

std::uint32_t pp_ipv4(const Secret& secret, std::uint32_t original);
Ipv6 pp_ipv6(const Secret& secret, const Ipv6& original);

}  // namespace mcxanon
