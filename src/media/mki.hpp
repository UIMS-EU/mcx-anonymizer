// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SRTP and SRTCP MKI (feature 005, spec FR-012a). RFC 3711 §3.1
// and §3.4 place the MKI before the authentication tag at the end of the packet. On a secure
// endpoint 004 zeroes everything after the header (FR-025); the MKI alone gets key identifier
// pseudonyms when its 4-octet words are key identifiers known from the endpoint's key context or
// from the project mapping, with purpose tags that fit the position, at exactly one (length,
// offset). Anything else keeps the zeroed trailer.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "media/counters.hpp"
#include "rewrite/address_mapper.hpp"
#include "sip/value_map.hpp"

#include <cstddef>

namespace mcxanon::media {

// `in` is the original packet, `out` its rewrite of the same length with the trailer zeroed;
// `min_off` is the first octet the MKI may start at (after the header, and after E+index for
// SRTCP). Errors are tool failures (a pseudonym collision).
Result<void> rewrite_mki(ByteView in, Bytes& out, std::size_t min_off, bool srtcp, const sip::KeyContext* keys,
                         AddressMapper& mapper, MediaCounters& counters);

}  // namespace mcxanon::media
