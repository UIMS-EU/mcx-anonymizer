// SPDX-License-Identifier: GPL-3.0-or-later
//
// MCX RTCP APP decoding and rewriting (FR-014 to FR-024): the 12-octet common header
// (TS 24.380 §8.1.2, TS 24.581 §9.1.2) and the application specific data fields (TS 24.380
// §8.1.3), each classified by the media rules of its family (rules/rtcp-app.yaml).
#pragma once

#include "media/rtcp.hpp"

namespace mcxanon::media {

// One APP packet as tiled by rewrite_rtcp (its length field covers it exactly): the rewritten
// packet, with every field re-padded and the APP length recomputed (FR-023). An unknown subtype,
// or a header too short, zeroes the data and keeps the header with the SSRC mapped; a name
// without rules removes the packet (an empty result).
Result<Bytes> rewrite_app(ByteView packet, RtcpEnv& env);

// One Location item (type + value) at `off` within [off, end) of `b`, rewritten in place
// Returns the octets the item occupies, or nullopt when the
// type is unknown or the value does not fit (the caller zeroes it).
Result<std::optional<std::size_t>> rewrite_location_item(Bytes& b, std::size_t off, std::size_t end,
                                                         AddressMapper& mapper);

}  // namespace mcxanon::media
