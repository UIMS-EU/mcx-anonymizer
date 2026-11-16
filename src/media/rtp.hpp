// SPDX-License-Identifier: GPL-3.0-or-later
//
// RTP rewrite (FR-004 to FR-008, FR-025). The fixed header is
// kept with SSRC and CSRCs pseudonymised; header extensions keep their structure with element
// data zeroed; the payload becomes zeros of the same length; on a secure (SRTP) endpoint every
// octet after the header is zeroed. The length never changes.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "media/counters.hpp"
#include "policy/media_rules.hpp"
#include "rewrite/address_mapper.hpp"
#include "sip/value_map.hpp"

#include <optional>

namespace mcxanon::media {

// The rewritten packet, or nullopt when nothing of it can be kept (malformed, or no RTP rules):
// the caller zeroes the whole payload. Errors are tool failures (pseudonym collision).
Result<std::optional<Bytes>> rewrite_rtp(ByteView packet, bool secure, const MediaRuleSet& rules,
                                         AddressMapper& mapper, MediaCounters& counters,
                                         const sip::KeyContext* keys = nullptr);

}  // namespace mcxanon::media
