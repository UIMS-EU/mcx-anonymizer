// SPDX-License-Identifier: GPL-3.0-or-later
//
// RTCP rewrite (FR-009 to FR-013, FR-024, FR-025, FR-030). A datagram is parsed as RTCP packets that must tile it exactly (compound or reduced-size,
// RFC 5506); one that does not, and every datagram on a secure endpoint, keeps its first 8
// octets (header and SSRC, pseudonymised) and is zeroed after them (the SRTCP view). MCX APP
// packets go to the APP decoder (app.hpp).
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "media/counters.hpp"
#include "policy/media_rules.hpp"
#include "rewrite/address_mapper.hpp"
#include "sip/value_map.hpp"

#include <optional>

namespace mcxanon::media {

// What the RTCP and APP rewriters use: the rules, the project mapping, the SIP context (for
// URIs and CNAMEs, so that identities get the SIP pseudonyms) and the counters.
struct RtcpEnv {
  const MediaRuleSet& rules;
  AddressMapper& mapper;
  sip::Context& sip;
  MediaCounters& counters;
  const sip::KeyContext* keys = nullptr;  // feature 005: the endpoint's key context (the MKI)
};

// The rewritten datagram (its length may change: SDES, BYE and APP values), or nullopt when
// nothing of it can be kept (shorter than 8 octets): the caller zeroes it. Errors are tool
// failures (pseudonym collision).
Result<std::optional<Bytes>> rewrite_rtcp(ByteView datagram, bool secure, RtcpEnv& env);

}  // namespace mcxanon::media
