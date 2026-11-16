// SPDX-License-Identifier: GPL-3.0-or-later
// Shared set-up of the media-plane fuzz targets: the embedded SIP and media rule sets and a fresh
// in-memory mapping per input, behind the real Pseudonymiser (no project store, no file I/O).
#pragma once

#include "fuzz_sip_common.hpp"
#include "media/counters.hpp"
#include "media/rtcp.hpp"
#include "policy/media_rules.hpp"

#include <cstdlib>

namespace fuzz {

inline const mcxanon::MediaRuleSet& media_rules() {
  static const auto rules = mcxanon::load_embedded_media_ruleset();
  if (!rules) std::abort();
  return *rules;
}

struct MediaEnv : SipEnv {
  mcxanon::media::MediaCounters media_counters;
  mcxanon::media::RtcpEnv rtcp{media_rules(), mapper, ctx, media_counters};
};

}  // namespace fuzz
