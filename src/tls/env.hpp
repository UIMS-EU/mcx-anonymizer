// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the TLS layer needs from the pipeline (feature 007): the TLS rule set, the SIP context
// (mapper and the URI and host mappings shared with SIP and HTTP) and the counters.
#pragma once

#include "policy/tls_rules.hpp"
#include "sip/value_map.hpp"
#include "tls/counters.hpp"

namespace mcxanon::tls {

struct Env {
  const TlsRuleSet& rules;
  sip::Context& sip;
  Counters& counters;
};

}  // namespace mcxanon::tls
