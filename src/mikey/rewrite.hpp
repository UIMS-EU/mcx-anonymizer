// SPDX-License-Identifier: GPL-3.0-or-later
//
// The payload handlers of the MIKEY rewriter in ciphertext mode (spec FR-006 to FR-015).
// Identities take the project's URI mapping through the SIP context,
// so one identity has one pseudonym in SIP, XML, the media plane and MIKEY.
#pragma once

#include "mcxanon/error.hpp"

#include "mikey/counters.hpp"
#include "mikey/decode.hpp"
#include "mikey/ledger.hpp"
#include "mikey/rewriter.hpp"
#include "policy/mikey_rules.hpp"
#include "sip/value_map.hpp"

#include <cstdint>
#include <set>

namespace mcxanon::mikey {

struct RewriteEnv {
  const MikeyRuleSet& rules;
  const RewriterOptions& options;
  sip::Context& ctx;
  Counters& counters;
  std::set<std::uint32_t>* seen_key_ids = nullptr;  // distinct key identifiers for the report
  const Ledger* ledger = nullptr;                    // identities seen in the run (UID resolution)
};

// Rewrites a parsed MIKEY-SAKKE message in place. Errors are tool failures (a pseudonym collision).
Result<void> rewrite_message(Message& m, RewriteEnv& env);

// A key identifier through the project mapping, counted per purpose tag.
Result<std::uint32_t> map_key_id(std::uint32_t original, RewriteEnv& env);

}  // namespace mcxanon::mikey
