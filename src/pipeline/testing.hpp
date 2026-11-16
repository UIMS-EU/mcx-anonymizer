// SPDX-License-Identifier: GPL-3.0-or-later
//
// Test seams of the pipeline. Internal: never installed and
// never reachable from include/mcxanon/; used only by tests/.
#pragma once

#include "mcxanon/anonymize.hpp"

#include "policy/ruleset.hpp"
#include "policy/sip_rules.hpp"

#include <optional>

namespace mcxanon::testing {

struct Hooks {
  std::optional<RuleSet> ruleset_override;   // replaces the embedded rule set
  bool fail_before_publish = false;          // simulate a crash after the mapping is saved
  bool suppress_removed_values = false;      // the anonymiser "forgets" what it removed
  bool sip_passthrough = false;              // the SIP layer pseudonymises, then keeps the original bytes
  bool xml_passthrough = false;              // the XML layer rewrites, then keeps the original body
  bool web_passthrough = false;              // feature 007: HTTP, h2 and TLS rewrite, then keep the original bytes
  std::optional<SipRuleSet> sip_ruleset_override;  // replaces the embedded SIP rule set
};

Result<Report> anonymize_file_with_hooks(Project& project, const AnonymizeFileRequest& request,
                                         const Hooks& hooks);

}  // namespace mcxanon::testing
