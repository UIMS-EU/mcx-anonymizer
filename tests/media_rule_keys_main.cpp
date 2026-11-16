// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded media rule set that changes a value (any action
// but keep), one per line, in the canary key format of tools/fixturegen/media.py. Used by
// test_rule_canary_coverage.py (FR-034: every such rule has a canary).
//
// The Reject Cause encoding keeps the cause and always removes the Reject Phrase (P5): it is
// listed too, since the phrase is a removed value.
#include "policy/media_rules.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_media_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys;
  for (const auto& [name, rule] : rs->rtp) {
    if (rule.action != MediaAction::keep) keys.insert("rtp:" + name);
  }
  for (const auto& [type, rule] : rs->rtcp.sdes_items) {
    if (rule.action != MediaAction::keep) keys.insert("rtcp:sdes/" + rule.name);
  }
  if (rs->rtcp.bye_reason) keys.insert("rtcp:bye/reason");
  for (const auto& fam : rs->app) {
    for (const auto& [id, rule] : fam.fields) {
      if (rule.action != MediaAction::keep || rule.encoding == AppEncoding::reject_cause) {
        keys.insert("app:" + fam.id + "/" + std::to_string(id));
      }
    }
  }
  for (const auto& [lower, rule] : rs->msrp.headers) {
    if (rule.action != MediaAction::keep) keys.insert("msrp:" + rule.name);
  }
  for (const auto& [name, rule] : rs->msrp.elements) {
    if (rule.action != MediaAction::keep) keys.insert("msrp:" + name);
  }
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
