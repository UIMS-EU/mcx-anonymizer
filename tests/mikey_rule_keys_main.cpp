// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded MIKEY rule set that changes a value, one per line,
// in the canary key format of tools/fixturegen/mikey.py. Used by test_rule_canary_coverage.py
// (every such rule has a canary). The T payload is shifted, not replaced, and kept
// ciphertext (SAKKE, SAKKE-to-self) and fallback rules change nothing inside a message.
//   mikey:hdr/csb-id, mikey:hdr/spi, mikey:hdr/ssrc   the common header and GENERIC-ID blocks
//   mikey:<payload>                                    a payload replaced as a whole (rand, sign)
//   mikey:idr/<role>                                   an ID role, and mikey:idr/unknown
//   mikey:ext/<type>                                   an extension type, and mikey:ext/unknown
//   mikey:sp/unknown                                   a policy parameter without a rule
//   mikey:mki                                          the SRTP/SRTCP MKI (FR-012a)
#include "policy/mikey_rules.hpp"

#include <cctype>
#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_mikey_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys{"mikey:hdr/csb-id", "mikey:hdr/spi", "mikey:hdr/ssrc", "mikey:idr/unknown",
                             "mikey:ext/unknown", "mikey:sp/unknown", "mikey:mki"};
  for (const auto& [next, rule] : rs->payloads) {
    if (rule.action != MikeyAction::nonce && rule.action != MikeyAction::zero) continue;
    std::string n = rule.name;
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    keys.insert("mikey:" + n);
  }
  for (const auto& [key, rule] : rs->id_roles) {
    if (rule.action == MikeyAction::identity || rule.action == MikeyAction::kms || rule.action == MikeyAction::uid) {
      keys.insert("mikey:idr/" + std::to_string(key.first));
    }
  }
  for (const auto& [type, rule] : rs->extensions) {
    if (rule.action == MikeyAction::zero || rule.action == MikeyAction::key_parameters) {
      keys.insert("mikey:ext/" + std::to_string(type));
    }
  }
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
