// SPDX-License-Identifier: GPL-3.0-or-later
//
// Test-only executable (never installed): runs the full pipeline with a
// deliberately leaky rule set, to prove that the independent scanner blocks
// the output (US2).
//   variant a: ipv4.src is kept (a leak of an address)
//   variant b: comments are kept and the anonymiser does not report removed
//              values (only the scanner's own input harvest can catch it)
//   variant d: a leaky SIP rule set keeps Call-ID, From and To as they are and the anonymiser
//              reports no removed value: only the scanner's own SIP harvester can catch
// the user parts and the Call-ID
//   variant c: the SIP layer pseudonymises every identity (the mapping holds them) but
//              keeps the original message bytes: the mapping tokens of the text categories
//              must block publication (FR-030)
//   variant x: the XML layer rewrites every body but keeps the original bytes, and the
//              anonymiser reports no removed value: the scanner's own XML harvester must catch
//              originals inside XML bodies (feature 003, FR-019)
//   variant r: as x, but removed values are reported: a value an XML rule removed, written
//              back, must be caught by the removed-value tokens (FR-017)
//   variant w: feature 007: the HTTP, h2 and TLS sessions rewrite every message (the mapping
//              holds the identities) but keep the original bytes, and no removed value is
//              reported: the mapping tokens and the scanner's own web harvest must block it
// Usage: mcxanon_leaktest DATA_DIR PROJECT INPUT OUTPUT a|b|c|d|x|r|w [DENY_LIST]
#include "mcxanon/project.hpp"

#include "pipeline/testing.hpp"
#include "policy/ruleset.hpp"
#include "policy/sip_rules.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
  using namespace mcxanon;
  if (argc < 6) {
    std::fputs("usage: mcxanon_leaktest DATA_DIR PROJECT INPUT OUTPUT a|b|c|d|x|r|w [DENY_LIST]\n", stderr);
    return 2;
  }
  auto rules = load_embedded_ruleset();
  if (!rules) return 70;
  const std::string variant = argv[5];
  for (auto& r : rules->rules) {
    if (variant == "a" && r.field == "ipv4.src") {
      r.action = Action::keep;
      r.category.reset();
    }
    if (variant == "b" && r.field == "pcapng.opt.comment") r.action = Action::keep;
  }
  testing::Hooks hooks;
  hooks.ruleset_override = *rules;
  hooks.suppress_removed_values = variant == "b" || variant == "c" || variant == "d" || variant == "x" || variant == "w";
  hooks.web_passthrough = variant == "w";
  hooks.xml_passthrough = variant == "x" || variant == "r";
  if (variant == "d") {
    auto sip = load_embedded_sip_ruleset();
    if (!sip) return 70;
    for (auto& h : sip->headers) {
      if (h.name == "Call-ID" || h.name == "From" || h.name == "To") {
        h.grammar = SipGrammar::opaque;  // copied as written
        h.action = SipAction::keep;
      }
    }
    hooks.sip_ruleset_override = std::move(*sip);
  }
  hooks.sip_passthrough = variant == "c";
  auto project = Project::open(DataDirResolution{argv[1], DataDirSource::flag}, argv[2], false);
  if (!project) {
    std::fprintf(stderr, "%s\n", project.error().message.c_str());
    return static_cast<int>(project.error().code);
  }
  AnonymizeFileRequest req;
  req.input = argv[3];
  req.output = argv[4];
  if (argc > 6) req.deny_list = argv[6];
  auto r = testing::anonymize_file_with_hooks(*project, req, hooks);
  if (!r) {
    std::fprintf(stderr, "%s\n", r.error().message.c_str());
    return static_cast<int>(r.error().code);
  }
  return 0;
}
