// SPDX-License-Identifier: GPL-3.0-or-later
// The MIKEY parser and encoder (feature 005, FR-021, SC-005): any input either fails to parse or
// parses into a message whose encoding parses again to the same encoding, with no crash, hang or
// sanitizer report. The rewrite of both modes is added to this target with the payload handlers.
#include "mikey/decode.hpp"
#include "mikey/encode.hpp"
#include "policy/mikey_rules.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const MikeyRuleSet rules = [] {
    auto r = load_embedded_mikey_ruleset();
    if (!r) std::abort();
    return *r;
  }();
  const auto d = mikey::decode(ByteView(data, size), rules);
  if (d.verdict != mikey::Verdict::sakke) {
    if (d.message.has_value()) std::abort();
    return 0;
  }
  if (!d.message) std::abort();
  const Bytes once = mikey::encode(*d.message);
  if (once != Bytes(data, data + size)) std::abort();  // an accepted message re-encodes exactly
  const auto again = mikey::decode(once, rules);
  if (again.verdict != mikey::Verdict::sakke || mikey::encode(*again.message) != once) std::abort();
  return 0;
}
