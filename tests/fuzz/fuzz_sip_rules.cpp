// SPDX-License-Identifier: GPL-3.0-or-later
// Arbitrary YAML into the mcxanon-sip loader: errors are values, never crashes.
#include "policy/sip_rules.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const mcxanon::RuleFile f{"sip-fuzz.yaml", std::string(reinterpret_cast<const char*>(data), size)};
  (void)mcxanon::load_sip_ruleset({&f, 1});
  return 0;
}
