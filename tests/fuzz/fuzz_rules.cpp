// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/ruleset.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  mcxanon::Catalogue cat;
  cat.add({"ipv4.src", mcxanon::FieldKind::address_ipv4});
  cat.add({"ipv4.ttl", mcxanon::FieldKind::numeric});
  cat.add({"pcapng.idb.opt.2", mcxanon::FieldKind::pcapng_option});
  const mcxanon::RuleFile f{"fuzz.yaml", std::string(reinterpret_cast<const char*>(data), size)};
  (void)mcxanon::load_ruleset({&f, 1}, cat);
  return 0;
}
