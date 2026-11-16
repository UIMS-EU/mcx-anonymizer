// SPDX-License-Identifier: GPL-3.0-or-later
// Shared set-up of the SIP fuzz targets: the embedded SIP rule set and a fresh in-memory mapping
// per input, behind the real Pseudonymiser (no project store, no file I/O).
#pragma once

#include "pipeline/mapper_adapter.hpp"
#include "policy/sip_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/value_map.hpp"

#include <cstdlib>
#include <memory>
#include <string_view>

namespace fuzz {

inline const mcxanon::SipRuleSet& sip_rules() {
  static const auto rules = mcxanon::load_embedded_sip_ruleset();
  if (!rules) std::abort();
  return *rules;
}

struct SipEnv {
  mcxanon::Secret secret{};
  mcxanon::Mapping mapping;
  mcxanon::Pseudonymiser pseudonymiser{secret, mapping};
  mcxanon::MapperAdapter mapper{pseudonymiser};
  mcxanon::sip::SipCounters counters;
  mcxanon::sip::Context ctx{sip_rules(), mapper, {}, counters};
};

inline std::string_view text(const std::uint8_t* data, std::size_t size) {
  return {reinterpret_cast<const char*>(data), size};
}

}  // namespace fuzz
