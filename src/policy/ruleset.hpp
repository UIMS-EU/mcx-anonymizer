// SPDX-License-Identifier: GPL-3.0-or-later
//
// The rule set: data that classifies every field (keep, pseudonymise, zero,
// pad, remove, recompute), each rule with its normative source.
#pragma once

#include "mcxanon/error.hpp"

#include "dissect/catalogue.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

// l7: delegate to the SIP layer (payload.sip only, feature 002).
enum class Action { keep, pseudonymise, zero, pad, remove, recompute, l7 };

std::string_view to_string(Action a);

struct Source {
  std::string spec;
  std::string version;
  std::string clause;
};

struct Rule {
  std::string field;
  Action action = Action::zero;
  std::optional<std::string> category;  // for pseudonymise: mac, ipv4, ipv6, vlan, port-eph
  Source source;
  std::string note;
};

struct RuleSet {
  std::string name;
  std::string version;
  std::string digest;  // SHA-256 (hex) of the rule files concatenated in name order
  std::vector<Rule> rules;
  [[nodiscard]] const Rule* find(std::string_view field) const;
};

struct RuleFile {
  std::string name;  // file name, used for ordering and messages
  std::string text;  // YAML
};

Result<RuleSet> load_ruleset(std::span<const RuleFile> files, const Catalogue& catalogue);

// The rule set embedded at build time from rules/*.yaml.
Result<RuleSet> load_embedded_ruleset();
std::string_view embedded_ruleset_name();
std::string_view embedded_ruleset_digest();

}  // namespace mcxanon
