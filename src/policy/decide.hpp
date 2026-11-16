// SPDX-License-Identifier: GPL-3.0-or-later
//
// Field decisions: the rule for a FieldId, with the fail-closed default for a
// field that has no rule (zero for packet fields, remove for pcapng items).
#pragma once

#include "dissect/fields.hpp"
#include "policy/ruleset.hpp"

#include <vector>

namespace mcxanon {

struct Decision {
  Action action = Action::zero;
  bool unclassified = false;
};

class Policy {
 public:
  explicit Policy(const RuleSet& rules);
  [[nodiscard]] Decision decide(Fid f) const { return table_[static_cast<std::size_t>(f)]; }
  [[nodiscard]] const RuleSet& rules() const { return *rules_; }

 private:
  const RuleSet* rules_;
  std::vector<Decision> table_;
};

}  // namespace mcxanon
