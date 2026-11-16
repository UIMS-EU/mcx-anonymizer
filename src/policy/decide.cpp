// SPDX-License-Identifier: GPL-3.0-or-later
#include "policy/decide.hpp"

namespace mcxanon {

Policy::Policy(const RuleSet& rules) : rules_(&rules) {
  const auto n = static_cast<std::size_t>(Fid::count_);
  table_.resize(n);
  for (std::size_t i = 0; i < n; ++i) {
    const auto f = static_cast<Fid>(i);
    const Rule* r = rules.find(field_name(f));
    if (r != nullptr) {
      table_[i] = {r->action, false};
    } else {
      const auto k = field_kind(f);
      const bool pcapng = k == FieldKind::pcapng_block || k == FieldKind::pcapng_option;
      table_[i] = {pcapng ? Action::remove : Action::zero, true};
    }
  }
}

}  // namespace mcxanon
