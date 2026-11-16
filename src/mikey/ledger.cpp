// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/ledger.hpp"

namespace mcxanon::mikey {

void Ledger::add(std::string_view original) {
  if (original.empty() || seen_.contains(std::string(original))) return;
  if (order_.size() >= kMax) {
    seen_.erase(order_.front());
    order_.pop_front();
  }
  order_.emplace_back(original);
  seen_.emplace(original);
}

}  // namespace mcxanon::mikey
