// SPDX-License-Identifier: GPL-3.0-or-later
//
// The identity ledger: the original SIP and tel URIs the run has rewritten, in
// first-seen order, bounded at 65,536 (the oldest are evicted). Run-scoped, never persisted.
#pragma once

#include <cstddef>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_set>

namespace mcxanon::mikey {

class Ledger {
 public:
  static constexpr std::size_t kMax = 65536;
  void add(std::string_view original);
  [[nodiscard]] const std::deque<std::string>& originals() const { return order_; }

 private:
  std::deque<std::string> order_;
  std::unordered_set<std::string> seen_;
};

}  // namespace mcxanon::mikey
