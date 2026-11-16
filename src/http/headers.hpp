// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP header fields by the rules of the HTTP rule set (feature 007, FR-007, FR-013, FR-014):
// the 002 grammars through the SIP header engine, the HTTP grammars here. A
// field without a rule is removed and its name counted.
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::http {

// The rewritten value of one field, or nullopt when the field leaves (no rule, removed by its
// rule, or malformed). Counts every decision.
Result<std::optional<std::string>> rewrite_field(std::string_view name, std::string_view value, Env& env);

}  // namespace mcxanon::http
