// SPDX-License-Identifier: GPL-3.0-or-later
// --time-shift grammar: [+|-]<n><unit>[<n><unit>...], units d h m s ms us ns.
#pragma once

#include "mcxanon/error.hpp"

#include <chrono>
#include <string_view>

namespace mcxanon::cli {

Result<std::chrono::nanoseconds> parse_duration(std::string_view text);

}  // namespace mcxanon::cli
