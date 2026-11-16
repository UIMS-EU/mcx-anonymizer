// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/duration.hpp"

#include <cstdint>
#include <limits>
#include <string>

namespace mcxanon::cli {
namespace {
__extension__ typedef __int128 i128;
}  // namespace

Result<std::chrono::nanoseconds> parse_duration(std::string_view t) {
  const auto bad = [&] {
    return fail(ErrorCode::usage, "invalid duration '" + std::string(t) +
                                      "'; use e.g. -30d, +1h30m, -250ms (units d h m s ms us ns)");
  };
  if (t.empty()) return bad();
  bool negative = false;
  std::size_t i = 0;
  if (t[0] == '+' || t[0] == '-') {
    negative = t[0] == '-';
    i = 1;
  }
  if (i == t.size()) return bad();
  i128 total = 0;
  while (i < t.size()) {
    if (t[i] < '0' || t[i] > '9') return bad();
    i128 n = 0;
    while (i < t.size() && t[i] >= '0' && t[i] <= '9') {
      n = n * 10 + (t[i] - '0');
      if (n > static_cast<i128>(std::numeric_limits<std::int64_t>::max())) return bad();
      ++i;
    }
    std::size_t j = i;
    while (j < t.size() && t[j] >= 'a' && t[j] <= 'z') ++j;
    const std::string_view unit = t.substr(i, j - i);
    std::int64_t scale = 0;
    if (unit == "d") scale = 86400LL * 1000000000LL;
    else if (unit == "h") scale = 3600LL * 1000000000LL;
    else if (unit == "m") scale = 60LL * 1000000000LL;
    else if (unit == "s") scale = 1000000000LL;
    else if (unit == "ms") scale = 1000000LL;
    else if (unit == "us") scale = 1000LL;
    else if (unit == "ns") scale = 1LL;
    else return bad();
    total += n * scale;
    if (total > static_cast<i128>(std::numeric_limits<std::int64_t>::max())) return bad();
    i = j;
  }
  const auto v = static_cast<std::int64_t>(total);
  return std::chrono::nanoseconds(negative ? -v : v);
}

}  // namespace mcxanon::cli
