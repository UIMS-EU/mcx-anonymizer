// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/duration.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace std::chrono;

TEST_CASE("duration grammar", "[time]") {
  CHECK(*cli::parse_duration("-30d") == -hours(24 * 30));
  CHECK(*cli::parse_duration("+1h30m") == minutes(90));
  CHECK(*cli::parse_duration("1h30m") == minutes(90));
  CHECK(*cli::parse_duration("-250ms") == -milliseconds(250));
  CHECK(*cli::parse_duration("2s500us7ns") == seconds(2) + microseconds(500) + nanoseconds(7));
  for (const char* bad : {"", "-", "30", "30x", "d", "1h-2m", "1.5h", "99999999999999999999d", "+ 1h"}) {
    INFO(bad);
    auto r = cli::parse_duration(bad);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == ErrorCode::usage);
  }
}
