// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>

using namespace mcxanon;

TEST_CASE("VLAN IDs map consistently into 1-4094", "[pseudo][vlan]") {
  Secret s{};
  s[0] = 1;
  Mapping m;
  Pseudonymiser p(s, m);
  std::set<std::uint16_t> seen;
  for (std::uint16_t v = 1; v < 300; ++v) {
    const auto r = p.vlan(v);
    REQUIRE(r.has_value());
    CHECK(*r >= 1);
    CHECK(*r <= 4094);
    CHECK(*p.vlan(v) == *r);
    seen.insert(*r);
  }
  CHECK(seen.size() == 299);  // collisions resolved, never shared
  CHECK(*p.vlan(0) == 0);
  CHECK(*p.vlan(4095) == 4095);
}

TEST_CASE("ephemeral ports map inside the configured range; service ports are kept", "[pseudo][ports]") {
  Secret s{};
  Mapping m;
  Pseudonymiser p(s, m, PseudonymiserOptions{false, 40000, 40999});
  for (const std::uint16_t port : {std::uint16_t{40000}, std::uint16_t{40500}, std::uint16_t{40999}}) {
    const auto r = *p.port(port);
    CHECK(r >= 40000);
    CHECK(r <= 40999);
    CHECK(*p.port(port) == r);
  }
  CHECK(*p.port(5060) == 5060);
  CHECK(*p.port(2152) == 2152);
  CHECK(*p.port(41000) == 41000);
}
