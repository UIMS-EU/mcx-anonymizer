// SPDX-License-Identifier: GPL-3.0-or-later
//
// Lookup in both directions (FR-020, FR-021, FR-022, P2).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using reveal_test::dotted;
using reveal_test::Fixture;

namespace {
std::vector<LookupResult> look(Fixture& f, std::string_view v, LookupDirection d, std::string* unresolved = nullptr) {
  auto r = reveal::lookup_mapping(f.mapping, v, d, unresolved);
  REQUIRE(r.has_value());
  return *r;
}
}  // namespace

TEST_CASE("lookup: pseudonym to original", "[reveal][lookup]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto h = f.host("mcx.example.net");
  const auto ip = dotted(f.ipv4(0x0A0000FE));
  const auto tac = std::to_string(f.binary(Category::tac, 0x0C41));
  const auto before = f.mapping.size();

  auto r = look(f, u, LookupDirection::to_original);
  REQUIRE(r.size() == 1);
  CHECK(r[0].category == "sip-user");
  CHECK(r[0].query == u);
  CHECK(r[0].counterpart == "alice");

  r = look(f, ip, LookupDirection::to_original);
  REQUIRE(r.size() == 1);
  CHECK(r[0].category == "ipv4");
  CHECK(r[0].counterpart == "10.0.0.254");

  // Small-space values resolve too (a lookup is explicit).
  r = look(f, tac, LookupDirection::to_original);
  REQUIRE(r.size() == 1);
  CHECK(r[0].counterpart == "3137");

  // A composite: one line per component plus the composite.
  r = look(f, "sip:" + u + "@" + h, LookupDirection::to_original);
  REQUIRE(r.size() == 3);
  CHECK(r[0].category == "sip-user");
  CHECK(r[1].category == "domain");
  CHECK(r[1].counterpart == "mcx.example.net");
  CHECK(r[2].category == "composite");
  CHECK(r[2].counterpart == "sip:alice@mcx.example.net");

  CHECK(look(f, "u-0badcafe", LookupDirection::to_original).empty());
  CHECK(f.mapping.size() == before);
}

TEST_CASE("lookup: a value that is a pseudonym in two categories", "[reveal][lookup]") {
  Fixture f;
  const Bytes p{'Z', 'z', '9', '-', 'Q', 'q', '8', 'x'};
  REQUIRE(f.mapping.insert(MappingEntry{Category::opaque, Bytes{'o', 'n', 'e', '-', '1'}, p, 0, 0}).has_value());
  REQUIRE(f.mapping.insert(MappingEntry{Category::msrp_tid, Bytes{'t', 'w', 'o', '-', '2'}, p, 0, 0}).has_value());
  const auto r = look(f, "Zz9-Qq8x", LookupDirection::to_original);
  REQUIRE(r.size() == 2);
  CHECK(r[0].category == "msrp-tid");
  CHECK(r[0].counterpart == "two-2");
  CHECK(r[1].category == "opaque");
  CHECK(r[1].counterpart == "one-1");
}

TEST_CASE("lookup --original: seen originals only, composites all or nothing", "[reveal][lookup]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto h = f.host("mcx.example.net");
  const auto ip = dotted(f.ipv4(0x0A0000FE));
  const auto t = f.tel("+48601234567");
  const auto before = f.mapping.size();

  auto r = look(f, "10.0.0.254", LookupDirection::to_pseudonym);
  REQUIRE(r.size() == 1);
  CHECK(r[0].category == "ipv4");
  CHECK(r[0].counterpart == ip);

  r = look(f, "alice", LookupDirection::to_pseudonym);
  REQUIRE(r.size() == 1);
  CHECK(r[0].counterpart == u);

  r = look(f, "mcx.example.net", LookupDirection::to_pseudonym);
  REQUIRE(r.size() == 1);
  CHECK(r[0].category == "domain");
  CHECK(r[0].counterpart == h);

  r = look(f, "tel:+48601234567", LookupDirection::to_pseudonym);
  REQUIRE_FALSE(r.empty());
  CHECK(r.back().counterpart == "tel:" + t);

  r = look(f, "sip:alice@mcx.example.net", LookupDirection::to_pseudonym);
  REQUIRE(r.size() == 3);
  CHECK(r[2].category == "composite");
  CHECK(r[2].counterpart == "sip:" + u + "@" + h);

  // An unseen component: nothing, and the component is named.
  std::string missing;
  CHECK(look(f, "sip:bob@mcx.example.net", LookupDirection::to_pseudonym, &missing).empty());
  CHECK(missing == "bob");
  CHECK(look(f, "sip:alice@other.example.org", LookupDirection::to_pseudonym, &missing).empty());
  CHECK(missing == "other.example.org");
  CHECK(look(f, "192.0.2.99", LookupDirection::to_pseudonym, &missing).empty());
  CHECK(f.mapping.size() == before);  // never issues a pseudonym
}
