// SPDX-License-Identifier: GPL-3.0-or-later
//
// The resolver: core, ambiguity and unknown shapes (FR-012, FR-013, FR-015, FR-015a, FR-016, FR-017a).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
Bytes b(std::string_view s) { return Bytes(s.begin(), s.end()); }
void put(Mapping& m, Category c, std::string_view orig, std::string_view pseudo) {
  REQUIRE(m.insert(MappingEntry{c, b(orig), b(pseudo), 0, 0}).has_value());
}
}  // namespace

TEST_CASE("resolve: a match must start and end at a boundary", "[reveal][resolve]") {
  Fixture f;
  const auto u = f.user("alice");
  CHECK(f.reveal("from " + u + " to") == "from alice to");
  CHECK(f.reveal("<sip:" + u + "@x>") == "<sip:alice@x>");
  CHECK(f.reveal("x" + u) == "x" + u);        // glued on the left
  CHECK(f.reveal(u + "7") == u + "7");        // glued on the right
  CHECK(f.reveal(u + "_a") == u + "_a");
  CHECK(f.reveal("\"" + u + "\"") == "\"alice\"");
}

TEST_CASE("resolve: the longest of overlapping candidates wins", "[reveal][resolve]") {
  Fixture f;
  put(f.mapping, Category::opaque, "Short-Orig", "Kq7x-Zm");
  put(f.mapping, Category::opaque, "Long-Original-1", "Kq7x-Zm-Lp9");
  CHECK(f.reveal("id Kq7x-Zm-Lp9 end") == "id Long-Original-1 end");
  CHECK(f.reveal("id Kq7x-Zm end") == "id Short-Orig end");
}

TEST_CASE("resolve: equal candidates with different originals are ambiguous", "[reveal][resolve]") {
  Fixture f;
  put(f.mapping, Category::opaque, "first-one", "Zz9-Qq8x");
  put(f.mapping, Category::msrp_tid, "second-1", "Zz9-Qq8x");
  RevealSummary s;
  CHECK(f.reveal("t Zz9-Qq8x", {}, &s) == "t Zz9-Qq8x");
  REQUIRE(s.candidates.size() == 1);
  CHECK(s.candidates[0].ambiguity == "overlap");
  CHECK(s.candidates[0].category == "msrp-tid|opaque");
  CHECK(s.candidates[0].line == 1);
  CHECK(s.candidates[0].column == 3);
  // --replace-ambiguous replaces overlap candidates with the first original in category order.
  RevealOptions o;
  o.replace_ambiguous = true;
  CHECK(f.reveal("t Zz9-Qq8x", o) == "t second-1");
}

TEST_CASE("resolve: a pseudonym that is also an original is never replaced", "[reveal][resolve]") {
  Fixture f;
  put(f.mapping, Category::sip_user, "Rq7-Bob1", "u-11111111");
  put(f.mapping, Category::opaque, "zzz-Qqq1", "Rq7-Bob1");
  RevealSummary s;
  RevealOptions o;
  o.replace_ambiguous = true;
  CHECK(f.reveal("x Rq7-Bob1 y", o, &s) == "x Rq7-Bob1 y");
  REQUIRE(s.candidates.size() == 1);
  CHECK(s.candidates[0].ambiguity == "pseudonym-and-original");
  CHECK(s.candidates[0].original == "zzz-Qqq1");
}

TEST_CASE("ambiguity: small value spaces and short matches (FR-015, FR-016)", "[reveal][resolve]") {
  Fixture f;
  const auto tac = f.binary(Category::tac, 0x0C41);
  const auto vlan = f.p.vlan(214);
  REQUIRE(vlan.has_value());
  const auto shortp = f.text(Category::opaque, "Ab3x");  // 4 bytes: short
  const auto u = f.user("alice");
  const std::string in = "tac " + std::to_string(tac) + " vlan " + std::to_string(*vlan) + " id " + shortp +
                         " user " + u;
  RevealSummary s;
  CHECK(f.reveal(in, {}, &s) == "tac " + std::to_string(tac) + " vlan " + std::to_string(*vlan) + " id " + shortp +
                                    " user alice");
  CHECK(s.revealed.at("sip-user") == 1);
  CHECK(s.ambiguous.at("tac") == 1);
  CHECK(s.ambiguous.at("vlan") == 1);
  CHECK(s.ambiguous.at("opaque") == 1);
  RevealOptions o;
  o.replace_ambiguous = true;
  CHECK(f.reveal(in, o) == "tac 3137 vlan 214 id Ab3x user alice");
}

TEST_CASE("ambiguity: a short telephone number is small-space, a long one is not", "[reveal][resolve]") {
  Fixture f;
  const auto t4 = f.tel("4711");
  const auto t11 = f.tel("+48601234567");
  RevealSummary s;
  CHECK(f.reveal("ext " + t4 + " mobile " + t11, {}, &s) == "ext " + t4 + " mobile +48601234567");
  CHECK(s.ambiguous.at("tel") == 1);
  CHECK(s.revealed.at("tel") == 1);
}

TEST_CASE("ambiguity: pseudonyms of 1 to 3 bytes are not searched (FR-015a)", "[reveal][resolve]") {
  Fixture f;
  const auto p = f.text(Category::sdp_sess, "7");
  RevealSummary s;
  CHECK(f.reveal("o=- " + p + " 1 IN", {}, &s) == "o=- " + p + " 1 IN");
  CHECK(s.candidates.empty());
  CHECK(s.not_searchable == 1);
}

TEST_CASE("unknown: pseudonym-shaped values missing from the mapping (FR-017a)", "[reveal][resolve]") {
  Fixture f;
  f.user("alice");
  RevealSummary s;
  const std::string in = "sip:u-0badcafe@d-0badcafe.invalid c-0123456789abcdef 240.1.2.3 2001:db8::77 "
                         "u-12345 255.255.255.255 de:ad:be:ef:00:01";
  CHECK(f.reveal(in, {}, &s) == in);
  CHECK(s.unknown.at("sip-user") == 1);
  CHECK(s.unknown.at("domain") == 1);
  CHECK(s.unknown.at("call-id") == 1);
  CHECK(s.unknown.at("ipv4") == 1);
  CHECK(s.unknown.at("ipv6") == 1);
  std::size_t unknown = 0;
  for (const auto& c : s.candidates) unknown += c.kind == RevealKind::unknown ? 1 : 0;
  CHECK(unknown == 5);  // not u-12345 (wrong length), not the broadcast address, not the MAC
}
