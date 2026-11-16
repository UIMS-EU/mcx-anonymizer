// SPDX-License-Identifier: GPL-3.0-or-later
//
// The reveal index (FR-015a).
#include "reveal/index.hpp"
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("index: reverse lookup for every family", "[reveal][index]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto v4 = f.ipv4(0x0A000001);
  const auto ss = f.ssrc(0x01020304);
  const auto tac = f.binary(Category::tac, 0x0C41);
  f.host("mcx.example.net");
  auto idx = reveal::Index::build(f.mapping);
  REQUIRE(idx.has_value());
  CHECK(idx->entries().size() == f.mapping.size());

  auto hits = idx->by_pseudonym(Family::sip_user, u);
  REQUIRE(hits.size() == 1);
  CHECK(idx->entry(hits[0]).original == bytes_of("alice"));

  const Bytes v4b{static_cast<std::uint8_t>(v4 >> 24), static_cast<std::uint8_t>(v4 >> 16),
                  static_cast<std::uint8_t>(v4 >> 8), static_cast<std::uint8_t>(v4)};
  hits = idx->by_pseudonym(Family::ipv4, v4b);
  REQUIRE(hits.size() == 1);
  CHECK(idx->entry(hits[0]).original == (Bytes{10, 0, 0, 1}));

  const Bytes ssb{static_cast<std::uint8_t>(ss >> 24), static_cast<std::uint8_t>(ss >> 16),
                  static_cast<std::uint8_t>(ss >> 8), static_cast<std::uint8_t>(ss)};
  CHECK(idx->by_pseudonym(Family::ssrc, ssb).size() == 1);
  CHECK(idx->by_pseudonym(Family::tac, Bytes{static_cast<std::uint8_t>(tac >> 8),
                                             static_cast<std::uint8_t>(tac)}).size() == 1);

  // Originals are indexed for lookup --original.
  CHECK(idx->by_original(Family::sip_user, std::string_view("alice")).size() == 1);
  CHECK(idx->by_original(Family::domain, std::string_view("example.net")).size() == 1);
}

TEST_CASE("index: text forms equal show-map's for addresses and numbers", "[reveal][index]") {
  CHECK(reveal::text_form(Category::ipv4, Bytes{10, 200, 0, 1}) == "10.200.0.1");
  CHECK(reveal::text_form(Category::mac, Bytes{0, 0, 0x5e, 0, 0x53, 1}) == "00:00:5e:00:53:01");
  CHECK(reveal::text_form(Category::ssrc, Bytes{0x3c, 0x3c, 0x3c, 0x07}) == "1010580487");
  CHECK(reveal::text_form(Category::sip_user, Bytes{'a', '\\', 'b'}) == "a\\b");  // raw, not escaped
}

TEST_CASE("index: exact patterns, folding and not-searchable entries", "[reveal][index]") {
  using reveal::exact_searchable;
  using reveal::folded;
  CHECK(exact_searchable(Category::sip_user));
  CHECK(exact_searchable(Category::call_id));
  CHECK(exact_searchable(Category::opaque));
  CHECK(exact_searchable(Category::plmn));
  CHECK_FALSE(exact_searchable(Category::domain));  // domain chains: recogniser
  CHECK_FALSE(exact_searchable(Category::tel));
  CHECK_FALSE(exact_searchable(Category::imei));
  CHECK_FALSE(exact_searchable(Category::sdp_sess));
  CHECK_FALSE(exact_searchable(Category::ssrc));
  CHECK_FALSE(exact_searchable(Category::ipv4));

  CHECK(folded(Category::call_id));
  CHECK(folded(Category::uuid));
  CHECK(folded(Category::session_id));
  CHECK(folded(Category::domain));
  CHECK_FALSE(folded(Category::sip_user));
  CHECK_FALSE(folded(Category::opaque));
  CHECK_FALSE(folded(Category::display_name));

  CHECK(reveal::small_space(Category::tac));
  CHECK(reveal::small_space(Category::vlan));
  CHECK(reveal::small_space(Category::port_eph));
  CHECK_FALSE(reveal::small_space(Category::ssrc));

  Fixture f;
  f.text(Category::call_id, "abc@host");
  f.text(Category::opaque, "xY");          // 2-byte pseudonym: not searchable
  f.text(Category::sdp_sess, "7");         // 1-digit pseudonym: not searchable
  f.text(Category::opaque, "Q9aB-77");     // searchable
  auto idx = reveal::Index::build(f.mapping);
  REQUIRE(idx.has_value());
  CHECK(idx->not_searchable() == 2);
  CHECK(idx->matcher().size() >= 2);
}

TEST_CASE("index: originals' forms for the pseudonym-and-original check", "[reveal][index]") {
  Fixture f;
  f.ipv4(0x0A000001);
  f.ssrc(0x01020304);
  f.user("Alice");
  auto idx = reveal::Index::build(f.mapping);
  REQUIRE(idx.has_value());
  CHECK(idx->is_original_form("10.0.0.1"));
  CHECK(idx->is_original_form("16909060"));  // 0x01020304 in decimal
  CHECK(idx->is_original_form("1020304"));   // and in hex without padding
  CHECK(idx->is_original_form("alice"));     // lowercase
  CHECK_FALSE(idx->is_original_form("bob"));
}
