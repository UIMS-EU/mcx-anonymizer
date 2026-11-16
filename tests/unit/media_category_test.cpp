// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pseudonym categories of feature 004.
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <set>
#include <string>

using namespace mcxanon;

namespace {
Secret secret(std::uint8_t seed = 7) {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * seed + 3);
  return s;
}

std::uint32_t bin(Pseudonymiser& p, Category c, std::uint32_t v) {
  auto r = p.binary(c, v);
  REQUIRE(r.has_value());
  return *r;
}

std::string text(Pseudonymiser& p, Category c, std::string_view v) {
  auto r = p.text(c, v);
  REQUIRE(r.has_value());
  return *r;
}

bool ident_char(char ch) {
  return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '.' || ch == '-' || ch == '+' ||
         ch == '%' || ch == '=';
}
}  // namespace

TEST_CASE("binary media categories keep their bit width", "[pseudo][media]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::uint32_t v : {0x00000001u, 0x0FFFFFFFu, 0x01234567u, 0x0ABCDEF0u}) {
    CHECK(bin(p, Category::eci, v) <= 0x0FFFFFFFu);
  }
  for (std::uint32_t v : {1u, 0xFFFFu, 0x1234u}) {
    CHECK(bin(p, Category::tac, v) <= 0xFFFFu);
    CHECK(bin(p, Category::mbms_sai, v) <= 0xFFFFu);
  }
  for (std::uint32_t v : {0u, 1u, 255u}) CHECK(bin(p, Category::mbsfn_area, v) <= 0xFFu);
  // fc_ref uses the whole 32-bit range.
  std::set<std::uint32_t> seen;
  bool high = false;
  for (std::uint32_t v = 1; v <= 64; ++v) {
    const auto r = bin(p, Category::fc_ref, v);
    seen.insert(r);
    high = high || r > 0x0FFFFFFFu;
  }
  CHECK(seen.size() == 64);
  CHECK(high);
}

TEST_CASE("an original outside the category width is an internal error", "[pseudo][media]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  CHECK_FALSE(p.binary(Category::eci, 0x10000000u).has_value());
  CHECK_FALSE(p.binary(Category::tac, 0x10000u).has_value());
  CHECK_FALSE(p.binary(Category::mbsfn_area, 0x100u).has_value());
  CHECK_FALSE(p.binary(Category::ssrc, 1u).has_value());  // ssrc has its own entry point
}

TEST_CASE("binary media pseudonyms are deterministic and domain-separated", "[pseudo][media]") {
  const auto s = secret();
  Mapping m1, m2;
  Pseudonymiser p1(s, m1), p2(s, m2);
  CHECK(bin(p1, Category::fc_ref, 0xCAFE0001u) == bin(p2, Category::fc_ref, 0xCAFE0001u));
  // The same 32-bit value is an SSRC in one place and a floor participant reference in another:
  // the pseudonyms are unrelated.
  auto ssrc = p1.ssrc(0xCAFE0002u);
  REQUIRE(ssrc.has_value());
  CHECK(*ssrc != bin(p1, Category::fc_ref, 0xCAFE0002u));
  CHECK(bin(p1, Category::tac, 0x0102u) == bin(p2, Category::tac, 0x0102u));
}

TEST_CASE("mbsfn-area, tac and mbms-sai are small spaces without collision exit", "[pseudo][media]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  // Every value of the 8-bit space can be mapped even though originals meet issued pseudonyms.
  for (std::uint32_t v = 0; v < 200; ++v) CHECK(p.binary(Category::mbsfn_area, v).has_value());
  for (std::uint32_t v = 0; v < 2048; ++v) CHECK(p.binary(Category::tac, v).has_value());
}

TEST_CASE("plmn pseudonyms keep the digit count", "[pseudo][media]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::string_view v : {"26201", "310410", "00101"}) {
    const auto r = text(p, Category::plmn, v);
    CHECK(r.size() == v.size());
    CHECK(std::all_of(r.begin(), r.end(), [](char ch) { return ch >= '0' && ch <= '9'; }));
  }
  CHECK_FALSE(p.text(Category::plmn, "2620F").has_value());  // the caller strips the filler
  CHECK(text(p, Category::plmn, "26201") == text(p, Category::plmn, "26201"));
}

TEST_CASE("msrp transaction and message ids keep length and the ident grammar", "[pseudo][media]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::string_view v : {"a1b2", "tid0001", "Zx.9-+%=Q", "0123456789abcdefABCDEF.-+%=xyz01"}) {
    for (auto c : {Category::msrp_tid, Category::msrp_msgid}) {
      const auto r = text(p, c, v);
      CHECK(r.size() == v.size());
      CHECK(std::isalnum(static_cast<unsigned char>(r[0])) != 0);
      CHECK(std::all_of(r.begin(), r.end(), ident_char));
      CHECK(r != v);
    }
  }
  // Transaction ids and message ids have separate namespaces.
  CHECK(text(p, Category::msrp_tid, "abcdefgh") != text(p, Category::msrp_msgid, "abcdefgh"));
}

TEST_CASE("the new categories have stable names", "[pseudo][media]") {
  for (auto [c, name] : {std::pair{Category::fc_ref, "fc-ref"}, std::pair{Category::plmn, "plmn"},
                         std::pair{Category::eci, "eci"}, std::pair{Category::tac, "tac"},
                         std::pair{Category::mbms_sai, "mbms-sai"}, std::pair{Category::mbsfn_area, "mbsfn-area"},
                         std::pair{Category::msrp_tid, "msrp-tid"}, std::pair{Category::msrp_msgid, "msrp-msgid"}}) {
    CHECK(to_string(c) == name);
    auto back = category_from_string(name);
    REQUIRE(back.has_value());
    CHECK(*back == c);
  }
  CHECK(is_binary_category(Category::fc_ref));
  CHECK(is_binary_category(Category::ssrc));
  CHECK_FALSE(is_binary_category(Category::plmn));
  CHECK(is_text_category(Category::msrp_tid));
}
