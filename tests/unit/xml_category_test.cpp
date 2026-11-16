// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pseudonym categories of feature 003.
#include "pseudo/category.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <set>
#include <string>

using namespace mcxanon;

namespace {
Secret secret(std::uint8_t seed = 11) {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * seed + 1);
  return s;
}

char klass(char c) {
  if (std::isdigit(static_cast<unsigned char>(c))) return 'd';
  if (std::islower(static_cast<unsigned char>(c))) return 'l';
  if (std::isupper(static_cast<unsigned char>(c))) return 'u';
  return c;
}
}  // namespace

TEST_CASE("opaque keeps length and per-character class", "[pseudo][xml]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::string_view v : {"tuple-1A", "Ab3_x.y-Z9", "p-id:0001", "users/sip:joe@example.com"}) {
    auto r = p.text(Category::opaque, v);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == v.size());
    for (std::size_t i = 0; i < v.size(); ++i) CHECK(klass((*r)[i]) == klass(v[i]));
    CHECK(*r != v);
    auto again = p.text(Category::opaque, v);
    REQUIRE(again.has_value());
    CHECK(*again == *r);  // deterministic within a project
  }
}

TEST_CASE("nci, nr_tac and mbs_fsa keep their bit width", "[pseudo][xml]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  std::set<std::uint64_t> seen;
  for (std::uint64_t v : {std::uint64_t{1}, std::uint64_t{0xFFFFFFFFFull}, std::uint64_t{0x123456789ull}}) {
    auto r = p.binary64(Category::nci, v);
    REQUIRE(r.has_value());
    CHECK(*r <= 0xFFFFFFFFFull);
    seen.insert(*r);
  }
  CHECK(seen.size() == 3);
  for (std::uint32_t v : {1u, 0xFFFFFFu, 0x123456u}) {
    auto a = p.binary(Category::nr_tac, v);
    auto b = p.binary(Category::mbs_fsa, v);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(*a <= 0xFFFFFFu);
    CHECK(*b <= 0xFFFFFFu);
  }
  CHECK_FALSE(p.binary64(Category::nci, 0x1000000000ull).has_value());  // wider than 36 bits
  CHECK_FALSE(p.binary(Category::nr_tac, 0x1000000u).has_value());
}

TEST_CASE("the new categories have their own names and domain labels", "[pseudo][xml]") {
  CHECK(to_string(Category::opaque) == "opaque");
  CHECK(to_string(Category::nci) == "nci");
  CHECK(to_string(Category::nr_tac) == "nr-tac");
  CHECK(to_string(Category::mbs_fsa) == "mbs-fsa");
  CHECK(binary_bits(Category::nci) == 36);
  CHECK(binary_bits(Category::nr_tac) == 24);
  CHECK(binary_bits(Category::mbs_fsa) == 24);
  // The same value under two categories gives unrelated pseudonyms (domain separation).
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  auto a = p.binary(Category::nr_tac, 0x00ABCD);
  auto b = p.binary(Category::mbs_fsa, 0x00ABCD);
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(*a != *b);
}
