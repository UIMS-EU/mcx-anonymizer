// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mapping format 5 and the categories key-id, nonce and uid of feature 005.
#include "mcxanon/error.hpp"

#include "pseudo/category.hpp"
#include "pseudo/mapping.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>

using namespace mcxanon;

namespace {
Secret secret(std::uint8_t k = 7) {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * k);
  return s;
}
}  // namespace

TEST_CASE("key-id keeps the purpose tag, is unique and never maps onto itself", "[mapping][format5]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  std::set<std::uint32_t> seen;
  for (std::uint32_t tag = 0; tag < 16; ++tag) {
    for (std::uint32_t low = 0; low < 64; ++low) {
      const std::uint32_t original = (tag << 28) | (low * 0x0012345u & 0x0FFFFFFFu);
      auto k = p.key_id(original);
      REQUIRE(k.has_value());
      CHECK((*k >> 28) == tag);
      CHECK(*k != original);
      CHECK(seen.insert(*k).second);
      auto again = p.key_id(original);
      REQUIRE(again.has_value());
      CHECK(*again == *k);
    }
  }
  // The same secret gives the same pseudonym in another run.
  Mapping m2;
  Pseudonymiser p2(s, m2);
  auto a = p.key_id(0x1ABCDEF0u);
  auto b = p2.key_id(0x1ABCDEF0u);
  REQUIRE((a && b));
  CHECK(*a == *b);
}

TEST_CASE("find_key_id never creates an entry", "[mapping][format5]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  CHECK_FALSE(p.find_key_id(0x2000AAAAu).has_value());
  CHECK(m.size() == 0);
  auto k = p.key_id(0x2000AAAAu);
  REQUIRE(k.has_value());
  auto f = p.find_key_id(0x2000AAAAu);
  REQUIRE(f.has_value());
  CHECK(*f == *k);
}

TEST_CASE("nonce and uid keep the length and never map onto themselves", "[mapping][format5]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::size_t n : {1u, 16u, 32u, 255u}) {
    Bytes o(n, 0x52);
    auto r = p.bytes(Category::nonce, o);
    REQUIRE(r.has_value());
    CHECK(r->size() == n);
    CHECK(*r != o);
    auto again = p.bytes(Category::nonce, o);
    REQUIRE(again.has_value());
    CHECK(*again == *r);
  }
  auto u = p.bytes(Category::uid, Bytes(32, 0x55));
  REQUIRE(u.has_value());
  CHECK(u->size() == 32);
  CHECK_FALSE(p.bytes(Category::nonce, Bytes{}).has_value());
  CHECK_FALSE(p.bytes(Category::nonce, Bytes(256, 1)).has_value());
  CHECK_FALSE(p.bytes(Category::uid, Bytes(31, 1)).has_value());
  CHECK_FALSE(p.bytes(Category::sip_user, Bytes(4, 1)).has_value());
}

TEST_CASE("the new categories: names, families and predicates", "[mapping][format5]") {
  for (auto [c, name] : {std::pair{Category::key_id, "key-id"}, std::pair{Category::nonce, "nonce"},
                         std::pair{Category::uid, "uid"}}) {
    CHECK(to_string(c) == name);
    auto back = category_from_string(name);
    REQUIRE(back.has_value());
    CHECK(*back == c);
  }
  CHECK(is_binary_category(Category::key_id));
  CHECK(binary_bits(Category::key_id) == 32);
  CHECK_FALSE(is_text_category(Category::key_id));
  CHECK(is_byte_category(Category::nonce));
  CHECK(is_byte_category(Category::uid));
  CHECK_FALSE(is_text_category(Category::nonce));
  CHECK_FALSE(is_text_category(Category::uid));
  CHECK_FALSE(is_binary_category(Category::uid));
  CHECK(family_of(Category::key_id) == Family::key_id);
  CHECK(family_of(Category::nonce) == Family::nonce);
  CHECK(family_of(Category::uid) == Family::uid);
}

TEST_CASE("formats 1 to 4 load; the first save writes format 5", "[mapping][format5]") {
  for (const char* doc : {R"({"format": 1, "entries": []})", R"({"format": 4, "entries": [
    {"category": "nci", "original": "0123456789", "pseudonym": "0abcdef012", "counter": 0, "runs_seen": 1}]})"}) {
    auto m = Mapping::from_json(doc);
    REQUIRE(m.has_value());
    CHECK(m->to_json().find("\"format\": 5") != std::string::npos);
  }
  const std::string doc = R"({"format": 5, "entries": [
    {"category": "key-id", "original": "1abcdef0", "pseudonym": "1234abcd", "counter": 0, "runs_seen": 1},
    {"category": "nonce", "original": "52525252525252525252525252525252", "pseudonym": "0102030405060708090a0b0c0d0e0f10", "counter": 0, "runs_seen": 1},
    {"category": "uid", "original": "5555555555555555555555555555555555555555555555555555555555555555", "pseudonym": "6666666666666666666666666666666666666666666666666666666666666666", "counter": 0, "runs_seen": 1}]})";
  auto m = Mapping::from_json(doc);
  REQUIRE(m.has_value());
  CHECK(m->size() == 3);
  auto again = Mapping::from_json(m->to_json());
  REQUIRE(again.has_value());
  CHECK(again->to_json() == m->to_json());
  CHECK_FALSE(Mapping::from_json(R"({"format": 6, "entries": []})").has_value());
}

TEST_CASE("show-map prints key-id as 8 hex digits and nonce and uid as hex", "[mapping][format5]") {
  CHECK(format_mapping_value(Category::key_id, Bytes{0x1a, 0xbc, 0xde, 0xf0}) == "1abcdef0");
  CHECK(format_mapping_value(Category::key_id, Bytes{0x00, 0x00, 0x00, 0x05}) == "00000005");
  CHECK(format_mapping_value(Category::nonce, Bytes{0x01, 0xff}) == "01ff");
  CHECK(format_mapping_value(Category::uid, Bytes(2, 0xab)) == "abab");
  // Existing categories keep their format.
  CHECK(format_mapping_value(Category::ssrc, Bytes{0, 0, 1, 0}) == "256");
  CHECK(format_mapping_value(Category::ipv4, Bytes{10, 0, 0, 1}) == "10.0.0.1");
}
