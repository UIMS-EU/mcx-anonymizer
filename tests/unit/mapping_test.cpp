// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "bytes/hex.hpp"
#include "pseudo/mapping.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>
#include <vector>

using namespace mcxanon;

namespace {
MappingEntry entry(Category c, Bytes orig, Bytes pseudo, std::uint32_t counter = 0) {
  return MappingEntry{c, std::move(orig), std::move(pseudo), counter, 0};
}
}  // namespace

TEST_CASE("forward and reverse lookup", "[mapping]") {
  Mapping m;
  REQUIRE(m.insert(entry(Category::ipv4, {10, 0, 0, 1}, {0xF1, 2, 3, 4})).has_value());
  const auto* e = m.find(Category::ipv4, Bytes{10, 0, 0, 1});
  REQUIRE(e != nullptr);
  CHECK(e->pseudonym == Bytes{0xF1, 2, 3, 4});
  CHECK(m.find(Category::ipv4, Bytes{10, 0, 0, 2}) == nullptr);
  CHECK(m.find(Category::ipv6, Bytes{10, 0, 0, 1}) == nullptr);
  CHECK(m.pseudonym_taken(Category::ipv4, Bytes{0xF1, 2, 3, 4}));
  CHECK_FALSE(m.pseudonym_taken(Category::ipv4, Bytes{0xF1, 2, 3, 5}));
  CHECK(m.size() == 1);
}

TEST_CASE("an original equal to an issued pseudonym of the family is detected", "[mapping]") {
  Mapping m;
  REQUIRE(m.insert(entry(Category::ipv4, {10, 0, 0, 1}, {0xF1, 2, 3, 4})).has_value());
  REQUIRE(m.insert(entry(Category::ipv4_mcast, {239, 1, 1, 1}, {233, 252, 0, 9})).has_value());
  CHECK(m.is_issued_pseudonym(Category::ipv4, Bytes{0xF1, 2, 3, 4}));
  CHECK(m.is_issued_pseudonym(Category::ipv4_pp, Bytes{0xF1, 2, 3, 4}));  // same family
  CHECK(m.is_issued_pseudonym(Category::ipv4, Bytes{233, 252, 0, 9}));
  CHECK_FALSE(m.is_issued_pseudonym(Category::ipv6, Bytes{0xF1, 2, 3, 4}));
  CHECK(m.is_known_original(Category::ipv4, Bytes{10, 0, 0, 1}));
  CHECK_FALSE(m.is_known_original(Category::ipv4, Bytes{0xF1, 2, 3, 4}));
}

TEST_CASE("the mapping is append-only", "[mapping]") {
  Mapping m;
  REQUIRE(m.insert(entry(Category::mac, {0, 1, 2, 3, 4, 5}, {2, 1, 2, 3, 4, 5})).has_value());
  auto again = m.insert(entry(Category::mac, {0, 1, 2, 3, 4, 5}, {6, 1, 2, 3, 4, 5}));
  REQUIRE_FALSE(again.has_value());
  CHECK(again.error().code == ErrorCode::internal);
  auto clash = m.insert(entry(Category::mac, {0, 9, 9, 9, 9, 9}, {2, 1, 2, 3, 4, 5}));
  REQUIRE_FALSE(clash.has_value());  // pseudonym already issued in the category
  CHECK(m.find(Category::mac, Bytes{0, 1, 2, 3, 4, 5})->pseudonym == Bytes{2, 1, 2, 3, 4, 5});
}

TEST_CASE("serialisation is deterministic and sorted", "[mapping]") {
  Mapping a;
  REQUIRE(a.insert(entry(Category::ipv4, {10, 0, 0, 2}, {0xF0, 0, 0, 2}, 1)).has_value());
  REQUIRE(a.insert(entry(Category::ipv4, {10, 0, 0, 1}, {0xF0, 0, 0, 1})).has_value());
  REQUIRE(a.insert(entry(Category::mac, {0, 1, 2, 3, 4, 5}, {2, 1, 2, 3, 4, 5})).has_value());
  Mapping b;
  REQUIRE(b.insert(entry(Category::mac, {0, 1, 2, 3, 4, 5}, {2, 1, 2, 3, 4, 5})).has_value());
  REQUIRE(b.insert(entry(Category::ipv4, {10, 0, 0, 1}, {0xF0, 0, 0, 1})).has_value());
  REQUIRE(b.insert(entry(Category::ipv4, {10, 0, 0, 2}, {0xF0, 0, 0, 2}, 1)).has_value());
  const std::string ja = a.to_json();
  CHECK(ja == b.to_json());
  CHECK(ja.find("\"format\": 5") != std::string::npos);
  CHECK(ja.find("0a000001") < ja.find("0a000002"));
  CHECK(ja.find("\"ipv4\"") < ja.find("\"mac\""));

  auto back = Mapping::from_json(ja);
  REQUIRE(back.has_value());
  CHECK(back->size() == 3);
  CHECK(back->find(Category::ipv4, Bytes{10, 0, 0, 2})->counter == 1);
  CHECK(back->to_json() == ja);
}

TEST_CASE("runs_seen is preserved and can be bumped", "[mapping]") {
  Mapping m;
  REQUIRE(m.insert(entry(Category::vlan, {0, 100}, {0x0F, 0xA0})).has_value());
  m.mark_seen(Category::vlan, Bytes{0, 100});
  m.mark_seen(Category::vlan, Bytes{0, 100});
  CHECK(m.find(Category::vlan, Bytes{0, 100})->runs_seen == 2);
}

TEST_CASE("corrupt or truncated mapping files are input errors", "[mapping]") {
  for (const char* bad : {"", "{", "{\"format\": 6, \"entries\": []}", "{\"entries\": []}",
                          "{\"format\": 1, \"entries\": [{\"category\": \"ipv4\"}]}",
                          "{\"format\": 1, \"entries\": [{\"category\": \"nope\", \"original\": "
                          "\"00\", \"pseudonym\": \"00\", \"counter\": 0, \"runs_seen\": 0}]}",
                          "{\"format\": 1, \"entries\": [{\"category\": \"ipv4\", \"original\": "
                          "\"zz\", \"pseudonym\": \"f0000001\", \"counter\": 0, \"runs_seen\": "
                          "0}]}"}) {
    auto m = Mapping::from_json(bad);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().code == ErrorCode::input);
  }
  CHECK(Mapping::from_json("{\"format\": 1, \"entries\": []}").has_value());
}

TEST_CASE("category names round-trip", "[mapping]") {
  for (auto c : {Category::mac, Category::ipv4, Category::ipv4_pp, Category::ipv6,
                 Category::ipv6_pp, Category::ipv6_iid_ll, Category::ipv6_sn24,
                 Category::ipv4_mcast, Category::vlan, Category::port_eph}) {
    auto back = category_from_string(to_string(c));
    REQUIRE(back.has_value());
    CHECK(*back == c);
  }
  CHECK(to_string(Category::port_eph) == "port-eph");
  CHECK_FALSE(category_from_string("ipv5").has_value());
}

// The streaming serialiser (R22: no JSON document of the whole mapping in memory) writes
// exactly what nlohmann::json::dump(2) writes for the same document.
TEST_CASE("the serialised mapping is byte-identical to the JSON document form", "[mapping]") {
  const auto reference = [](const Mapping& m) {
    nlohmann::json entries = nlohmann::json::array();
    std::vector<const MappingEntry*> sorted;
    for (const auto& [k, v] : m.entries()) sorted.push_back(&v);
    std::sort(sorted.begin(), sorted.end(), [](const MappingEntry* a, const MappingEntry* b) {
      return std::pair(to_string(a->category), a->original) < std::pair(to_string(b->category), b->original);
    });
    for (const auto* e : sorted) {
      entries.push_back({{"category", std::string(to_string(e->category))},
                         {"original", to_hex(e->original)},
                         {"pseudonym", to_hex(e->pseudonym)},
                         {"counter", e->counter},
                         {"runs_seen", e->runs_seen}});
    }
    return nlohmann::json{{"format", 5}, {"entries", entries}}.dump(2) + "\n";
  };
  Mapping m;
  CHECK(m.to_json() == reference(m));
  REQUIRE(m.insert({Category::ipv4, {10, 0, 0, 1}, {240, 0, 0, 1}, 0, 1}));
  CHECK(m.to_json() == reference(m));
  REQUIRE(m.insert({Category::mac, {2, 0, 0, 0, 0, 1}, {2, 0, 0, 0, 0, 2}, 4294967295u, 7}));
  REQUIRE(m.insert({Category::domain, {'e', 'x', 0xff}, {'d', '-', '1'}, 3, 0}));
  REQUIRE(m.insert({Category::sip_user, {}, {'u'}, 0, 0}));
  REQUIRE(m.insert({Category::ipv4, {10, 0, 0, 0}, {240, 0, 0, 2}, 12, 100}));
  CHECK(m.to_json() == reference(m));
}
