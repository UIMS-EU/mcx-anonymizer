// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mapping file format 2.
#include "mcxanon/error.hpp"

#include "pseudo/mapping.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {
Bytes text(std::string_view s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("a format 1 mapping file loads", "[mapping][format2]") {
  const std::string v1 = R"({"format": 1, "entries": [
    {"category": "ipv4", "original": "0a000001", "pseudonym": "f0000001", "counter": 0, "runs_seen": 3}]})";
  auto m = Mapping::from_json(v1);
  REQUIRE(m.has_value());
  CHECK(m->find(Category::ipv4, Bytes{10, 0, 0, 1})->runs_seen == 3);
  // The first save writes the current format (3 since feature 004).
  CHECK(m->to_json().find("\"format\": 5") != std::string::npos);
}

TEST_CASE("text originals are hex-encoded, including non-UTF-8 bytes", "[mapping][format2]") {
  Mapping m;
  REQUIRE(m.insert(MappingEntry{Category::sip_user, text("alice"), text("u-0011aabb"), 0, 0}));
  // Percent-decoding can yield any byte (RFC 3986 §2.1): 0xFF 0x00 are not UTF-8 text.
  REQUIRE(m.insert(MappingEntry{Category::sip_user, Bytes{'a', 0xFF, 0x00, 'z'}, text("u-0011aabc"),
                                0, 0}));
  REQUIRE(m.insert(MappingEntry{Category::domain, text("example.net"), text("d-12345678"), 2, 0}));
  const auto j = m.to_json();
  CHECK(j.find("\"original\": \"616c696365\"") != std::string::npos);
  CHECK(j.find("\"original\": \"61ff007a\"") != std::string::npos);
  CHECK(j.find("\"pseudonym\": \"752d3030313161616262\"") != std::string::npos);
  CHECK(j.find("alice") == std::string::npos);
  // Sorted by (category name, original bytes): "domain" before "sip-user", and within
  // sip-user 'a','l',... before 'a',0xFF,...
  CHECK(j.find("\"domain\"") < j.find("\"sip-user\""));
  CHECK(j.find("616c696365") < j.find("61ff007a"));
  auto back = Mapping::from_json(j);
  REQUIRE(back.has_value());
  CHECK(back->find(Category::sip_user, Bytes{'a', 0xFF, 0x00, 'z'}) != nullptr);
  CHECK(back->find(Category::domain, text("example.net"))->counter == 2);
  CHECK(back->to_json() == j);
}

TEST_CASE("an unknown mapping format is rejected as corrupt input", "[mapping][format2]") {
  for (const char* doc : {R"({"format": 6, "entries": []})", R"({"format": 0, "entries": []})",
                          R"({"format": "2", "entries": []})"}) {
    auto m = Mapping::from_json(doc);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().code == ErrorCode::input);
    CHECK(m.error().message == "mapping file is corrupt: unsupported format");
  }
}

TEST_CASE("every new category loads from format 2", "[mapping][format2]") {
  const std::string doc = R"({"format": 2, "entries": [
    {"category": "tel", "original": "2b3438363031323334353637", "pseudonym": "2b3438393939393939393939", "counter": 0, "runs_seen": 1},
    {"category": "spi", "original": "12345678", "pseudonym": "9abcdef0", "counter": 0, "runs_seen": 1},
    {"category": "cname", "original": "6162", "pseudonym": "636e2d303030303030303030303030", "counter": 0, "runs_seen": 1}]})";
  auto m = Mapping::from_json(doc);
  REQUIRE(m.has_value());
  CHECK(m->size() == 3);
}
