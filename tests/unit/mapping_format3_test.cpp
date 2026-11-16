// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mapping file format 3.
#include "mcxanon/error.hpp"

#include "pseudo/mapping.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

TEST_CASE("format 1 and format 2 mapping files load; the first save writes the current format", "[mapping][format3]") {
  for (const char* doc : {R"({"format": 1, "entries": [
    {"category": "ipv4", "original": "0a000001", "pseudonym": "f0000001", "counter": 0, "runs_seen": 3}]})",
                          R"({"format": 2, "entries": [
    {"category": "cname", "original": "6162", "pseudonym": "636e2d30", "counter": 0, "runs_seen": 1}]})"}) {
    auto m = Mapping::from_json(doc);
    REQUIRE(m.has_value());
    CHECK(m->size() == 1);
    CHECK(m->to_json().find("\"format\": 5") != std::string::npos);  // feature 003
  }
  CHECK(Mapping{}.to_json().find("\"format\": 5") != std::string::npos);
}

TEST_CASE("the media categories load from format 3", "[mapping][format3]") {
  const std::string doc = R"({"format": 3, "entries": [
    {"category": "fc-ref", "original": "cafe0001", "pseudonym": "12345678", "counter": 0, "runs_seen": 1},
    {"category": "plmn", "original": "3236323031", "pseudonym": "3931373534", "counter": 0, "runs_seen": 1},
    {"category": "eci", "original": "01234567", "pseudonym": "0abcdef0", "counter": 0, "runs_seen": 1},
    {"category": "tac", "original": "0102", "pseudonym": "f00d", "counter": 0, "runs_seen": 1},
    {"category": "mbms-sai", "original": "0003", "pseudonym": "7777", "counter": 0, "runs_seen": 1},
    {"category": "mbsfn-area", "original": "05", "pseudonym": "a0", "counter": 0, "runs_seen": 1},
    {"category": "msrp-tid", "original": "74696430303031", "pseudonym": "71727330393132", "counter": 0, "runs_seen": 1},
    {"category": "msrp-msgid", "original": "6d31", "pseudonym": "7a39", "counter": 0, "runs_seen": 1}]})";
  auto m = Mapping::from_json(doc);
  REQUIRE(m.has_value());
  CHECK(m->size() == 8);
  // Entries are written sorted by category name, then original.
  const auto j = m->to_json();
  CHECK(j.find("\"eci\"") < j.find("\"fc-ref\""));
  CHECK(j.find("\"msrp-msgid\"") < j.find("\"msrp-tid\""));
}

TEST_CASE("a mapping format above the current one is rejected as corrupt input", "[mapping][format3]") {
  for (const char* doc : {R"({"format": 6, "entries": []})", R"({"format": 0, "entries": []})"}) {
    auto m = Mapping::from_json(doc);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().code == ErrorCode::input);
    CHECK(m.error().message == "mapping file is corrupt: unsupported format");
  }
}
