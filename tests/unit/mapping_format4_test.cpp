// SPDX-License-Identifier: GPL-3.0-or-later
//
// Mapping file format 4.
#include "mcxanon/error.hpp"

#include "pseudo/mapping.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

TEST_CASE("formats 1 to 3 load; the first save writes the current format", "[mapping][format4]") {
  for (const char* doc : {R"({"format": 1, "entries": []})", R"({"format": 2, "entries": []})",
                          R"({"format": 3, "entries": [
    {"category": "eci", "original": "01234567", "pseudonym": "0abcdef0", "counter": 0, "runs_seen": 1}]})"}) {
    auto m = Mapping::from_json(doc);
    REQUIRE(m.has_value());
    CHECK(m->to_json().find("\"format\": 5") != std::string::npos);  // feature 005
  }
  CHECK(Mapping{}.to_json().find("\"format\": 5") != std::string::npos);
}

TEST_CASE("the XML categories load from format 4 and round-trip", "[mapping][format4]") {
  const std::string doc = R"({"format": 4, "entries": [
    {"category": "opaque", "original": "7475706c65", "pseudonym": "71776572", "counter": 0, "runs_seen": 1},
    {"category": "nci", "original": "0123456789", "pseudonym": "0abcdef012", "counter": 0, "runs_seen": 1},
    {"category": "nr-tac", "original": "000102", "pseudonym": "a0b0c0", "counter": 0, "runs_seen": 1},
    {"category": "mbs-fsa", "original": "0a0b0c", "pseudonym": "112233", "counter": 0, "runs_seen": 1}]})";
  auto m = Mapping::from_json(doc);
  REQUIRE(m.has_value());
  CHECK(m->size() == 4);
  auto again = Mapping::from_json(m->to_json());
  REQUIRE(again.has_value());
  CHECK(again->to_json() == m->to_json());
}

TEST_CASE("an unknown format is rejected", "[mapping][format4]") {
  auto m = Mapping::from_json(R"({"format": 6, "entries": []})");
  REQUIRE_FALSE(m.has_value());
  CHECK(m.error().code == ErrorCode::input);
}
