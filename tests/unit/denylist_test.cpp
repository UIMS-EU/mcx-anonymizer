// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/scan.hpp"

#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>

using namespace mcxanon;

TEST_CASE("deny-list parsing", "[scan][deny]") {
  test::TempDir tmp;
  const auto p = tmp.path() / "deny.txt";
  std::ofstream(p) << "# company names\nAcmeCorp\n\n  Project Kestrel  \nÄpfelGmbH\n";
  auto ts = scan::load_deny_list(p);
  REQUIRE(ts.has_value());
  REQUIRE(ts->size() == 3);
  CHECK((*ts)[0].label == "deny#2");
  CHECK((*ts)[1].value == std::vector<std::uint8_t>{'P', 'r', 'o', 'j', 'e', 'c', 't', ' ', 'K', 'e', 's', 't', 'r', 'e', 'l'});
  CHECK((*ts)[1].label == "deny#4");
  CHECK((*ts)[2].category == scan::TokenCategory::deny);
}

TEST_CASE("deny-list entries shorter than four characters are rejected", "[scan][deny]") {
  test::TempDir tmp;
  const auto p = tmp.path() / "deny.txt";
  std::ofstream(p) << "fine-entry\nabc\n";
  auto ts = scan::load_deny_list(p);
  REQUIRE_FALSE(ts.has_value());
  CHECK(ts.error().code == ErrorCode::usage);
  CHECK(ts.error().message.find("line 2") != std::string::npos);
  CHECK_FALSE(scan::load_deny_list(tmp.path() / "missing.txt").has_value());
}
