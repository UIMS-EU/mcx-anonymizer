// SPDX-License-Identifier: GPL-3.0-or-later
//
// Escaped pseudonyms (FR-011, P4).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  for (std::size_t at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size())) {
    s.replace(at, from.size(), to);
  }
  return s;
}
}  // namespace

TEST_CASE("escape: a percent-escaped pseudonym gets a percent-escaped original", "[reveal][escape]") {
  Fixture f;
  const auto o = f.text(Category::opaque, "ab@cd.ef-12");  // '@' and '.' kept in place
  REQUIRE(o.find('@') != std::string::npos);
  CHECK(f.reveal("v=" + replace_all(o, "@", "%40")) == "v=ab%40cd.ef-12");
  CHECK(f.reveal("v=" + replace_all(o, "@", "%40") + "&w=1") == "v=ab%40cd.ef-12&w=1");
  // The plain form still works.
  CHECK(f.reveal("v=" + o) == "v=ab@cd.ef-12");
}

TEST_CASE("escape: URI components around an escape keep the escape", "[reveal][escape]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto h = f.host("mcx.example.net");
  CHECK(f.reveal("target=sip%3A" + u + "%40" + h + "%3Bx") == "target=sip%3Aalice%40mcx.example.net%3Bx");
}

TEST_CASE("escape: XML character references", "[reveal][escape]") {
  Fixture f;
  const auto o = f.text(Category::opaque, "Q&A-77x");
  REQUIRE(o.find('&') != std::string::npos);
  CHECK(f.reveal("<v>" + replace_all(o, "&", "&amp;") + "</v>") == "<v>Q&amp;A-77x</v>");
  CHECK(f.reveal("<v>" + replace_all(o, "&", "&#38;") + "</v>") == "<v>Q&#38;A-77x</v>");
  // A match without escapes gets the original verbatim, even where the original has '&'.
  const auto n = f.text(Category::display_name, "Tom & Jerry");
  CHECK(f.reveal("<n>" + n + "</n>") == "<n>Tom & Jerry</n>");
}
