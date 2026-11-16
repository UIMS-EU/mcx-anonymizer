// SPDX-License-Identifier: GPL-3.0-or-later
//
// --annotate (FR-014a).
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

TEST_CASE("annotate: revealed values carry their pseudonym", "[reveal][render]") {
  Fixture f;
  const auto u = f.user("alice");
  const auto h = f.host("mcx.example.net");
  const auto tac = std::to_string(f.binary(Category::tac, 0x0C41));
  RevealOptions o;
  o.annotate = true;
  CHECK(f.reveal("sip:" + u + "@" + h + " tac " + tac + " u-0badcafe", o) ==
        "sip:alice\xe2\x9f\xa6" + u + "\xe2\x9f\xa7@mcx.example.net\xe2\x9f\xa6" + h + "\xe2\x9f\xa7 tac " + tac +
            " u-0badcafe");
  // With --replace-ambiguous the ambiguous value is revealed and annotated too.
  o.replace_ambiguous = true;
  CHECK(f.reveal("tac " + tac, o) == "tac 3137\xe2\x9f\xa6" + tac + "\xe2\x9f\xa7");
}
