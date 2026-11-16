// SPDX-License-Identifier: GPL-3.0-or-later
//
// APP identities share the SIP mappings (FR-018, SC-003).
#include "media_env.hpp"

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
const Bytes* value(const std::vector<std::pair<std::uint8_t, Bytes>>& f, std::uint8_t id) {
  for (const auto& [i, v] : f) {
    if (i == id) return &v;
  }
  return nullptr;
}
Bytes run(MediaEnv& e, const Bytes& in) {
  auto r = media::rewrite_rtcp(in, false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  return **r;
}
}  // namespace

TEST_CASE("Granted Party's Identity gets the pseudonym SIP gives the same URI", "[media][app][identity]") {
  MediaEnv e;
  const std::string bob = "sip:bob.zielinski@mcx.example.net";
  // The SIP layer sees the URI first, in a header of the same project.
  const std::string from_sip = e.uri(bob);
  const auto out = run(e, app("MCPT", 2, 1, {field(4, str(bob))}));
  CHECK(*value(fields_of(out), 4) == str(from_sip));
  CHECK(from_sip.find("bob.zielinski") == std::string::npos);
}

TEST_CASE("the anonymous identity of TS 24.380 §8.3.4 gets the SIP pseudonym", "[media][app][identity]") {
  MediaEnv e;
  const std::string anon = "sip:anonymous@invalid.invalid";
  const auto out = run(e, app("MCPT", 2, 1, {field(4, str(anon))}));
  CHECK(*value(fields_of(out), 4) == str(e.uri(anon)));
}

TEST_CASE("Functional Alias and the Queued User ID use the same URI mapping (A12)", "[media][app][identity]") {
  MediaEnv e;
  const std::string fa = "sip:fa-dispatch@mcx.example.net";
  const auto out = run(e, app("MCPT", 2, 1, {field(17, str(fa)), field(9, str(fa))}));
  const auto f = fields_of(out);
  CHECK(*value(f, 17) == str(e.uri(fa)));
  CHECK(*value(f, 9) == *value(f, 17));
}

TEST_CASE("Floor Participant References do not share the SSRC namespace", "[media][app][identity]") {
  MediaEnv e;
  CHECK(*e.mapper.binary(Category::fc_ref, 0x12345678) != e.ssrc(0x12345678));
}
