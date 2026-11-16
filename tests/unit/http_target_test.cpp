// SPDX-License-Identifier: GPL-3.0-or-later
//
// Request targets, XCAP selectors and identities in HTTP.
#include "http/target.hpp"
#include "sip/rewrite.hpp"

#include "web_env.hpp"

using namespace mcxanon;
using namespace mcxanon::http;

namespace {
std::string must(const Opt& r) {
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  return **r;
}
}  // namespace

TEST_CASE("http target: XCAP selectors keep AUIDs and map the XUI like SIP", "[http][target]") {
  web_test::Env e;
  const auto t = must(rewrite_target("/xcap-root/org.3gpp.mcptt.user-profile/users/sip%3Aalice%40example.org/mcptt-user-profile-0.xml",
                                     "GET", *e));
  CHECK(t.find("/org.3gpp.mcptt.user-profile/users/sip%3Au-") != std::string::npos);
  CHECK(t.ends_with("/mcptt-user-profile-0.xml"));
  CHECK(t.find("alice") == std::string::npos);
  CHECK(t.find("xcap-root") == std::string::npos);  // the XCAP root is opaque
  // The same user in a SIP URI gets the same user part.
  const auto sip = must(sip::rewrite_uri_text("sip:alice@example.org", *e.sctx));
  const auto user = sip.substr(4, sip.find('@') - 4);
  CHECK(t.find(user) != std::string::npos);
  CHECK(e.counters.xcap_selectors == 1);
}

TEST_CASE("http target: KMS paths, opaque segments, queries and forms", "[http][target]") {
  web_test::Env e;
  const auto k = must(rewrite_target("/keymanagement/identity/v1/keyprov/sip%3Abob%40example.org/D6B43232", "POST", *e));
  CHECK(k.starts_with("/keymanagement/identity/v1/keyprov/sip%3Au-"));
  CHECK(k.find("bob") == std::string::npos);
  CHECK(k.find("D6B43232") == std::string::npos);
  const auto o = must(rewrite_target("/v1/secret-document.xml?grant_type=password&password=hunter22&foo=bar", "GET", *e));
  CHECK(o.starts_with("/v1/"));  // a segment of 1-3 characters is kept (D6)
  CHECK(o.find("secret-document") == std::string::npos);
  CHECK(o.find("grant_type=password") != std::string::npos);
  CHECK(o.find("password=&") == std::string::npos);
  CHECK(o.find("hunter22") == std::string::npos);
  CHECK(o.find("foo") == std::string::npos);
  CHECK(e.removed("hunter22"));
  CHECK(must(rewrite_target("*", "OPTIONS", *e)) == "*");
  const auto c = must(rewrite_target("kms.example.org:443", "CONNECT", *e));
  CHECK(c.ends_with(":443"));
  CHECK(c.find("example") == std::string::npos);
  CHECK_FALSE(rewrite_target("relative", "GET", *e)->has_value());
}

TEST_CASE("http target: absolute URLs drop userinfo; identities by shape", "[http][target]") {
  web_test::Env e;
  const auto u = must(rewrite_uri_ref("https://user:pass@idms.example.org:8443/auth?state=abcdef#frag", *e));
  CHECK(u.starts_with("https://"));
  CHECK(u.find("pass") == std::string::npos);
  CHECK(u.find(":8443/") != std::string::npos);
  CHECK(e.removed("user:pass"));
  CHECK(must(rewrite_identity("sip:carol@example.org", *e)).starts_with("sip:u-"));
  CHECK(must(rewrite_identity("carol@example.org", *e)).find('@') != std::string::npos);
  // A bare value is a user name (the MC ID in sub or username, TS 23.280 §8.1.1): the SIP user
  // part pseudonym, also when it looks like a domain name.
  const auto bare = must(rewrite_identity("alice.nowak", *e));
  CHECK(bare.starts_with("u-"));
  CHECK(must(sip::rewrite_uri_text("sip:alice.nowak@example.org", *e.sctx)).starts_with("sip:" + bare + "@"));
  const auto opaque = must(rewrite_identity("Some Free Value", *e));
  CHECK(opaque.size() == 15);
  CHECK(opaque != "Some Free Value");
}
