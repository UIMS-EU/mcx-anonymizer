// SPDX-License-Identifier: GPL-3.0-or-later
//
// The HTTP rule set loader.
#include "policy/http_rules.hpp"
#include "policy/ruleset_embedded.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {

const HttpRuleSet& embedded() {
  static const HttpRuleSet rs = [] {
    auto r = load_embedded_http_ruleset();
    if (!r) FAIL(r.error().message);
    return *r;
  }();
  return rs;
}

Result<HttpRuleSet> load_text(const std::string& text) {
  std::vector<RuleFile> f{RuleFile{"test.yaml", text}};
  return load_http_ruleset(f);
}

const std::string kHead = "ruleset: mcxanon-http\nversion: 1.0.0\n";

}  // namespace

TEST_CASE("http rules: the embedded rule set loads", "[http][rules]") {
  const auto& rs = embedded();
  CHECK(rs.name == "mcxanon-http");
  CHECK(rs.digest.size() == 64);
  CHECK(rs.headers.find_header("host") != nullptr);
  CHECK(rs.headers.find_header("Authorization")->grammar == SipGrammar::http_credentials);
  CHECK(rs.headers.known_method("GET"));
  CHECK_FALSE(rs.headers.known_method("PATCH"));
  REQUIRE(rs.find_body("Application/JSON") != nullptr);
  CHECK(rs.find_body("application/json")->handling == HttpBodyHandling::json);
  CHECK(rs.find_body("application/vnd.3gpp.mcptt-user-profile+xml")->handling == HttpBodyHandling::xml);
  CHECK(rs.find_body("application/octet-stream") == nullptr);
  CHECK(rs.kept_segment("keymanagement"));
  CHECK_FALSE(rs.kept_segment("token"));
  REQUIRE(rs.find_param("password") != nullptr);
  CHECK(rs.find_param("password")->action == HttpParamAction::remove);
  CHECK(rs.find_param("password")->reason == "credential");
  CHECK(rs.find_param("access_token")->action == HttpParamAction::token);
  CHECK(rs.find_param("grant_type")->value == HttpValueGrammar::enumeration);
  CHECK(rs.find_param("scope")->value == HttpValueGrammar::scope);
  CHECK(rs.find_jwt_claim("exp")->action == HttpParamAction::shift);
  CHECK(rs.find_jwt_claim("mcptt_id")->category == HttpCategory::identity);
  CHECK(rs.find_jwt_header("kid")->category == HttpCategory::opaque);
  CHECK(rs.find_jwt_claim("auth_time") == nullptr);  // no corpus source (D5): removed
  CHECK(rs.find_cookie_attribute("max-age")->action == CookieAttrAction::number);
}

TEST_CASE("http rules: load-time validation", "[http][rules]") {
  const auto bad = [](const std::string& t) {
    auto r = load_text(kHead + t);
    CHECK_FALSE(r.has_value());
  };
  bad("params:\n  - {name: x, action: keep, source: {spec: RFC 6749, version: \"2012-10\", clause: \"5.1\"}}\n");
  bad("params:\n  - {name: x, action: remove, source: {spec: RFC 6749, version: \"2012-10\", clause: \"5.1\"}}\n");
  bad("params:\n  - {name: x, action: pseudonymise, source: {spec: RFC 6749, version: \"2012-10\", clause: \"5.1\"}}\n");
  bad("params:\n  - {name: x, action: shift, source: {spec: RFC 6749, version: \"2012-10\", clause: \"5.1\"}}\n");
  bad("params:\n  - {name: x, action: token, source: {spec: RFC 9999, version: \"2012-10\", clause: \"5.1\"}}\n");
  bad("params:\n  - {name: x, action: token}\n");
  bad("bodies:\n  - {content_type: nonsense, handling: xml, source: {spec: RFC 9110, version: \"2022-06\", clause: \"8.3\"}}\n");
  bad("bodies:\n  - {content_type: a/b, handling: magic, source: {spec: RFC 9110, version: \"2022-06\", clause: \"8.3\"}}\n");
  bad("paths:\n  - {segment: \"a/b\", source: {spec: TS 33.180, version: \"20.0.0\", clause: \"D.2.1\"}}\n");
  bad("unknown: 1\n");
  bad("headers:\n  - {name: Host, grammar: no-such, source: {spec: RFC 9110, version: \"2022-06\", clause: \"7.2\"}}\n");
  auto ok = load_text(kHead + "params:\n  - {name: x, action: token, source: {spec: RFC 6749, version: \"2012-10\", clause: \"5.1\"}}\n");
  CHECK(ok.has_value());
}

TEST_CASE("sip rules: HTTP grammars are refused in the SIP rule set", "[http][rules]") {
  std::vector<RuleFile> f{RuleFile{"sip-x.yaml",
                                   "ruleset: mcxanon-sip\nversion: 1.0.0\nheaders:\n  - {name: X, grammar: cookie, action: "
                                   "pseudonymise, source: {spec: RFC 3261, version: \"2002-06\", clause: \"20\"}}\n"}};
  CHECK_FALSE(load_sip_ruleset(f).has_value());
}
