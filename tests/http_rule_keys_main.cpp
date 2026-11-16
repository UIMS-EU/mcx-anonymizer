// SPDX-License-Identifier: GPL-3.0-or-later
//
// Prints the key of every rule of the embedded HTTP rule set that changes a value, one per line,
// in the canary key format of tools/fixturegen/web.py. Used by
// test_rule_canary_coverage.py.
//   http:<Header>             a header rule that pseudonymises or removes
//   http:<Header>;<param>     a header parameter that pseudonymises or removes
//   http-param:<name>         a query, form or JSON parameter that does not keep its value
//   jwt:<claim>, jwt-header:<member>   JWT claims and JOSE header members likewise
//   cookie:<attribute>        the cookie attributes that are mapped (Domain, Path)
// and the fixed keys of values without a rule (unknown headers, parameters, members) and of the
// structural values (cookie names and values, request target parts, JWT signatures).
#include "policy/http_rules.hpp"

#include <cstdio>
#include <set>
#include <string>

using namespace mcxanon;

int main() {
  auto rs = load_embedded_http_ruleset();
  if (!rs) {
    std::fprintf(stderr, "%s\n", rs.error().message.c_str());
    return 1;
  }
  std::set<std::string> keys{"http-header:unknown", "http-param:unknown", "json-member:unknown", "jwt:unknown",
                             "jwt:signature",       "cookie:name",        "cookie:value",        "http-target:user",
                             "http-target:segment", "http-body:application/octet-stream"};
  for (const auto& h : rs->headers.headers) {
    bool changes = h.action != SipAction::keep;
    if (h.action == SipAction::pseudonymise && !h.components.empty()) {
      changes = false;
      for (const auto& [name, c] : h.components) changes = changes || c.action != SipAction::keep;
    }
    if (h.grammar == SipGrammar::http_credentials || h.grammar == SipGrammar::cookie || h.grammar == SipGrammar::set_cookie) {
      changes = true;
    }
    if (changes) keys.insert("http:" + h.name);
    for (const auto& p : h.params) {
      if (p.rule.action != SipAction::keep) keys.insert("http:" + h.name + ";" + p.name);
    }
  }
  for (const auto& p : rs->params) {
    if (p.action != HttpParamAction::keep) keys.insert("http-param:" + p.name);
  }
  for (const auto& p : rs->jwt_claims) {
    if (p.action != HttpParamAction::keep && p.action != HttpParamAction::shift) keys.insert("jwt:" + p.name);
  }
  for (const auto& p : rs->jwt_header) {
    if (p.action != HttpParamAction::keep) keys.insert("jwt-header:" + p.name);
  }
  for (const auto& a : rs->cookie_attributes) {
    if (a.action == CookieAttrAction::domain || a.action == CookieAttrAction::path) keys.insert("cookie:" + a.name);
  }
  for (const auto& k : keys) std::printf("%s\n", k.c_str());
  return 0;
}
