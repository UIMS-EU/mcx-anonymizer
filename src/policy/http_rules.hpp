// SPDX-License-Identifier: GPL-3.0-or-later
//
// The HTTP rule set (`ruleset: mcxanon-http`, feature 007):
// header and method rules in the 002 header format (loaded by
// load_http_header_rules), body handlings by content type, static path segments, cookie
// attributes, OAuth 2.0 / OpenID Connect parameters and JSON members, and JWT header members and
// claims. Everything without a rule is removed. Every entry cites its normative source.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"
#include "policy/sip_rules.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

// The documents an HTTP or TLS rule may cite (rules/SOURCES.md, "HTTP rule set" and "TLS rule
// set"): the IETF documents added to the standards corpus for feature 007 and the 3GPP
// specifications of HTTP-1.
bool http_source_allowed(std::string_view spec);

enum class HttpBodyHandling {
  xml,        // an MCX XML document (feature 003 engine, rules/xml-*.yaml)
  form,       // application/x-www-form-urlencoded parameters (R7)
  json,       // an OAuth/OIDC JSON object (R7)
  jwt,        // a JWT as the whole body (application/jwt)
  multipart,  // each part by its own content type
};

struct HttpBodyRule {
  std::string content_type;  // lowercase type/subtype
  HttpBodyHandling handling = HttpBodyHandling::xml;
  std::vector<std::string> params;  // allowed Content-Type parameters (lowercase)
  Source source;
};

struct HttpPathRule {
  std::string segment;  // a path segment kept as written (case-sensitive)
  Source source;
};

enum class CookieAttrAction { keep, number, date, path, domain };

struct HttpCookieAttr {
  std::string name;  // lowercase comparison key
  CookieAttrAction action = CookieAttrAction::keep;
  Source source;
};

enum class HttpParamAction {
  keep,          // by value grammar
  pseudonymise,  // by category
  uri,           // the URI rules (redirect_uri, iss, aud)
  token,         // a token (R8): JWT decomposed, anything else opaque
  shift,         // a NumericDate moved by --time-shift (JWT claims)
  remove,        // a credential or free text: the value leaves (the name stays)
};

enum class HttpValueGrammar { token, number, boolean, scope, enumeration };

enum class HttpCategory { identity, opaque, host };

struct HttpParamRule {
  std::string name;  // case-sensitive (RFC 6749 §3.1, RFC 7519 §4)
  HttpParamAction action = HttpParamAction::remove;
  HttpValueGrammar value = HttpValueGrammar::token;
  std::vector<std::string> values;  // enumeration, or the scope tokens kept (others opaque)
  std::optional<HttpCategory> category;
  std::string reason;  // remove: credential or free-text
  Source source;
};

struct HttpRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  SipRuleSet headers;  // headers and methods in the 002 format
  std::vector<HttpBodyRule> bodies;
  std::vector<HttpPathRule> paths;
  std::vector<HttpCookieAttr> cookie_attributes;
  std::vector<HttpParamRule> params;      // query, form and JSON members
  std::vector<HttpParamRule> jwt_header;  // JOSE header members
  std::vector<HttpParamRule> jwt_claims;  // JWT claims

  [[nodiscard]] const HttpBodyRule* find_body(std::string_view content_type) const;
  [[nodiscard]] bool kept_segment(std::string_view segment) const;
  [[nodiscard]] const HttpCookieAttr* find_cookie_attribute(std::string_view name) const;
  [[nodiscard]] const HttpParamRule* find_param(std::string_view name) const;
  [[nodiscard]] const HttpParamRule* find_jwt_header(std::string_view name) const;
  [[nodiscard]] const HttpParamRule* find_jwt_claim(std::string_view name) const;
};

std::string_view to_string(HttpBodyHandling h);
std::string_view to_string(HttpParamAction a);

Result<HttpRuleSet> load_http_ruleset(std::span<const RuleFile> files);
Result<HttpRuleSet> load_embedded_http_ruleset();

}  // namespace mcxanon
