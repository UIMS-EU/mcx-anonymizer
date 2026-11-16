// SPDX-License-Identifier: GPL-3.0-or-later
//
// OAuth 2.0 / OpenID Connect parameters (feature 007): query strings and
// application/x-www-form-urlencoded bodies, JSON objects (token responses, introspection, JWT
// claims) by one rule table. Kept by value grammar, pseudonymised, rewritten as a URI or a token,
// shifted, or removed; a parameter without a rule leaves with its value and its name is counted.
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"
#include "http/json.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::http {

// A query string or form body, re-encoded (RFC 3986 unreserved kept, space as "+").
Result<std::string> rewrite_form(std::string_view text, Env& env, std::string_view carrier);

// The members of a JSON object by `rules`; `claims` counts into the JWT claim counters.
Result<void> rewrite_object(Json& object, const std::vector<HttpParamRule>& rules, Env& env, bool claims);

// An OAuth/OIDC JSON body: nullopt when it is not a JSON object (the body is removed).
Result<std::optional<std::string>> rewrite_json_body(std::string_view body, Env& env);

std::optional<std::string> form_decode(std::string_view s);
std::string form_encode(std::string_view s);

}  // namespace mcxanon::http
