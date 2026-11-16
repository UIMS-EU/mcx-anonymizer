// SPDX-License-Identifier: GPL-3.0-or-later
//
// OAuth tokens (feature 007): a JWS-compact JWT is
// decomposed (header members and claims by the rule set, signature zeroed with its length kept);
// a JWE, a JWT that does not decode, and any other token become a project-consistent opaque
// pseudonym of the same length and character classes. The original signature and token are
// kept as in-memory scan tokens.
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"

#include <string>
#include <string_view>

namespace mcxanon::http {

struct TokenOut {
  std::string text;
  std::string kind;  // jwt, jwe, opaque, malformed-jwt
};

Result<TokenOut> rewrite_token(std::string_view token, Env& env);

}  // namespace mcxanon::http
