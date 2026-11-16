// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP bodies by content type (feature 007, FR-009): the decision before the
// body is read (rewritten, removed with a reason, or none) and the rewriting of a complete body
// (XML through the 003 engine, forms, OAuth/OIDC JSON, a JWT, multipart by part).
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"
#include "http/message.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::http {

struct BodyDecision {
  enum class Kind { none, rewrite, remove };
  Kind kind = Kind::none;
  std::string reason;        // remove: no-rule, encoded, limit, to-close, trailers, malformed
  std::string content_type;  // lowercase type/subtype
  std::string charset;
  std::string boundary;      // multipart
  const HttpBodyRule* rule = nullptr;
};

// The decision for the body that `plan` frames after `head`.
BodyDecision decide_body(const Head& head, const BodyPlan& plan, Env& env);

// A complete body: the rewritten bytes, or nullopt with `reason` set (the body is removed).
Result<std::optional<std::string>> rewrite_body(const BodyDecision& d, std::string_view body, Env& env,
                                                std::string& reason);

}  // namespace mcxanon::http
