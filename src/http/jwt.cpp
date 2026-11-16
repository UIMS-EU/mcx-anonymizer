// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/jwt.hpp"

#include "bytes/base64.hpp"
#include "bytes/bytes.hpp"
#include "http/json.hpp"
#include "http/limits.hpp"
#include "http/params.hpp"
#include "http/target.hpp"

#include <algorithm>
#include <vector>

namespace mcxanon::http {

namespace {

std::vector<std::string_view> split_dots(std::string_view t) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  for (;;) {
    const auto d = t.find('.', start);
    out.push_back(t.substr(start, d == std::string_view::npos ? std::string_view::npos : d - start));
    if (d == std::string_view::npos) break;
    start = d + 1;
    if (out.size() > 5) break;
  }
  return out;
}

std::optional<Bytes> b64url(std::string_view s) {
  if (s.empty() || s.find('=') != std::string_view::npos) return std::nullopt;
  auto d = base64::decode(s, base64::Alphabet::url);
  if (!d || d->layout.line != 0) return std::nullopt;
  return std::move(d->bytes);
}

std::string b64url_encode(std::string_view s) {
  base64::Layout l;
  l.padded = false;
  return base64::encode(ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()), l, base64::Alphabet::url);
}

Result<TokenOut> opaque_token(std::string_view token, std::string_view kind, Env& env) {
  auto p = opaque_text(token, env);
  if (!p) return std::unexpected(p.error());
  Counters::bump(env.counters.tokens, kind);
  // A token with too few letters and digits for an opaque pseudonym (D20) leaves as zeros of its
  // length: a credential, never kept.
  if (!*p) return TokenOut{std::string(token.size(), '0'), std::string(kind)};
  return TokenOut{std::move(**p), std::string(kind)};
}

}  // namespace

Result<TokenOut> rewrite_token(std::string_view token, Env& env) {
  if (token.empty()) return TokenOut{std::string(), "opaque"};
  if (token.size() > kMaxToken) {
    // Too long to map: the value leaves (a fixed-length zero-content replacement would claim to
    // be a token). It stays a scan token.
    env.credential("token", token);
    Counters::bump(env.counters.tokens, "removed");
    return TokenOut{std::string(), "removed"};
  }
  const auto segs = split_dots(token);
  if (segs.size() == 5) return opaque_token(token, "jwe", env);
  if (segs.size() != 3 || segs[0].empty() || segs[1].empty() || segs[2].empty()) return opaque_token(token, "opaque", env);
  const auto h = b64url(segs[0]);
  const auto c = b64url(segs[1]);
  const auto s = b64url(segs[2]);
  if (!h || !c || !s) return opaque_token(token, segs[0].starts_with("eyJ") ? "malformed-jwt" : "opaque", env);
  auto header = parse_json(std::string_view(reinterpret_cast<const char*>(h->data()), h->size()));
  auto claims = parse_json(std::string_view(reinterpret_cast<const char*>(c->data()), c->size()));
  const auto has_alg = [&] {
    if (!header || header->type != Json::Type::object) return false;
    return std::any_of(header->members.begin(), header->members.end(), [](const auto& m) { return m.first == "alg"; });
  };
  if (!has_alg() || !claims || claims->type != Json::Type::object) return opaque_token(token, "malformed-jwt", env);
  if (auto r = rewrite_object(*header, env.rules.jwt_header, env, true); !r) return std::unexpected(r.error());
  if (auto r = rewrite_object(*claims, env.rules.jwt_claims, env, true); !r) return std::unexpected(r.error());
  // The signature leaves; its length stays (RFC 7515 §7.1: BASE64URL(JWS Signature)).
  env.sip.counters.add_removed("string", std::string(segs[2]));
  env.sip.counters.add_removed("string", std::string(token));
  const std::string zeros(s->size(), '\0');
  TokenOut out;
  out.text = b64url_encode(write_json(*header)) + "." + b64url_encode(write_json(*claims)) + "." + b64url_encode(zeros);
  out.kind = "jwt";
  Counters::bump(env.counters.tokens, "jwt");
  return out;
}

}  // namespace mcxanon::http
