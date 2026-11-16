// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/body.hpp"

#include "http/jwt.hpp"
#include "http/limits.hpp"
#include "http/params.hpp"
#include "sip/multipart.hpp"
#include "sip/value_map.hpp"

#include <algorithm>

namespace mcxanon::http {

namespace {

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

std::string unquote(std::string_view v) {
  if (v.size() >= 2 && v.front() == '"' && v.back() == '"') return std::string(v.substr(1, v.size() - 2));
  return std::string(v);
}

// type/subtype and the charset and boundary parameters of a Content-Type value.
void content_type(std::string_view v, std::string& type, std::string& charset, std::string& boundary) {
  const auto semi = v.find(';');
  type = lower(trim(v.substr(0, semi)));
  std::string_view rest = semi == std::string_view::npos ? std::string_view() : v.substr(semi + 1);
  while (!rest.empty()) {
    const auto next = rest.find(';');
    const auto p = trim(rest.substr(0, next));
    const auto eq = p.find('=');
    if (eq != std::string_view::npos) {
      const auto name = lower(trim(p.substr(0, eq)));
      const auto value = unquote(trim(p.substr(eq + 1)));
      if (name == "charset") charset = value;
      if (name == "boundary") boundary = value;
    }
    if (next == std::string_view::npos) break;
    rest.remove_prefix(next + 1);
  }
}

Result<std::optional<std::string>> multipart(const BodyDecision& d, std::string_view body, Env& env, std::string& reason,
                                             std::size_t depth);

Result<std::optional<std::string>> by_rule(const BodyDecision& d, std::string_view body, Env& env, std::string& reason,
                                           std::size_t depth) {
  switch (d.rule->handling) {
    case HttpBodyHandling::xml: {
      if (env.sip.xml == nullptr) {
        reason = "no-rule";
        return std::optional<std::string>{};
      }
      auto r = env.sip.xml->rewrite(d.content_type, d.charset, body, 0, env.sip);
      if (!r) return std::unexpected(r.error());
      if (!r->rewritten) {
        reason = r->reason.empty() ? "malformed" : r->reason;
        return std::optional<std::string>{};
      }
      return std::optional<std::string>(std::move(r->bytes));
    }
    case HttpBodyHandling::form: {
      auto f = rewrite_form(body, env, "form");
      if (!f) return std::unexpected(f.error());
      return std::optional<std::string>(std::move(*f));
    }
    case HttpBodyHandling::json: {
      auto j = rewrite_json_body(body, env);
      if (!j) return j;
      if (!*j) reason = "malformed";
      return j;
    }
    case HttpBodyHandling::jwt: {
      auto t = rewrite_token(trim(body), env);
      if (!t) return std::unexpected(t.error());
      return std::optional<std::string>(std::move(t->text));
    }
    case HttpBodyHandling::multipart: return multipart(d, body, env, reason, depth);
  }
  reason = "no-rule";
  return std::optional<std::string>{};
}

// RFC 2046 §5.1: each part by its own content type; parts without a rule are dropped, part
// headers other than Content-Type are removed. The boundary takes the 002 boundary pseudonym, as
// the Content-Type header rule writes it.
Result<std::optional<std::string>> multipart(const BodyDecision& d, std::string_view body, Env& env, std::string& reason,
                                             std::size_t depth) {
  if (depth > 0 || d.boundary.empty()) {
    reason = "malformed";
    return std::optional<std::string>{};
  }
  const auto mp = sip::parse_multipart(body, d.boundary);
  if (!mp) {
    reason = "malformed";
    return std::optional<std::string>{};
  }
  auto b = sip::map_value(SipCategory::boundary, d.boundary, env.sip);
  if (!b) return std::unexpected(b.error());
  if (!*b) {
    reason = "malformed";
    return std::optional<std::string>{};
  }
  std::string out;
  for (const auto& part : mp->parts) {
    std::string ct;
    for (const auto& h : part.headers) {
      const auto name = body.substr(h.name.off, h.name.len);
      if (iequal(name, "Content-Type")) ct = h.unfolded;
    }
    BodyDecision pd;
    content_type(ct, pd.content_type, pd.charset, pd.boundary);
    pd.rule = env.rules.find_body(pd.content_type);
    if (pd.rule == nullptr || pd.rule->handling == HttpBodyHandling::multipart) {
      Counters::bump(env.counters.bodies, pd.content_type.empty() ? "(none)" : pd.content_type, "removed:no-rule");
      continue;
    }
    std::string r2;
    auto pb = by_rule(pd, part.body, env, r2, depth + 1);
    if (!pb) return pb;
    if (!*pb) {
      Counters::bump(env.counters.bodies, pd.content_type, "removed:" + r2);
      continue;
    }
    Counters::bump(env.counters.bodies, pd.content_type, to_string(pd.rule->handling));
    out += "--" + **b + "\r\nContent-Type: " + pd.content_type;
    if (!pd.charset.empty() && is_token(pd.charset)) out += ";charset=" + pd.charset;
    out += "\r\n\r\n" + **pb + "\r\n";
  }
  out += "--" + **b + "--\r\n";
  return std::optional<std::string>(std::move(out));
}

}  // namespace

BodyDecision decide_body(const Head& head, const BodyPlan& plan, Env& env) {
  BodyDecision d;
  if (plan.kind == BodyPlan::Kind::none) return d;
  const auto* ct = find(head, "Content-Type");
  if (ct != nullptr) content_type(ct->value, d.content_type, d.charset, d.boundary);
  d.kind = BodyDecision::Kind::remove;
  for (const auto v : values_of(head, "Content-Encoding")) {
    if (!iequal(v, "identity")) {
      d.reason = "encoded";
      return d;
    }
  }
  const auto te = values_of(head, "Transfer-Encoding");
  for (std::size_t i = 0; i + 1 < te.size(); ++i) {
    if (!iequal(te[i], "identity")) {
      d.reason = "encoded";
      return d;
    }
  }
  if (plan.kind == BodyPlan::Kind::to_close) {
    d.reason = "to-close";
    return d;
  }
  d.rule = env.rules.find_body(d.content_type);
  if (d.rule == nullptr) {
    d.reason = "no-rule";
    return d;
  }
  if (plan.kind == BodyPlan::Kind::length && plan.length > kMaxRewrittenBody) {
    d.reason = "limit";
    return d;
  }
  d.kind = BodyDecision::Kind::rewrite;
  return d;
}

Result<std::optional<std::string>> rewrite_body(const BodyDecision& d, std::string_view body, Env& env,
                                                std::string& reason) {
  if (d.rule == nullptr) {
    reason = "no-rule";
    return std::optional<std::string>{};
  }
  return by_rule(d, body, env, reason, 0);
}

}  // namespace mcxanon::http
