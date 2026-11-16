// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/headers.hpp"

#include "http/jwt.hpp"
#include "http/message.hpp"
#include "http/target.hpp"
#include "sip/header_values.hpp"
#include "sip/rewrite.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace mcxanon::http {

namespace {

using Opt = Result<std::optional<std::string>>;
const auto kNone = std::optional<std::string>{};

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

std::vector<std::string_view> split(std::string_view v, char sep) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  bool quoted = false;
  for (std::size_t i = 0; i <= v.size(); ++i) {
    if (i < v.size() && v[i] == '"') quoted = !quoted;
    if (i == v.size() || (v[i] == sep && !quoted)) {
      out.push_back(trim(v.substr(start, i - start)));
      start = i + 1;
    }
  }
  return out;
}

Opt opaque(std::string_view v, Env& env) { return opaque_text(v, env); }

// RFC 9110 §8.8.3: entity-tag = [ weak ] opaque-tag; "*" for If-Match / If-None-Match.
Opt etags(const SipHeaderRule& r, std::string_view v, Env& env) {
  const auto items = split(v, ',');
  std::string out;
  for (const auto item : items) {
    std::string tag;
    if (item == "*") {
      tag = "*";
    } else {
      std::string_view t = item;
      const bool weak = t.starts_with("W/");
      if (weak) t.remove_prefix(2);
      if (t.size() < 2 || t.front() != '"' || t.back() != '"') return kNone;
      const auto content = t.substr(1, t.size() - 2);
      if (content.find('"') != std::string_view::npos) return kNone;
      std::string mapped(content);
      const auto c = r.components.find("value");
      if (c == r.components.end() || c->second.action != SipAction::keep) {
        if (!content.empty()) {
          auto m = sip::map_value(SipCategory::entity_tag, content, env.sip);
          if (!m) return std::unexpected(m.error());
          if (!*m) return kNone;
          mapped = std::move(**m);
        }
      }
      tag = std::string(weak ? "W/" : "") + "\"" + mapped + "\"";
    }
    if (!out.empty()) out += ", ";
    out += tag;
  }
  return out.empty() ? kNone : std::optional<std::string>(out);
}

Opt credentials(const SipHeaderRule& r, std::string_view v, Env& env) {
  const auto sp = v.find(' ');
  const auto scheme = v.substr(0, sp);
  const auto rest = sp == std::string_view::npos ? std::string_view() : trim(v.substr(sp + 1));
  if (!is_token(scheme)) return kNone;
  if (iequal(scheme, "Basic")) {
    env.credential("basic", rest);  // RFC 7617 §2: user-id ":" password, base64
    return std::optional<std::string>(std::string(scheme));
  }
  if (iequal(scheme, "Bearer")) {
    // RFC 6750 §2.1: b64token.
    if (rest.empty() || rest.find(' ') != std::string_view::npos) {
      env.credential("bearer", rest);
      return std::optional<std::string>(std::string(scheme));
    }
    auto t = rewrite_token(rest, env);
    if (!t) return std::unexpected(t.error());
    if (t->text.empty()) return std::optional<std::string>(std::string(scheme));
    return std::optional<std::string>(std::string(scheme) + " " + t->text);
  }
  if (iequal(scheme, "Digest")) {
    SipHeaderRule d = r;
    d.grammar = SipGrammar::credentials;
    auto x = sip::rewrite_header_value(d, v, env.sip);
    if (x && *x) Counters::bump(env.counters.credentials_removed, "digest-response");
    return x;
  }
  env.credential(lower(scheme), rest);
  return std::optional<std::string>(std::string(scheme));
}

// RFC 6265 §4.2.1: cookie-pair *( ";" SP cookie-pair ); names opaque, values removed (P7).
Opt cookie(std::string_view v, Env& env) {
  std::string out;
  for (const auto pair : split(v, ';')) {
    if (pair.empty()) continue;
    const auto eq = pair.find('=');
    if (eq == std::string_view::npos || eq == 0 || !is_token(pair.substr(0, eq))) return kNone;
    auto n = opaque(pair.substr(0, eq), env);
    if (!n) return n;
    ++env.counters.cookie_values_removed;
    env.credential("cookie", pair.substr(eq + 1));
    if (!*n) continue;  // a name without an opaque pseudonym (D20): the pair is left out
    ++env.counters.cookie_names;
    if (!out.empty()) out += "; ";
    out += **n + "=";
  }
  return out.empty() ? kNone : std::optional<std::string>(out);
}

// RFC 6265 §4.1.1: cookie-pair *( ";" SP cookie-av ).
Opt set_cookie(std::string_view v, Env& env) {
  const auto parts = split(v, ';');
  if (parts.empty()) return kNone;
  auto first = cookie(parts[0], env);
  if (!first || !*first) return first;
  std::string out = **first;
  for (std::size_t i = 1; i < parts.size(); ++i) {
    const auto av = parts[i];
    if (av.empty()) continue;
    const auto eq = av.find('=');
    const auto name = trim(av.substr(0, eq));
    const auto value = eq == std::string_view::npos ? std::string_view() : trim(av.substr(eq + 1));
    const auto* rule = env.rules.find_cookie_attribute(name);
    if (rule == nullptr) {
      Counters::bump(env.counters.removed_unknown, "cookie-attribute", counted_name(name));
      continue;
    }
    std::optional<std::string> nv;
    switch (rule->action) {
      case CookieAttrAction::keep:
        if (eq == std::string_view::npos) nv = std::string();
        break;
      case CookieAttrAction::number:
        if (!value.empty() && std::all_of(value.begin(), value.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0 || c == '-'; })) {
          nv = std::string(value);
        }
        break;
      case CookieAttrAction::date:
        if (auto t = sip::parse_date(value)) nv = sip::render_date(*t + env.shift_s());
        break;
      case CookieAttrAction::path: {
        auto p = rewrite_path(value, env);
        if (!p) return p;
        nv = *p;
        break;
      }
      case CookieAttrAction::domain: {
        const bool dot = value.starts_with('.');
        auto h = sip::map_host(dot ? value.substr(1) : value, env.sip);
        if (!h) return h;
        if (*h) nv = std::string(dot ? "." : "") + **h;
        break;
      }
    }
    if (!nv) {
      Counters::bump(env.counters.removed_unknown, "cookie-attribute", counted_name(name));
      continue;
    }
    out += "; " + std::string(name);
    if (eq != std::string_view::npos) out += "=" + *nv;
  }
  return std::optional<std::string>(out);
}

// RFC 9111 §5.2: #( token [ "=" ( token / quoted-string ) ] ); listed names kept, numeric
// arguments kept, other arguments removed.
Opt directives(const SipHeaderRule& r, std::string_view v) {
  std::string out;
  for (const auto d : split(v, ',')) {
    if (d.empty()) continue;
    const auto eq = d.find('=');
    const auto name = trim(d.substr(0, eq));
    if (!is_token(name) || std::find(r.values.begin(), r.values.end(), lower(name)) == r.values.end()) continue;
    std::string item(name);
    if (eq != std::string_view::npos) {
      const auto arg = trim(d.substr(eq + 1));
      if (!arg.empty() && std::all_of(arg.begin(), arg.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; })) {
        item += "=" + std::string(arg);
      }
    }
    if (!out.empty()) out += ", ";
    out += item;
  }
  return std::optional<std::string>(out);
}

// RFC 9110 §14: range units, numbers, "-", ",", "/", "*" and spaces only.
Opt range(std::string_view v) {
  if (v.empty() || v.size() > 1024) return kNone;
  const bool ok = std::all_of(v.begin(), v.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("-,/*= ").find(c) != std::string_view::npos;
  });
  return ok ? std::optional<std::string>(std::string(v)) : kNone;
}

Opt identity(std::string_view v, Env& env) {
  const bool quoted = v.size() >= 2 && v.front() == '"' && v.back() == '"';
  const auto inner = quoted ? v.substr(1, v.size() - 2) : v;
  auto m = rewrite_identity(inner, env);
  if (!m || !*m) return m;
  return std::optional<std::string>(quoted ? "\"" + **m + "\"" : **m);
}

}  // namespace

Result<std::optional<std::string>> rewrite_field(std::string_view name, std::string_view value, Env& env) {
  const auto* rule = env.rules.headers.find_header(name);
  if (rule == nullptr) {
    Counters::bump(env.counters.removed_unknown, "http-header", counted_name(name));
    return kNone;
  }
  const auto done = [&](Opt r, std::string_view action) -> Opt {
    if (!r) return r;
    if (!*r) {
      Counters::bump(env.counters.headers, rule->name, "malformed");
      return kNone;
    }
    if ((*r)->empty()) {
      Counters::bump(env.counters.headers, rule->name, "removed");
      return kNone;
    }
    Counters::bump(env.counters.headers, rule->name, action);
    return r;
  };
  if (rule->action == SipAction::remove) {
    Counters::bump(env.counters.headers, rule->name, "removed");
    env.sip.counters.add_removed("string", std::string(value));
    return kNone;
  }
  const char* act = rule->action == SipAction::keep ? "kept" : "pseudonymised";
  switch (rule->grammar) {
    case SipGrammar::host: return done(rewrite_authority(value, env), act);
    case SipGrammar::etag_list: return done(etags(*rule, value, env), act);
    case SipGrammar::http_uri: return done(rewrite_uri_ref(value, env), act);
    case SipGrammar::http_credentials: return done(credentials(*rule, value, env), act);
    case SipGrammar::cookie: return done(cookie(value, env), act);
    case SipGrammar::set_cookie: return done(set_cookie(value, env), act);
    case SipGrammar::directives: return done(directives(*rule, value), act);
    case SipGrammar::range: return done(range(value), act);
    case SipGrammar::identity: return done(identity(value, env), act);
    default: return done(sip::rewrite_header_value(*rule, value, env.sip), act);
  }
}

}  // namespace mcxanon::http
