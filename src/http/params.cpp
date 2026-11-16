// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/params.hpp"

#include "http/jwt.hpp"
#include "http/limits.hpp"
#include "http/message.hpp"
#include "http/target.hpp"
#include "sip/value_map.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>

namespace mcxanon::http {

namespace {

enum class Out { keep, set, empty, drop };
struct Value {
  Out out = Out::drop;
  std::string text;
};

bool token_value(std::string_view v) {
  return !v.empty() && v.size() <= 256 && std::all_of(v.begin(), v.end(), [](char c) {
           return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("-._~:/+").find(c) != std::string_view::npos;
         });
}

bool number_value(std::string_view v) {
  return !v.empty() && v.size() <= 20 && std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; });
}

const char* action_word(const HttpParamRule& r) {
  switch (r.action) {
    case HttpParamAction::keep: return "kept";
    case HttpParamAction::pseudonymise: return "pseudonymised";
    case HttpParamAction::uri: return "pseudonymised";
    case HttpParamAction::token: return "token";
    case HttpParamAction::shift: return "shifted";
    case HttpParamAction::remove: return "removed";
  }
  return "removed";
}

Result<std::optional<std::string>> opaque(std::string_view v, Env& env) { return opaque_text(v, env); }

// One string value under its rule.
Result<Value> apply_string(const HttpParamRule& r, std::string_view v, Env& env) {
  Value out;
  switch (r.action) {
    case HttpParamAction::keep:
      switch (r.value) {
        case HttpValueGrammar::token: out.out = token_value(v) ? Out::keep : Out::drop; break;
        case HttpValueGrammar::number: out.out = number_value(v) ? Out::keep : Out::drop; break;
        case HttpValueGrammar::boolean: out.out = v == "true" || v == "false" ? Out::keep : Out::drop; break;
        case HttpValueGrammar::enumeration:
          out.out = std::find(r.values.begin(), r.values.end(), v) != r.values.end() ? Out::keep : Out::drop;
          break;
        case HttpValueGrammar::scope: {
          // Space-delimited scope tokens (RFC 6749 §3.3): listed tokens kept, others opaque.
          if (v.size() > kMaxToken) return out;
          std::string s;
          std::size_t start = 0;
          bool first = true;
          while (start <= v.size()) {
            const auto sp = v.find(' ', start);
            const auto t = v.substr(start, sp == std::string_view::npos ? std::string_view::npos : sp - start);
            std::optional<std::string> o = std::string(t);
            if (std::find(r.values.begin(), r.values.end(), t) == r.values.end()) {
              auto m = opaque(t, env);
              if (!m) return std::unexpected(m.error());
              o = std::move(*m);  // nullopt: a token without an opaque pseudonym is left out (D20)
            }
            if (o) {
              if (!first) s.push_back(' ');
              s += *o;
              first = false;
            }
            if (sp == std::string_view::npos) break;
            start = sp + 1;
          }
          out.out = s == v ? Out::keep : Out::set;
          out.text = std::move(s);
          break;
        }
      }
      return out;
    case HttpParamAction::pseudonymise: {
      Result<std::optional<std::string>> m = std::optional<std::string>{};
      switch (*r.category) {
        case HttpCategory::identity: m = rewrite_identity(v, env); break;
        case HttpCategory::opaque: m = opaque(v, env); break;
        case HttpCategory::host: m = sip::map_host(v, env.sip); break;
      }
      if (!m) return std::unexpected(m.error());
      if (*m) {
        out.out = Out::set;
        out.text = std::move(**m);
      }
      return out;
    }
    case HttpParamAction::uri: {
      auto m = rewrite_uri_ref(v, env);
      if (!m) return std::unexpected(m.error());
      if (*m) {
        out.out = Out::set;
        out.text = std::move(**m);
      }
      return out;
    }
    case HttpParamAction::token: {
      auto t = rewrite_token(v, env);
      if (!t) return std::unexpected(t.error());
      out.out = Out::set;
      out.text = std::move(t->text);
      return out;
    }
    case HttpParamAction::shift: return out;  // a NumericDate is a number, never a string
    case HttpParamAction::remove:
      if (r.reason == "credential") env.credential(r.name, v);
      else env.sip.counters.add_removed("string", std::string(v));
      out.out = Out::empty;
      return out;
  }
  return out;
}

void count(Env& env, bool claims, std::string_view name, std::string_view action) {
  Counters::bump(claims ? env.counters.jwt_claims : env.counters.params, name, action);
}

// One JSON value under its rule; false when the member is removed.
Result<bool> apply_json(const HttpParamRule& r, Json& j, Env& env) {
  switch (j.type) {
    case Json::Type::string: {
      auto v = apply_string(r, j.text, env);
      if (!v) return std::unexpected(v.error());
      if (v->out == Out::drop) return false;
      if (v->out == Out::set) j.text = std::move(v->text);
      if (v->out == Out::empty) j.text.clear();
      return true;
    }
    case Json::Type::number:
      if (r.action == HttpParamAction::keep && r.value == HttpValueGrammar::number) {
        return number_value(j.text);
      }
      if (r.action == HttpParamAction::shift && number_value(j.text)) {
        std::int64_t x = 0;
        std::from_chars(j.text.data(), j.text.data() + j.text.size(), x);
        j.text = std::to_string(x + env.shift_s());
        return true;
      }
      if (r.action == HttpParamAction::remove) {
        j = Json::string_of("");
        return true;
      }
      return false;
    case Json::Type::boolean:
      return r.action == HttpParamAction::keep && r.value == HttpValueGrammar::boolean;
    case Json::Type::array: {
      if (r.action == HttpParamAction::remove || r.action == HttpParamAction::shift) {
        j.items.clear();
        return r.action == HttpParamAction::remove;
      }
      std::vector<Json> kept;
      for (auto& e : j.items) {
        if (e.type != Json::Type::string) continue;
        auto ok = apply_json(r, e, env);
        if (!ok) return std::unexpected(ok.error());
        if (*ok) kept.push_back(std::move(e));
      }
      j.items = std::move(kept);
      return true;
    }
    case Json::Type::null:
    case Json::Type::object: return false;
  }
  return false;
}

}  // namespace

std::optional<std::string> form_decode(std::string_view s) {
  std::string t(s);
  std::replace(t.begin(), t.end(), '+', ' ');
  return percent_decode(t);
}

std::string form_encode(std::string_view s) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (char c : s) {
    const auto u = static_cast<unsigned char>(c);
    if (std::isalnum(u) != 0 || c == '-' || c == '.' || c == '_' || c == '~') {
      out.push_back(c);
    } else if (c == ' ') {
      out.push_back('+');
    } else {
      out.push_back('%');
      out.push_back(kHex[u >> 4]);
      out.push_back(kHex[u & 15]);
    }
  }
  return out;
}

Result<std::string> rewrite_form(std::string_view text, Env& env, std::string_view carrier) {
  (void)carrier;
  std::string out;
  std::size_t n = 0;
  std::size_t start = 0;
  bool oauth = false;
  while (start <= text.size()) {
    const auto amp = text.find('&', start);
    const auto pair = text.substr(start, amp == std::string_view::npos ? std::string_view::npos : amp - start);
    start = amp == std::string_view::npos ? text.size() + 1 : amp + 1;
    if (pair.empty()) continue;
    if (++n > kMaxParams) {
      Counters::bump(env.counters.removed_unknown, "http-param", "(limit)");
      continue;
    }
    const auto eq = pair.find('=');
    const auto name = form_decode(pair.substr(0, eq));
    const auto value = eq == std::string_view::npos ? std::optional<std::string>(std::string()) : form_decode(pair.substr(eq + 1));
    if (!name || !value) {
      Counters::bump(env.counters.removed_unknown, "http-param", "(invalid)");
      continue;
    }
    const auto* rule = env.rules.find_param(*name);
    if (rule == nullptr) {
      Counters::bump(env.counters.removed_unknown, "http-param", counted_name(*name));
      continue;
    }
    oauth = true;
    auto v = apply_string(*rule, *value, env);
    if (!v) return std::unexpected(v.error());
    if (v->out == Out::drop) {
      count(env, false, rule->name, "malformed");
      continue;
    }
    count(env, false, rule->name, action_word(*rule));
    if (!out.empty()) out.push_back('&');
    out += form_encode(*name);
    if (eq == std::string_view::npos && v->out == Out::keep) continue;
    out.push_back('=');
    if (v->out == Out::keep) out += form_encode(*value);
    else if (v->out == Out::set) out += form_encode(v->text);
  }
  if (oauth) ++env.counters.oauth_messages;
  return out;
}

Result<void> rewrite_object(Json& object, const std::vector<HttpParamRule>& rules, Env& env, bool claims) {
  std::vector<JsonMember> kept;
  for (auto& [name, value] : object.members) {
    const HttpParamRule* rule = nullptr;
    for (const auto& r : rules) {
      if (r.name == name) rule = &r;
    }
    if (rule == nullptr) {
      Counters::bump(env.counters.removed_unknown, claims ? "jwt-member" : "json-member", counted_name(name));
      continue;
    }
    auto ok = apply_json(*rule, value, env);
    if (!ok) return std::unexpected(ok.error());
    if (!*ok) {
      count(env, claims, rule->name, "malformed");
      continue;
    }
    count(env, claims, rule->name, action_word(*rule));
    kept.push_back(JsonMember{name, std::move(value)});
  }
  object.members = std::move(kept);
  return {};
}

Result<std::optional<std::string>> rewrite_json_body(std::string_view body, Env& env) {
  auto j = parse_json(body);
  if (!j || j->type != Json::Type::object) return std::optional<std::string>{};
  if (auto r = rewrite_object(*j, env.rules.params, env, false); !r) return std::unexpected(r.error());
  ++env.counters.oauth_messages;
  return std::optional<std::string>(write_json(*j));
}

}  // namespace mcxanon::http
