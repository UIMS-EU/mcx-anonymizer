// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/target.hpp"

#include "http/limits.hpp"
#include "http/message.hpp"
#include "http/params.hpp"
#include "sip/rewrite.hpp"
#include "xml/categories.hpp"
#include "xml/xcap.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <vector>

namespace mcxanon::http {

namespace {

const auto kNone = std::optional<std::string>{};

bool starts_ci(std::string_view s, std::string_view p) { return s.size() >= p.size() && iequal(s.substr(0, p.size()), p); }

bool unreserved(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '.' || c == '_' || c == '~';
}

// RFC 3986 pchar without the percent-encoded form: unreserved / sub-delims / ":" / "@".
bool pchar(char c) { return unreserved(c) || std::string_view("!$&'()*+,;=:@").find(c) != std::string_view::npos; }

Opt opaque(std::string_view v, Env& env) { return opaque_text(v, env); }

// The octets the input escaped, so that the output escapes them too.
std::string escaped_set(std::string_view s) {
  std::string set;
  for (std::size_t i = 0; i + 2 < s.size(); ++i) {
    if (s[i] != '%') continue;
    const auto d = percent_decode(s.substr(i, 3));
    if (d && d->size() == 1 && set.find((*d)[0]) == std::string::npos) set.push_back((*d)[0]);
  }
  return set;
}

Opt rewrite_url(std::string_view v, Env& env) {
  const auto colon = v.find("://");
  const auto scheme = v.substr(0, colon);
  std::string out(scheme);
  out += "://";
  std::string_view rest = v.substr(colon + 3);
  const auto end = rest.find_first_of("/?#");
  std::string_view authority = rest.substr(0, end);
  rest = end == std::string_view::npos ? std::string_view() : rest.substr(end);
  if (const auto at = authority.rfind('@'); at != std::string_view::npos) {
    // RFC 3986 §3.2.1: userinfo, possibly with a password (FR-013): it leaves.
    env.credential("uri-userinfo", authority.substr(0, at));
    authority.remove_prefix(at + 1);
  }
  auto a = rewrite_authority(authority, env);
  if (!a || !*a) return a;
  out += **a;
  std::string_view path = rest;
  std::string_view query;
  std::string_view fragment;
  if (const auto h = path.find('#'); h != std::string_view::npos) {
    fragment = path.substr(h + 1);
    path = path.substr(0, h);
  }
  bool has_query = false;
  if (const auto q = path.find('?'); q != std::string_view::npos) {
    query = path.substr(q + 1);
    path = path.substr(0, q);
    has_query = true;
  }
  if (!path.empty()) {
    auto p = rewrite_path(path, env);
    if (!p || !*p) return p;
    out += **p;
  }
  if (has_query) {
    auto q = rewrite_form(query, env, "query");
    if (!q) return std::unexpected(q.error());
    out += "?" + *q;
  }
  if (!fragment.empty()) {
    const auto d = percent_decode(fragment);
    if (!d) return kNone;
    auto f = opaque(*d, env);
    if (!f || !*f) return f;
    out += "#" + percent_encode(**f, escaped_set(fragment));
  }
  return std::optional<std::string>(std::move(out));
}

bool http_url(std::string_view v) {
  return (starts_ci(v, "http://") || starts_ci(v, "https://")) && v.size() > (v[4] == ':' ? 7u : 8u);
}

}  // namespace

Opt opaque_text(std::string_view v, Env& env) {
  if (v.empty()) return std::optional<std::string>(std::string());
  if (v.size() < 4 && std::all_of(v.begin(), v.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' || c == '_' || c == '-';
      })) {
    return std::optional<std::string>(std::string(v));
  }
  // A class-keeping pseudonym changes only ASCII letters and digits; a value with fewer than four
  // has (almost) no pseudonym space and is removed instead.
  if (std::count_if(v.begin(), v.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }) < 4) {
    return kNone;
  }
  auto p = env.sip.mapper.text(Category::opaque, v);
  if (!p) return std::unexpected(p.error());
  return std::optional<std::string>(std::move(*p));
}

std::optional<std::string> percent_decode(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '%') {
      out.push_back(s[i]);
      continue;
    }
    if (i + 2 >= s.size() || std::isxdigit(static_cast<unsigned char>(s[i + 1])) == 0 ||
        std::isxdigit(static_cast<unsigned char>(s[i + 2])) == 0) {
      return std::nullopt;
    }
    const auto hex = [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0 ? c - '0' : (std::tolower(static_cast<unsigned char>(c)) - 'a' + 10); };
    out.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
    i += 2;
  }
  return out;
}

std::string percent_encode(std::string_view s, std::string_view also_escape) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (char c : s) {
    if (pchar(c) && also_escape.find(c) == std::string_view::npos) {
      out.push_back(c);
    } else {
      const auto u = static_cast<unsigned char>(c);
      out.push_back('%');
      out.push_back(kHex[u >> 4]);
      out.push_back(kHex[u & 15]);
    }
  }
  return out;
}

Opt rewrite_identity(std::string_view v, Env& env) {
  if (v.empty() || v.size() > kMaxToken) return kNone;
  if (starts_ci(v, "sip:") || starts_ci(v, "sips:") || starts_ci(v, "tel:")) return sip::rewrite_uri_text(v, env.sip);
  if (starts_ci(v, "urn:uuid:") || starts_ci(v, "urn:gsma:imei:")) return sip::map_instance(v, env.sip);
  if (http_url(v)) return rewrite_url(v, env);
  if (v.find('@') != std::string_view::npos && v.find(':') == std::string_view::npos) {
    auto u = xml::map_category(XmlCategory::user_at_host, v, env.sip);
    if (!u || *u) return u;
    return opaque(v, env);
  }
  // A bare value (no scheme, no "@") in an identity parameter, claim or header is a user name:
  // the MC ID of TS 23.280 §8.1.1 in `sub` or `username` (TS 33.180 §5.1.2.1) gets the pseudonym
  // of the same user part in SIP URIs (SC-003). Values that are no user
  // part are opaque.
  // RFC 3261 §25.1: user = 1*( unreserved / escaped / user-unreserved ).
  const bool user_part = std::all_of(v.begin(), v.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("-_.!~*'()%&=+$,;?/").find(c) != std::string_view::npos;
  });
  if (user_part) {
    auto u = sip::map_value(SipCategory::sip_user, v, env.sip);
    if (!u || *u) return u;
  }
  return opaque(v, env);
}

Opt rewrite_authority(std::string_view authority, Env& env) {
  if (authority.empty()) return kNone;
  std::string_view host = authority;
  std::string_view port;
  if (host.front() == '[') {
    const auto close = host.find(']');
    if (close == std::string_view::npos) return kNone;
    port = host.substr(close + 1);
    host = host.substr(0, close + 1);
  } else if (const auto c = host.rfind(':'); c != std::string_view::npos) {
    port = host.substr(c);
    host = host.substr(0, c);
  }
  if (!port.empty() &&
      (port.front() != ':' || port.size() > 6 || !std::all_of(port.begin() + 1, port.end(), [](char c) { return c >= '0' && c <= '9'; }))) {
    return kNone;
  }
  auto h = sip::map_host(host, env.sip);
  if (!h || !*h) return h;
  return std::optional<std::string>(**h + std::string(port));
}

Opt rewrite_uri_ref(std::string_view v, Env& env) {
  if (v.empty() || v.size() > kMaxToken) return kNone;
  if (http_url(v)) return rewrite_url(v, env);
  if (starts_ci(v, "sip:") || starts_ci(v, "sips:") || starts_ci(v, "tel:")) return sip::rewrite_uri_text(v, env.sip);
  if (starts_ci(v, "urn:uuid:") || starts_ci(v, "urn:gsma:imei:")) return sip::map_instance(v, env.sip);
  if (v.front() == '/' && !v.starts_with("//")) {
    std::string_view path = v;
    std::string_view query;
    bool has_query = false;
    if (const auto h = path.find('#'); h != std::string_view::npos) path = path.substr(0, h);  // fragment dropped
    if (const auto q = path.find('?'); q != std::string_view::npos) {
      query = path.substr(q + 1);
      path = path.substr(0, q);
      has_query = true;
    }
    auto p = rewrite_path(path, env);
    if (!p || !*p) return p;
    std::string out = **p;
    if (has_query) {
      auto q = rewrite_form(query, env, "query");
      if (!q) return std::unexpected(q.error());
      out += "?" + *q;
    }
    return std::optional<std::string>(std::move(out));
  }
  return kNone;  // other schemes and relative references without a path are not understood
}

Opt rewrite_path(std::string_view path, Env& env) {
  if (path.empty() || path.front() != '/') return kNone;
  std::vector<std::string_view> raw;
  for (std::size_t start = 1;;) {
    const auto slash = path.find('/', start);
    raw.push_back(path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start));
    if (slash == std::string_view::npos) break;
    start = slash + 1;
  }
  std::vector<std::string> decoded;
  bool xcap = path.find("/~~/") != std::string_view::npos;
  for (const auto s : raw) {
    auto d = percent_decode(s);
    if (!d) return kNone;
    if (xml::is_known_auid(*d)) xcap = true;
    decoded.push_back(std::move(*d));
  }
  if (xcap) {
    // The XCAP root segments before the AUID are opaque; the document selector from the AUID on
    // is the 003 XCAP selector in its relative form (E.7.4).
    ++env.counters.xcap_selectors;
    std::size_t auid = raw.size();
    for (std::size_t k = 0; k < decoded.size(); ++k) {
      if (xml::is_known_auid(decoded[k])) {
        auid = k;
        break;
      }
    }
    if (auid == raw.size()) {
      ++env.counters.xcap_malformed;
      return kNone;
    }
    std::string out;
    for (std::size_t k = 0; k < auid; ++k) {
      out.push_back('/');
      auto m = opaque(decoded[k], env);
      if (!m || !*m) return m;
      out += percent_encode(**m, escaped_set(raw[k]) + "/?#");
    }
    const auto from = static_cast<std::size_t>(raw[auid].data() - path.data());
    auto r = xml::map_category(XmlCategory::xcap_selector, path.substr(from), env.sip);
    if (!r) return r;
    if (!*r) {
      ++env.counters.xcap_malformed;
      return kNone;
    }
    out += "/" + **r;
    return std::optional<std::string>(std::move(out));
  }
  std::string out;
  for (std::size_t k = 0; k < raw.size(); ++k) {
    out.push_back('/');
    const auto& d = decoded[k];
    if (d.empty()) continue;
    if (env.rules.kept_segment(d)) {
      out += raw[k];
      continue;
    }
    // File names look like domain names: only URIs and user@host take the identity mapping here.
    const bool id = starts_ci(d, "sip:") || starts_ci(d, "sips:") || starts_ci(d, "tel:") ||
                    (d.find('@') != std::string::npos && d.find(':') == std::string::npos);
    auto m = id ? rewrite_identity(d, env) : opaque(d, env);
    if (!m) return m;
    if (!*m) return kNone;
    out += percent_encode(**m, escaped_set(raw[k]) + "/?#");
  }
  return std::optional<std::string>(std::move(out));
}

Opt rewrite_target(std::string_view target, std::string_view method, Env& env) {
  if (target == "*") return std::optional<std::string>("*");  // asterisk-form (OPTIONS)
  if (method == "CONNECT") return rewrite_authority(target, env);  // authority-form
  if (http_url(target)) return rewrite_url(target, env);           // absolute-form
  if (target.front() != '/') return kNone;
  std::string_view path = target;
  std::string_view query;
  bool has_query = false;
  if (const auto q = path.find('?'); q != std::string_view::npos) {
    query = path.substr(q + 1);
    path = path.substr(0, q);
    has_query = true;
  }
  auto p = rewrite_path(path, env);
  if (!p || !*p) return p;
  std::string out = **p;
  if (has_query) {
    auto q = rewrite_form(query, env, "query");
    if (!q) return std::unexpected(q.error());
    out += "?" + *q;
  }
  return std::optional<std::string>(std::move(out));
}

}  // namespace mcxanon::http
