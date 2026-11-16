// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/uri.hpp"

#include "sip/limits.hpp"
#include "sip/render.hpp"

#include <algorithm>
#include <cctype>

namespace mcxanon::sip {
namespace {

bool alnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool alpha(char c) { return std::isalpha(static_cast<unsigned char>(c)) != 0; }
bool digit(char c) { return c >= '0' && c <= '9'; }
bool hexdig(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }
bool in(char c, std::string_view set) { return set.find(c) != std::string_view::npos; }

// RFC 3261 §25.1 unreserved = alphanum / mark; mark = "-" "_" "." "!" "~" "*" "'" "(" ")"
bool unreserved(char c) { return alnum(c) || in(c, "-_.!~*'()"); }

// Validates `s` against chars + escaped ("%" HEXDIG HEXDIG).
template <class Pred>
bool escaped_chars(std::string_view s, Pred ok) {
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%') {
      if (i + 2 >= s.size() + 0 || !hexdig(s[i + 1]) || !hexdig(s[i + 2])) return false;
      i += 2;
    } else if (!ok(s[i])) {
      return false;
    }
  }
  return true;
}

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

// RFC 3261 §25.1 hostname: *( domainlabel "." ) toplabel [ "." ]; labels of alphanum and
// hyphens, not starting or ending with a hyphen, the toplabel starting with ALPHA. Underscores
// are accepted inside labels (seen in lab systems); everything else fails.
bool hostname(std::string_view s) {
  if (s.ends_with('.')) s.remove_suffix(1);
  if (s.empty() || s.size() > 255) return false;
  std::size_t start = 0;
  std::string_view last;
  for (;;) {
    const auto dot = s.find('.', start);
    const auto label = s.substr(start, dot == std::string_view::npos ? dot : dot - start);
    if (label.empty() || label.size() > 63 || !alnum(label.front()) || !alnum(label.back())) {
      return false;
    }
    if (!std::all_of(label.begin(), label.end(), [](char c) { return alnum(c) || c == '-' || c == '_'; })) {
      return false;
    }
    last = label;
    if (dot == std::string_view::npos) break;
    start = dot + 1;
  }
  return alpha(last.front());
}

std::optional<HostKind> host_kind(std::string_view h) {
  if (h.starts_with('[')) {
    if (parse_ipv6_text(h)) return HostKind::ipv6;
    return std::nullopt;
  }
  if (!h.empty() && std::all_of(h.begin(), h.end(), [](char c) { return digit(c) || c == '.'; })) {
    if (parse_ipv4_text(h)) return HostKind::ipv4;
    return std::nullopt;
  }
  if (hostname(h)) return HostKind::domain;
  return std::nullopt;
}

bool port_ok(std::string_view p) {
  if (p.empty() || p.size() > 5 || !std::all_of(p.begin(), p.end(), digit)) return false;
  return std::stoul(std::string(p)) <= 65535;
}

// uri-parameter: pname [ "=" pvalue ], paramchar = param-unreserved / unreserved / escaped,
// param-unreserved = "[" / "]" / "/" / ":" / "&" / "+" / "$" (RFC 3261 §25.1; the same set is
// RFC 3966's paramchar).
bool paramchar(char c) { return unreserved(c) || in(c, "[]/:&+$"); }

std::optional<std::vector<Param>> uri_params(std::string_view s) {
  std::vector<Param> out;
  if (s.empty()) return out;
  if (s.front() != ';') return std::nullopt;
  std::size_t i = 1;
  for (;;) {
    const auto semi = s.find(';', i);
    const auto item = s.substr(i, semi == std::string_view::npos ? semi : semi - i);
    const auto eq = item.find('=');
    Param p;
    p.name = std::string(item.substr(0, eq));
    if (p.name.empty() || !escaped_chars(p.name, paramchar)) return std::nullopt;
    if (eq != std::string_view::npos) {
      const auto v = item.substr(eq + 1);
      if (v.empty() || !escaped_chars(v, paramchar)) return std::nullopt;
      p.value = std::string(v);
    }
    out.push_back(std::move(p));
    if (out.size() > kMaxParamsPerHeader) return std::nullopt;
    if (semi == std::string_view::npos) break;
    i = semi + 1;
  }
  return out;
}

std::optional<Uri> parse_sip(Uri u, std::string_view rest) {
  const auto q = rest.find('?');
  if (q != std::string_view::npos) {
    const auto h = rest.substr(q + 1);
    // hnv-unreserved / unreserved / escaped, plus the "=" and "&" separators.
    if (!escaped_chars(h, [](char c) { return unreserved(c) || in(c, "[]/?:+$=&"); })) return std::nullopt;
    u.headers = std::string(h);
    rest = rest.substr(0, q);
  }
  const auto at = rest.find('@');
  if (at != std::string_view::npos) {
    const auto userinfo = rest.substr(0, at);
    const auto colon = userinfo.find(':');
    const auto user = userinfo.substr(0, colon);
    // user = 1*( unreserved / escaped / user-unreserved ), user-unreserved = & = + $ , ; ? /
    if (user.empty() || !escaped_chars(user, [](char c) { return unreserved(c) || in(c, "&=+$,;?/"); })) {
      return std::nullopt;
    }
    if (colon != std::string_view::npos) {
      const auto pw = userinfo.substr(colon + 1);
      if (!escaped_chars(pw, [](char c) { return unreserved(c) || in(c, "&=+$,"); })) return std::nullopt;
      u.had_password = true;
    }
    u.user = std::string(user);
    rest = rest.substr(at + 1);
  }
  const auto semi = rest.find(';');
  auto hostport = rest.substr(0, semi);
  const auto params = semi == std::string_view::npos ? std::string_view() : rest.substr(semi);
  std::string_view host = hostport;
  if (hostport.starts_with('[')) {
    const auto close = hostport.find(']');
    if (close == std::string_view::npos) return std::nullopt;
    host = hostport.substr(0, close + 1);
    const auto after = hostport.substr(close + 1);
    if (!after.empty()) {
      if (after.front() != ':' || !port_ok(after.substr(1))) return std::nullopt;
      u.port = std::string(after.substr(1));
    }
  } else {
    const auto colon = hostport.find(':');
    if (colon != std::string_view::npos) {
      if (!port_ok(hostport.substr(colon + 1))) return std::nullopt;
      u.port = std::string(hostport.substr(colon + 1));
      host = hostport.substr(0, colon);
    }
  }
  const auto kind = host_kind(host);
  if (!kind) return std::nullopt;
  u.host = std::string(host);
  u.host_kind = *kind;
  auto p = uri_params(params);
  if (!p) return std::nullopt;
  u.params = std::move(*p);
  return u;
}

std::optional<Uri> parse_tel(Uri u, std::string_view rest) {
  const auto semi = rest.find(';');
  const auto number = rest.substr(0, semi);
  if (number.empty()) return std::nullopt;
  const bool global = number.front() == '+';
  const auto digits = global ? number.substr(1) : number;
  // RFC 3966 §3: global-number-digits = "+" *phonedigit DIGIT *phonedigit;
  // local-number-digits = *phonedigit-hex (HEXDIG / "*" / "#") *phonedigit-hex;
  // visual-separator = "-" / "." / "(" / ")".
  const bool ok = std::all_of(digits.begin(), digits.end(), [&](char c) {
    return digit(c) || in(c, "-.()") || (!global && (hexdig(c) || c == '*' || c == '#'));
  });
  const bool has_digit = std::any_of(digits.begin(), digits.end(), [&](char c) {
    return digit(c) || (!global && (hexdig(c) || c == '*' || c == '#'));
  });
  if (!ok || !has_digit) return std::nullopt;
  u.user = std::string(number);
  auto p = uri_params(semi == std::string_view::npos ? std::string_view() : rest.substr(semi));
  if (!p) return std::nullopt;
  u.params = std::move(*p);
  if (!global && std::none_of(u.params.begin(), u.params.end(),
                              [](const Param& x) { return iequal(x.name, "phone-context"); })) {
    return std::nullopt;  // RFC 3966 §3: a local number needs its context
  }
  return u;
}

std::string escape_quoted(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (c == '"' || c == '\\') out.push_back('\\');
    out.push_back(c);
  }
  return out;
}

// quoted-string at the start of `s`: returns (unescaped content, length consumed).
std::optional<std::pair<std::string, std::size_t>> quoted_at(std::string_view s) {
  if (s.empty() || s.front() != '"') return std::nullopt;
  std::string out;
  for (std::size_t i = 1; i < s.size(); ++i) {
    const char c = s[i];
    if (c == '"') return std::pair{out, i + 1};
    if (c == '\\') {
      if (i + 1 >= s.size()) return std::nullopt;
      const auto n = static_cast<unsigned char>(s[i + 1]);
      if (n > 0x7F || n == '\r' || n == '\n') return std::nullopt;  // quoted-pair %x00-09/0B-0C/0E-7F
      out.push_back(s[++i]);
    } else if (c == '\r' || c == '\n') {
      return std::nullopt;
    } else {
      out.push_back(c);
    }
    if (out.size() > kMaxQuotedBytes) return std::nullopt;
  }
  return std::nullopt;
}

bool is_wsp(char c) { return c == ' ' || c == '\t'; }

}  // namespace

bool is_token(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
    return alnum(c) || in(c, "-.!%*_+`'~");
  });
}

std::string_view trim_lws(std::string_view s) {
  while (!s.empty() && is_wsp(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_wsp(s.back())) s.remove_suffix(1);
  return s;
}

std::string quote(std::string_view text) { return "\"" + escape_quoted(text) + "\""; }

std::string percent_decode(std::string_view text) {
  std::string out;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '%' && i + 2 < text.size() + 0 && hexdig(text[i + 1]) && hexdig(text[i + 2])) {
      out.push_back(static_cast<char>(std::stoi(std::string(text.substr(i + 1, 2)), nullptr, 16)));
      i += 2;
    } else {
      out.push_back(text[i]);
    }
  }
  return out;
}

std::optional<Uri> parse_uri(std::string_view text) {
  const auto colon = text.find(':');
  if (colon == std::string_view::npos || colon == 0) return std::nullopt;
  Uri u;
  u.scheme = std::string(text.substr(0, colon));
  // RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  if (!alpha(u.scheme.front()) ||
      !std::all_of(u.scheme.begin(), u.scheme.end(), [](char c) { return alnum(c) || in(c, "+-."); })) {
    return std::nullopt;
  }
  const auto rest = text.substr(colon + 1);
  if (iequal(u.scheme, "sip") || iequal(u.scheme, "sips")) {
    u.kind = iequal(u.scheme, "sip") ? Scheme::sip : Scheme::sips;
    return parse_sip(std::move(u), rest);
  }
  if (iequal(u.scheme, "tel")) {
    u.kind = Scheme::tel;
    return parse_tel(std::move(u), rest);
  }
  // Another scheme: printable, no whitespace, no delimiters of the header grammar.
  if (rest.empty() || !std::all_of(rest.begin(), rest.end(), [](char c) {
        const auto x = static_cast<unsigned char>(c);
        return x > 0x20 && x < 0x7F && !in(c, "<>\"");
      })) {
    return std::nullopt;
  }
  u.kind = Scheme::other;
  u.opaque = std::string(rest);
  return u;
}

std::string render_uri(const Uri& u) {
  std::string out = u.scheme + ":";
  if (u.kind == Scheme::other) return out + u.opaque;
  if (u.kind == Scheme::tel) {
    out += u.user.value_or("");
  } else {
    if (u.user) out += *u.user + "@";
    out += u.host;
    if (u.port) out += ":" + *u.port;
  }
  for (const auto& p : u.params) {
    out += ";" + p.name;
    if (p.value) out += "=" + *p.value;
  }
  if (u.headers) out += "?" + *u.headers;
  return out;
}

std::optional<std::vector<Param>> parse_params(std::string_view text) {
  std::vector<Param> out;
  text = trim_lws(text);
  while (!text.empty()) {
    if (text.front() != ';') return std::nullopt;
    text = trim_lws(text.substr(1));
    std::size_t i = 0;
    while (i < text.size() && is_token(text.substr(i, 1))) ++i;
    Param p;
    p.name = std::string(text.substr(0, i));
    if (p.name.empty()) return std::nullopt;
    text = trim_lws(text.substr(i));
    if (!text.empty() && text.front() == '=') {
      text = trim_lws(text.substr(1));
      if (!text.empty() && text.front() == '"') {
        auto q = quoted_at(text);
        if (!q) return std::nullopt;
        p.value = q->first;
        p.quoted = true;
        text = trim_lws(text.substr(q->second));
      } else {
        // token / host (an IPv6 reference included)
        std::size_t j = 0;
        while (j < text.size() && (is_token(text.substr(j, 1)) || in(text[j], "[]:"))) ++j;
        if (j == 0) return std::nullopt;
        p.value = std::string(text.substr(0, j));
        text = trim_lws(text.substr(j));
      }
    }
    out.push_back(std::move(p));
    if (out.size() > kMaxParamsPerHeader) return std::nullopt;
  }
  return out;
}

std::string render_params(const std::vector<Param>& params) {
  std::string out;
  for (const auto& p : params) {
    out += ";" + p.name;
    if (p.value) out += "=" + (p.quoted ? quote(*p.value) : *p.value);
  }
  return out;
}

std::optional<NameAddr> parse_name_addr(std::string_view text) {
  text = trim_lws(text);
  NameAddr na;
  std::string_view after;
  if (!text.empty() && text.front() == '"') {
    auto q = quoted_at(text);
    if (!q) return std::nullopt;
    na.display = q->first;
    na.display_quoted = true;
    text = trim_lws(text.substr(q->second));
    if (text.empty() || text.front() != '<') return std::nullopt;
  }
  const auto lt = text.find('<');
  if (lt != std::string_view::npos) {
    if (!na.display_quoted && lt > 0) {
      // display-name = *(token LWS): join the tokens with one SP.
      std::string disp;
      std::size_t i = 0;
      const auto head = text.substr(0, lt);
      while (i < head.size()) {
        while (i < head.size() && is_wsp(head[i])) ++i;
        std::size_t j = i;
        while (j < head.size() && !is_wsp(head[j])) ++j;
        if (j > i) {
          const auto tok = head.substr(i, j - i);
          if (!is_token(tok)) return std::nullopt;
          if (!disp.empty()) disp.push_back(' ');
          disp += tok;
        }
        i = j;
      }
      if (!disp.empty()) na.display = disp;
    }
    const auto gt = text.find('>', lt);
    if (gt == std::string_view::npos) return std::nullopt;
    auto u = parse_uri(text.substr(lt + 1, gt - lt - 1));
    if (!u) return std::nullopt;
    na.uri = std::move(*u);
    na.angle = true;
    after = text.substr(gt + 1);
  } else {
    // addr-spec: the URI ends at the first ';' (RFC 3261 §20.10); no display name.
    const auto semi = text.find(';');
    auto u = parse_uri(trim_lws(text.substr(0, semi)));
    if (!u) return std::nullopt;
    na.uri = std::move(*u);
    after = semi == std::string_view::npos ? std::string_view() : text.substr(semi);
  }
  auto p = parse_params(after);
  if (!p) return std::nullopt;
  na.params = std::move(*p);
  return na;
}

std::string render_name_addr(const NameAddr& v) {
  std::string out;
  if (v.angle) {
    if (v.display) out += (v.display_quoted ? quote(*v.display) : *v.display) + " ";
    out += "<" + render_uri(v.uri) + ">";
  } else {
    out += render_uri(v.uri);
  }
  return out + render_params(v.params);
}

}  // namespace mcxanon::sip
