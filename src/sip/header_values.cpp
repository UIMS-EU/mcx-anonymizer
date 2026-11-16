// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/header_values.hpp"

#include "sip/limits.hpp"
#include "sip/render.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>

namespace mcxanon::sip {
namespace {

bool digit(char c) { return c >= '0' && c <= '9'; }
bool all_digits(std::string_view s) { return !s.empty() && std::all_of(s.begin(), s.end(), digit); }
bool is_wsp(char c) { return c == ' ' || c == '\t'; }

// Length of the head token at the start of `s` for the given kind.
std::size_t head_length(std::string_view s, HeadKind k) {
  std::size_t i = 0;
  switch (k) {
    case HeadKind::number:
      while (i < s.size() && digit(s[i])) ++i;
      return i;
    case HeadKind::session_id:
      while (i < s.size() && (digit(s[i]) || (s[i] >= 'a' && s[i] <= 'f'))) ++i;
      return i;
    case HeadKind::token:
    case HeadKind::media_type: {
      while (i < s.size() && is_token(s.substr(i, 1))) ++i;
      if (k == HeadKind::media_type) {
        // m-type SLASH m-subtype, SLASH = SWS "/" SWS
        std::size_t j = i;
        while (j < s.size() && is_wsp(s[j])) ++j;
        if (i == 0 || j >= s.size() || s[j] != '/') return 0;
        ++j;
        while (j < s.size() && is_wsp(s[j])) ++j;
        const std::size_t sub = j;
        while (j < s.size() && is_token(s.substr(j, 1))) ++j;
        if (j == sub) return 0;
        return j;
      }
      return i;
    }
  }
  return 0;
}

std::string squeeze_slash(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (!is_wsp(c)) out.push_back(c);
  }
  return out;
}

// A comment "(" *(ctext / quoted-pair / comment) ")" at the start of s; returns its length.
std::optional<std::size_t> comment_at(std::string_view s) {
  if (s.empty() || s.front() != '(') return std::nullopt;
  int depth = 0;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\') {
      ++i;
      continue;
    }
    if (s[i] == '(') ++depth;
    if (s[i] == ')' && --depth == 0) return i + 1;
    if (i > kMaxQuotedBytes) return std::nullopt;
  }
  return std::nullopt;
}

constexpr std::array<std::string_view, 7> kDays{"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"};
constexpr std::array<std::string_view, 12> kMonths{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

// Days since 1970-01-01 of a proleptic Gregorian date.
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const auto yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t z, std::int64_t& y, unsigned& m, unsigned& d) {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const auto doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  y += m <= 2;
}

bool host_and_port(std::string_view hp, std::string& host, HostKind& kind,
                   std::optional<std::string>& port) {
  // Parse through the URI parser, which validates host and port exactly.
  auto u = parse_uri("sip:" + std::string(hp));
  if (!u || u->user || !u->params.empty() || u->headers) return false;
  host = u->host;
  kind = u->host_kind;
  port = u->port;
  return true;
}

}  // namespace

std::optional<std::vector<std::string_view>> split_list(std::string_view value) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  bool quoted = false;
  bool angle = false;
  int paren = 0;
  for (std::size_t i = 0; i <= value.size(); ++i) {
    if (i < value.size()) {
      const char c = value[i];
      if (quoted) {
        if (c == '\\') {
          ++i;
        } else if (c == '"') {
          quoted = false;
        }
        continue;
      }
      if (c == '"') {
        quoted = true;
        continue;
      }
      if (c == '<' && paren == 0) angle = true;
      if (c == '>' && paren == 0) angle = false;
      if (c == '(' && !angle) ++paren;
      if (c == ')' && !angle && paren > 0) --paren;
      if (c != ',' || angle || paren > 0) continue;
    }
    if (quoted || angle || paren > 0) return std::nullopt;
    const auto elem = trim_lws(value.substr(start, i - start));
    if (elem.empty()) return std::nullopt;
    out.push_back(elem);
    if (out.size() > kMaxParamsPerHeader) return std::nullopt;
    start = i + 1;
  }
  return out;
}

std::optional<std::vector<NameAddr>> parse_name_addr_list(std::string_view value) {
  if (trim_lws(value) == "*") {
    NameAddr star;
    star.uri.kind = Scheme::other;
    star.uri.opaque = "*";
    return std::vector<NameAddr>{star};
  }
  auto parts = split_list(value);
  if (!parts) return std::nullopt;
  std::vector<NameAddr> out;
  for (auto p : *parts) {
    auto na = parse_name_addr(p);
    if (!na) return std::nullopt;
    out.push_back(std::move(*na));
  }
  return out;
}

std::optional<std::vector<Via>> parse_via(std::string_view value) {
  auto parts = split_list(value);
  if (!parts) return std::nullopt;
  std::vector<Via> out;
  for (auto p : *parts) {
    // sent-protocol LWS sent-by *( SEMI via-params ); sent-protocol = protocol-name SLASH
    // protocol-version SLASH transport, SLASH = SWS "/" SWS (RFC 3261 §25.1).
    Via v;
    std::size_t i = 0;
    for (int part = 0; part < 3; ++part) {
      while (part > 0 && i < p.size() && is_wsp(p[i])) ++i;
      const std::size_t t = i;
      while (i < p.size() && is_token(p.substr(i, 1))) ++i;
      if (i == t) return std::nullopt;
      v.protocol += p.substr(t, i - t);
      if (part < 2) {
        while (i < p.size() && is_wsp(p[i])) ++i;
        if (i >= p.size() || p[i] != '/') return std::nullopt;
        v.protocol.push_back('/');
        ++i;
      }
    }
    if (i >= p.size() || !is_wsp(p[i])) return std::nullopt;
    auto rest = trim_lws(p.substr(i));
    const auto semi = rest.find(';');
    const auto sent_by = trim_lws(rest.substr(0, semi));
    if (sent_by.empty()) return std::nullopt;
    if (!host_and_port(sent_by, v.host, v.host_kind, v.port)) return std::nullopt;
    auto params = parse_params(semi == std::string_view::npos ? std::string_view() : rest.substr(semi));
    if (!params) return std::nullopt;
    v.params = std::move(*params);
    out.push_back(std::move(v));
  }
  return out;
}

std::string render_via(const Via& v) {
  return v.protocol + " " + v.host + (v.port ? ":" + *v.port : "") + render_params(v.params);
}

std::optional<std::string> parse_call_id(std::string_view value) {
  value = trim_lws(value);
  // word = 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~" / "(" / ")" /
  //   "<" / ">" / ":" / "\" / DQUOTE / "/" / "[" / "]" / "?" / "{" / "}")
  const auto word = [](std::string_view w) {
    return !w.empty() && std::all_of(w.begin(), w.end(), [](char c) {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 ||
             std::string_view("-.!%*_+`'~()<>:\\\"/[]?{}").find(c) != std::string_view::npos;
    });
  };
  const auto at = value.find('@');
  if (at == std::string_view::npos) {
    if (!word(value)) return std::nullopt;
  } else if (!word(value.substr(0, at)) || !word(value.substr(at + 1))) {
    return std::nullopt;
  }
  return std::string(value);
}

std::optional<CSeq> parse_cseq(std::string_view value) {
  value = trim_lws(value);
  std::size_t i = 0;
  while (i < value.size() && digit(value[i])) ++i;
  if (i == 0 || i > 10) return std::nullopt;
  const auto number = value.substr(0, i);
  // RFC 3261 §8.1.1.5: the sequence number "MUST be less than 2**31".
  if (std::stoull(std::string(number)) >= (1ull << 31)) return std::nullopt;
  const auto method = trim_lws(value.substr(i));
  if (method.size() == value.size() - i || !is_token(method)) return std::nullopt;
  return CSeq{std::string(number), std::string(method)};
}

std::optional<std::vector<Item>> parse_items(std::string_view value, HeadKind head, bool multi) {
  std::vector<Item> out;
  if (trim_lws(value).empty()) {
    if (multi) return out;
    return std::nullopt;
  }
  auto parts = split_list(value);
  if (!parts || (!multi && parts->size() != 1)) return std::nullopt;
  for (auto p : *parts) {
    if (head == HeadKind::token && p.starts_with('"')) {
      // quoted-string head: parsed with the parameter parser's quoted-string rules
      std::size_t end = 1;
      while (end < p.size() && p[end] != '"') end += p[end] == '\\' ? std::size_t{2} : std::size_t{1};
      if (end >= p.size()) return std::nullopt;
      auto head_param = parse_params(";q=" + std::string(p.substr(0, end + 1)));
      if (!head_param || head_param->size() != 1) return std::nullopt;
      Item it;
      it.value = *head_param->front().value;
      it.quoted = true;
      auto params = parse_params(p.substr(end + 1));
      if (!params) return std::nullopt;
      it.params = std::move(*params);
      out.push_back(std::move(it));
      continue;
    }
    const auto n = head_length(p, head);
    if (n == 0) return std::nullopt;
    Item it;
    it.value = head == HeadKind::media_type ? squeeze_slash(p.substr(0, n)) : std::string(p.substr(0, n));
    if (head == HeadKind::session_id && it.value.size() != 32) return std::nullopt;
    auto params = parse_params(p.substr(n));
    if (!params) return std::nullopt;
    it.params = std::move(*params);
    out.push_back(std::move(it));
  }
  return out;
}

std::string render_item(const Item& item) {
  return (item.quoted ? quote(item.value) : item.value) + render_params(item.params);
}

std::optional<AuthValue> parse_auth(std::string_view value) {
  value = trim_lws(value);
  std::size_t i = 0;
  while (i < value.size() && is_token(value.substr(i, 1))) ++i;
  AuthValue a;
  a.scheme = std::string(value.substr(0, i));
  if (a.scheme.empty() || i == value.size() || !is_wsp(value[i])) return std::nullopt;
  auto parts = split_list(value.substr(i));
  if (!parts) return std::nullopt;
  for (auto p : *parts) {
    // auth-param = auth-param-name EQUAL ( token / quoted-string )
    auto params = parse_params(";" + std::string(p));
    if (!params || params->size() != 1 || !params->front().value) return std::nullopt;
    a.params.push_back(std::move(params->front()));
  }
  return a;
}

std::string render_auth(const AuthValue& a) {
  std::string out = a.scheme;
  for (std::size_t i = 0; i < a.params.size(); ++i) {
    const auto& p = a.params[i];
    out += (i ? ", " : " ") + p.name + "=" + (p.quoted ? quote(*p.value) : *p.value);
  }
  return out;
}

std::optional<std::vector<Warning>> parse_warning(std::string_view value) {
  auto parts = split_list(value);
  if (!parts) return std::nullopt;
  std::vector<Warning> out;
  for (auto p : *parts) {
    // warning-value = warn-code SP warn-agent SP warn-text
    if (p.size() < 4 || !all_digits(p.substr(0, 3)) || p[3] != ' ') return std::nullopt;
    Warning w;
    w.code = std::string(p.substr(0, 3));
    const auto rest = p.substr(4);
    const auto sp = rest.find(' ');
    if (sp == std::string_view::npos) return std::nullopt;
    w.agent = std::string(rest.substr(0, sp));
    std::string host;
    HostKind kind{};
    std::optional<std::string> port;
    if (!is_token(w.agent) && !host_and_port(w.agent, host, kind, port)) return std::nullopt;
    auto text = parse_params(";t=" + std::string(trim_lws(rest.substr(sp + 1))));
    if (!text || text->size() != 1 || !text->front().quoted) return std::nullopt;
    w.text = *text->front().value;
    out.push_back(std::move(w));
  }
  return out;
}

std::string render_warning(const Warning& w) { return w.code + " " + w.agent + " " + quote(w.text); }

std::optional<RetryAfter> parse_retry_after(std::string_view value) {
  value = trim_lws(value);
  std::size_t i = 0;
  while (i < value.size() && digit(value[i])) ++i;
  if (i == 0) return std::nullopt;
  RetryAfter r;
  r.seconds = std::string(value.substr(0, i));
  auto rest = trim_lws(value.substr(i));
  if (!rest.empty() && rest.front() == '(') {
    const auto n = comment_at(rest);
    if (!n) return std::nullopt;
    r.comment = std::string(rest.substr(1, *n - 2));
    rest = trim_lws(rest.substr(*n));
  }
  auto params = parse_params(rest);
  if (!params) return std::nullopt;
  r.params = std::move(*params);
  return r;
}

std::string render_retry_after(const RetryAfter& r) {
  return r.seconds + (r.comment ? " (" + *r.comment + ")" : "") + render_params(r.params);
}

std::optional<std::int64_t> parse_date(std::string_view v) {
  v = trim_lws(v);
  // wkday "," SP 2DIGIT SP month SP 4DIGIT SP 2DIGIT ":" 2DIGIT ":" 2DIGIT SP "GMT"
  if (v.size() != 29 || v[3] != ',' || v[4] != ' ' || v[7] != ' ' || v[11] != ' ' || v[16] != ' ' ||
      v[19] != ':' || v[22] != ':' || v[25] != ' ' || v.substr(26) != "GMT") {
    return std::nullopt;
  }
  const auto num = [&](std::size_t off, std::size_t n) -> std::optional<unsigned> {
    if (!all_digits(v.substr(off, n))) return std::nullopt;
    return static_cast<unsigned>(std::stoul(std::string(v.substr(off, n))));
  };
  const auto day = num(5, 2), year = num(12, 4), hh = num(17, 2), mm = num(20, 2), ss = num(23, 2);
  if (!day || !year || !hh || !mm || !ss) return std::nullopt;
  const auto mon = std::find(kMonths.begin(), kMonths.end(), v.substr(8, 3));
  const auto wk = std::find(kDays.begin(), kDays.end(), v.substr(0, 3));
  if (mon == kMonths.end() || wk == kDays.end()) return std::nullopt;
  const auto m = static_cast<unsigned>(mon - kMonths.begin()) + 1;
  if (*day < 1 || *hh > 23 || *mm > 59 || *ss > 60) return std::nullopt;
  const std::int64_t days = days_from_civil(*year, m, *day);
  std::int64_t y = 0;
  unsigned m2 = 0, d2 = 0;
  civil_from_days(days, y, m2, d2);
  if (m2 != m || d2 != *day) return std::nullopt;  // e.g. 31 Feb
  if (kDays[static_cast<std::size_t>(((days % 7) + 7) % 7)] != *wk) return std::nullopt;
  return days * 86400 + *hh * 3600 + *mm * 60 + *ss;
}

std::string render_date(std::int64_t t) {
  std::int64_t days = t / 86400;
  std::int64_t secs = t % 86400;
  if (secs < 0) {
    secs += 86400;
    --days;
  }
  std::int64_t y = 0;
  unsigned m = 0, d = 0;
  civil_from_days(days, y, m, d);
  char buf[40];
  std::snprintf(buf, sizeof buf, "%s, %02u %s %04lld %02lld:%02lld:%02lld GMT",
                std::string(kDays[static_cast<std::size_t>(((days % 7) + 7) % 7)]).c_str(), d,
                std::string(kMonths[m - 1]).c_str(), static_cast<long long>(y),
                static_cast<long long>(secs / 3600), static_cast<long long>((secs / 60) % 60),
                static_cast<long long>(secs % 60));
  return buf;
}

}  // namespace mcxanon::sip
