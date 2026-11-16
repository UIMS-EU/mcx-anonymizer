// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/values.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <cctype>

namespace mcxanon::xml {
namespace {

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
bool digit(char c) { return c >= '0' && c <= '9'; }
bool alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool hexd(char c) { return digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

// n digits at s[i..] as a number, advancing i; -1 if not exactly n digits.
int fixed_digits(std::string_view s, std::size_t& i, std::size_t n) {
  if (i + n > s.size()) return -1;
  int v = 0;
  for (std::size_t k = 0; k < n; ++k) {
    if (!digit(s[i + k])) return -1;
    v = v * 10 + (s[i + k] - '0');
  }
  i += n;
  return v;
}

bool lit(std::string_view s, std::size_t& i, char c) {
  if (i < s.size() && s[i] == c) {
    ++i;
    return true;
  }
  return false;
}

// XSD date part: -?YYYY(Y*)-MM-DD
bool date_part(std::string_view s, std::size_t& i) {
  lit(s, i, '-');
  std::size_t y = 0;
  while (i + y < s.size() && digit(s[i + y])) ++y;
  if (y < 4 || (y > 4 && s[i] == '0')) return false;
  i += y;
  if (!lit(s, i, '-')) return false;
  const int m = fixed_digits(s, i, 2);
  if (m < 1 || m > 12 || !lit(s, i, '-')) return false;
  const int d = fixed_digits(s, i, 2);
  return d >= 1 && d <= 31;
}

// hh:mm:ss(.s+)?
bool time_part(std::string_view s, std::size_t& i) {
  const int h = fixed_digits(s, i, 2);
  if (h < 0 || !lit(s, i, ':')) return false;
  const int m = fixed_digits(s, i, 2);
  if (m < 0 || m > 59 || !lit(s, i, ':')) return false;
  const int sec = fixed_digits(s, i, 2);
  if (sec < 0 || sec > 59) return false;
  bool frac = false;
  if (lit(s, i, '.')) {
    std::size_t n = 0;
    while (i < s.size() && digit(s[i])) {
      ++i;
      ++n;
      frac = frac || s[i - 1] != '0';
    }
    if (n == 0) return false;
  }
  return h < 24 || (h == 24 && m == 0 && sec == 0 && !frac);
}

// (Z | (+|-)hh:mm)?
bool timezone(std::string_view s, std::size_t& i) {
  if (i == s.size()) return true;
  if (lit(s, i, 'Z')) return i == s.size();
  if (s[i] != '+' && s[i] != '-') return false;
  ++i;
  const int h = fixed_digits(s, i, 2);
  if (h < 0 || h > 14 || !lit(s, i, ':')) return false;
  const int m = fixed_digits(s, i, 2);
  return m >= 0 && m <= 59 && (h < 14 || m == 0) && i == s.size();
}

bool duration(std::string_view s) {
  std::size_t i = 0;
  lit(s, i, '-');
  if (!lit(s, i, 'P')) return false;
  bool any = false, in_time = false, time_any = false;
  const std::string_view date_units = "YMD", time_units = "HMS";
  std::size_t next_unit = 0;
  while (i < s.size()) {
    if (s[i] == 'T') {
      if (in_time) return false;
      in_time = true;
      next_unit = 0;
      ++i;
      continue;
    }
    std::size_t n = 0;
    while (i + n < s.size() && digit(s[i + n])) ++n;
    if (n == 0) return false;
    i += n;
    bool frac = false;
    if (in_time && lit(s, i, '.')) {
      std::size_t f = 0;
      while (i + f < s.size() && digit(s[i + f])) ++f;
      if (f == 0) return false;
      i += f;
      frac = true;
    }
    if (i >= s.size()) return false;
    const auto units = in_time ? time_units : date_units;
    const auto u = units.find(s[i], next_unit);
    if (u == std::string_view::npos || (frac && s[i] != 'S')) return false;
    next_unit = u + 1;
    ++i;
    any = true;
    time_any = time_any || in_time;
  }
  return any && (!in_time || time_any);
}

bool lang(std::string_view s) {  // xs:language: [a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*
  std::size_t i = 0;
  bool first = true;
  while (true) {
    std::size_t n = 0;
    while (i + n < s.size() && (alpha(s[i + n]) || (!first && digit(s[i + n])))) ++n;
    if (n < 1 || n > 8) return false;
    i += n;
    first = false;
    if (i == s.size()) return true;
    if (s[i] != '-') return false;
    ++i;
  }
}

bool token_nodot(std::string_view s) {
  return !s.empty() && s.size() <= 32 && std::all_of(s.begin(), s.end(), [](char c) {
    return alpha(c) || digit(c) || std::string_view("-!%*_+`'~").find(c) != std::string_view::npos;
  });
}

bool token(TokenGrammar g, std::string_view s) {
  switch (g) {
    case TokenGrammar::trigger_id:
      return !s.empty() && s.size() <= 64 && std::all_of(s.begin(), s.end(), [](char c) {
        return alpha(c) || digit(c) || c == '-' || c == '_' || c == '.' || c == ':';
      });
    case TokenGrammar::hex_counter:
      return !s.empty() && s.size() <= 8 && std::all_of(s.begin(), s.end(), hexd);
    case TokenGrammar::r_value: {
      const auto dot = s.find('.');
      return dot != std::string_view::npos && token_nodot(s.substr(0, dot)) && token_nodot(s.substr(dot + 1));
    }
    case TokenGrammar::ncname:
      return !s.empty() && s.size() <= 64 && (alpha(s[0]) || s[0] == '_') &&
             std::all_of(s.begin(), s.end(), [](char c) { return alpha(c) || digit(c) || c == '_' || c == '-' || c == '.'; });
    case TokenGrammar::rfc_token:
      return !s.empty() && s.size() <= 64 && std::all_of(s.begin(), s.end(), [](char c) {
        return alpha(c) || digit(c) || std::string_view("-.!%*_+`'~").find(c) != std::string_view::npos;
      });
    case TokenGrammar::qvalue: {
      if (s.empty() || (s[0] != '0' && s[0] != '1')) return false;
      if (s.size() == 1) return true;
      if (s[1] != '.' || s.size() > 5) return false;
      const auto frac = s.substr(2);
      return std::all_of(frac.begin(), frac.end(), [&](char c) { return s[0] == '0' ? digit(c) : c == '0'; });
    }
  }
  return false;
}

bool integer(const ValueType& t, std::string_view s) {
  bool neg = false;
  std::size_t i = 0;
  if (!s.empty() && (s[0] == '+' || s[0] == '-')) {
    neg = s[0] == '-';
    i = 1;
  }
  if (i == s.size()) return false;
  std::uint64_t mag = 0;
  for (; i < s.size(); ++i) {
    if (!digit(s[i])) return false;
    const auto d = static_cast<std::uint64_t>(s[i] - '0');
    if (mag > (UINT64_MAX - d) / 10) return false;
    mag = mag * 10 + d;
  }
  if (neg && mag != 0) {
    if (t.min >= 0) return false;
    const std::uint64_t limit = static_cast<std::uint64_t>(-(t.min + 1)) + 1;  // |min|
    return mag <= limit;
  }
  if (mag > t.max) return false;
  return t.min <= 0 || mag >= static_cast<std::uint64_t>(t.min);
}

}  // namespace

std::string_view trim_xml_space(std::string_view v) {
  while (!v.empty() && is_space(v.front())) v.remove_prefix(1);
  while (!v.empty() && is_space(v.back())) v.remove_suffix(1);
  return v;
}

std::optional<TokenGrammar> token_grammar(std::string_view name) { return xml_token_grammar(name); }

namespace {

// Days from 1970-01-01 of a proleptic Gregorian date (civil calendar).
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

}  // namespace

std::optional<std::string> shift_datetime(std::string_view raw, std::int64_t seconds) {
  const auto s = trim_xml_space(raw);
  std::size_t i = 0;
  if (!(date_part(s, i) && lit(s, i, 'T') && time_part(s, i) && timezone(s, i))) return std::nullopt;
  // YYYY-MM-DDThh:mm:ss[.fff][zone]; a negative or 5-digit year is not shifted.
  if (s.size() < 19 || s[4] != '-' || s[10] != 'T') return std::nullopt;
  const auto num = [&](std::size_t at, std::size_t n) {
    std::int64_t v = 0;
    for (std::size_t k = 0; k < n; ++k) v = v * 10 + (s[at + k] - '0');
    return v;
  };
  const std::int64_t t = days_from_civil(num(0, 4), static_cast<unsigned>(num(5, 2)), static_cast<unsigned>(num(8, 2))) * 86400 +
                         num(11, 2) * 3600 + num(14, 2) * 60 + num(17, 2) + seconds;
  std::int64_t days = t >= 0 ? t / 86400 : (t - 86399) / 86400;
  const std::int64_t sec = t - days * 86400;
  std::int64_t y = 0;
  unsigned m = 0;
  unsigned d = 0;
  civil_from_days(days, y, m, d);
  if (y < 0 || y > 9999) return std::nullopt;
  char buf[64];
  std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02lld:%02lld:%02lld", static_cast<long long>(y), m, d,
                static_cast<long long>(sec / 3600), static_cast<long long>(sec / 60 % 60), static_cast<long long>(sec % 60));
  return std::string(buf) + std::string(s.substr(19));
}

std::string zero_text(std::string_view raw) {
  std::string out(raw);
  const bool hex = std::all_of(raw.begin(), raw.end(), [](char c) { return hexd(c) || is_space(c); });
  for (auto& c : out) {
    if (is_space(c) || c == '=') continue;
    c = hex ? '0' : 'A';
  }
  return out;
}

bool matches(const ValueType& t, std::string_view raw) {
  const auto s = trim_xml_space(raw);
  using K = ValueType::Kind;
  switch (t.kind) {
    case K::boolean: return s == "true" || s == "false" || s == "1" || s == "0";
    case K::enumeration:
    case K::std_uri: return std::find(t.values.begin(), t.values.end(), s) != t.values.end();
    case K::integer: return integer(t, s);
    case K::datetime:
    case K::datetime_shifted: {
      std::size_t i = 0;
      return date_part(s, i) && lit(s, i, 'T') && time_part(s, i) && timezone(s, i);
    }
    case K::date: {
      std::size_t i = 0;
      return date_part(s, i) && timezone(s, i);
    }
    case K::time: {
      std::size_t i = 0;
      return time_part(s, i) && timezone(s, i);
    }
    case K::duration: return duration(s);
    case K::hex:
      return std::find(t.lengths.begin(), t.lengths.end(), s.size()) != t.lengths.end() &&
             std::all_of(s.begin(), s.end(), hexd);
    case K::token: return token(t.grammar, s);
    case K::lang: return lang(s);
    case K::empty: return s.empty();
    case K::base64: {
      // xs:base64Binary: the RFC 4648 §4 alphabet in groups of four, '=' padding only at the end,
      // XML whitespace anywhere (XML Schema Part 2 §3.2.16).
      std::size_t n = 0, pad = 0;
      for (const char c : s) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
                           c == '/';
        if (c == '=') {
          ++pad;
        } else if (!alpha || pad > 0) {
          return false;
        }
        ++n;
      }
      return n > 0 && n % 4 == 0 && pad <= 2;
    }
  }
  return false;
}

}  // namespace mcxanon::xml
