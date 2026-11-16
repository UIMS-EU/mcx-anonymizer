// SPDX-License-Identifier: GPL-3.0-or-later
#include "reveal/candidate.hpp"

#include <array>
#include <cstring>

namespace mcxanon::reveal {
namespace {

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Length of the escape at s[i] and its value, or 0.
std::size_t escape_at(std::string_view s, std::size_t i, unsigned char& value, Escape& kind) {
  if (s[i] == '%') {
    if (i + 2 >= s.size()) return 0;
    const int a = hexval(s[i + 1]), b = hexval(s[i + 2]);
    if (a >= 0 && b >= 0) {
      value = static_cast<unsigned char>(a * 16 + b);
      kind = Escape::percent;
      return 3;
    }
    return 0;
  }
  if (s[i] != '&') return 0;
  static constexpr std::array<std::pair<const char*, char>, 5> kNamed{
      {{"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}}};
  for (const auto& [name, ch] : kNamed) {
    const std::size_t n = std::strlen(name);
    if (s.substr(i, n) == name) {
      value = static_cast<unsigned char>(ch);
      kind = Escape::xml;
      return n;
    }
  }
  if (i + 3 < s.size() && s[i + 1] == '#') {
    std::size_t j = i + 2;
    const bool hex = s[j] == 'x' || s[j] == 'X';
    if (hex) ++j;
    unsigned v = 0;
    std::size_t digits = 0;
    while (j < s.size() && digits < 6) {
      const int d = hex ? hexval(s[j]) : (s[j] >= '0' && s[j] <= '9' ? s[j] - '0' : -1);
      if (d < 0) break;
      v = v * (hex ? 16u : 10u) + static_cast<unsigned>(d);
      ++j;
      ++digits;
    }
    if (digits > 0 && j < s.size() && s[j] == ';' && v > 0 && v < 0x80) {
      value = static_cast<unsigned char>(v);
      kind = Escape::xml;
      return j + 1 - i;
    }
  }
  return 0;
}

}  // namespace

bool has_escapes(std::string_view s) {
  unsigned char v = 0;
  Escape k = Escape::none;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if ((s[i] == '%' || s[i] == '&') && escape_at(s, i, v, k) > 0) return true;
  }
  return false;
}

View make_view(std::string_view source, bool decode) {
  View v;
  v.text.reserve(source.size());
  v.src.reserve(source.size() + 1);
  v.esc.reserve(source.size());
  for (std::size_t i = 0; i < source.size();) {
    unsigned char value = 0;
    Escape kind = Escape::none;
    const std::size_t n = (decode && (source[i] == '%' || source[i] == '&')) ? escape_at(source, i, value, kind) : 0;
    v.src.push_back(static_cast<std::uint32_t>(i));
    if (n > 0) {
      v.text.push_back(static_cast<char>(value));
      v.esc.push_back(kind);
      v.any_escape = true;
      i += n;
    } else {
      v.text.push_back(source[i]);
      v.esc.push_back(Escape::none);
      ++i;
    }
  }
  v.src.push_back(static_cast<std::uint32_t>(source.size()));
  return v;
}

}  // namespace mcxanon::reveal
