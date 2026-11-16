// SPDX-License-Identifier: GPL-3.0-or-later
#include "reveal/render.hpp"

#include <cstdio>

namespace mcxanon::reveal {

std::string format_ipv6(ByteView a, const Ipv6Style& st) {
  if (a.size() != 16) return {};
  const auto group = [&](std::size_t g) { return static_cast<unsigned>((a[2 * g] << 8) | a[2 * g + 1]); };
  const std::size_t groups = st.dotted ? 6 : 8;
  std::size_t best = groups, best_len = 0;
  if (st.compressed) {
    for (std::size_t i = 0; i < groups;) {
      if (group(i) == 0) {
        std::size_t j = i;
        while (j < groups && group(j) == 0) ++j;
        if (j - i > best_len && (j - i >= 2 || st.dotted)) {
          best = i;
          best_len = j - i;
        }
        i = j;
      } else {
        ++i;
      }
    }
  }
  std::string out;
  char buf[16];
  const char* fmt = st.full ? (st.upper ? "%04X" : "%04x") : (st.upper ? "%X" : "%x");
  for (std::size_t i = 0; i < groups; ++i) {
    if (i == best) {
      out += "::";
      i += best_len - 1;
      continue;
    }
    if (!out.empty() && out.back() != ':') out.push_back(':');
    std::snprintf(buf, sizeof buf, fmt, group(i));
    out += buf;
  }
  if (st.dotted) {
    if (!out.empty() && out.back() != ':') out.push_back(':');
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
    out += buf;
  }
  return out;
}

bool all_upper(std::string_view s) {
  bool up = false;
  for (char c : s) {
    if (c >= 'a' && c <= 'z') return false;
    if (c >= 'A' && c <= 'Z') up = true;
  }
  return up;
}

std::string upper(std::string_view s) {
  std::string o(s);
  for (auto& c : o) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return o;
}

std::string hex_width(std::uint64_t v, std::size_t width, bool upper_case) {
  char buf[32];
  std::snprintf(buf, sizeof buf, upper_case ? "%0*llX" : "%0*llx", static_cast<int>(width),
                static_cast<unsigned long long>(v));
  return buf;
}

namespace {
bool unreserved(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
         c == '_' || c == '~';
}
}  // namespace

std::string encode_like(std::string_view original, const EscapeStyle& st) {
  if (st.scheme == Escape::none) return std::string(original);
  std::string out;
  char buf[8];
  for (char ch : original) {
    const auto c = static_cast<unsigned char>(ch);
    if (!st.escaped[c].empty()) {
      out += st.escaped[c];
    } else if (st.scheme == Escape::percent && !unreserved(c)) {
      std::snprintf(buf, sizeof buf, st.lower_hex ? "%%%02x" : "%%%02X", c);
      out += buf;
    } else if (st.scheme == Escape::xml && c == '&') {
      out += "&amp;";
    } else if (st.scheme == Escape::xml && c == '<') {
      out += "&lt;";
    } else if (st.scheme == Escape::xml && c == '>') {
      out += "&gt;";
    } else if (st.scheme == Escape::xml && c == '"') {
      out += "&quot;";
    } else if (st.scheme == Escape::xml && c == '\'') {
      out += "&apos;";
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

}  // namespace mcxanon::reveal
