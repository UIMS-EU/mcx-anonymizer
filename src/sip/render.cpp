// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/render.hpp"

#include <array>
#include <cctype>
#include <vector>

namespace mcxanon::sip {
namespace {

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::optional<std::uint32_t> dotted(std::string_view s) {
  std::uint32_t v = 0;
  int parts = 0;
  std::size_t i = 0;
  while (parts < 4) {
    std::size_t j = i;
    unsigned octet = 0;
    while (j < s.size() && j - i < 3 && s[j] >= '0' && s[j] <= '9') {
      octet = octet * 10 + static_cast<unsigned>(s[j] - '0');
      ++j;
    }
    if (j == i || octet > 255) return std::nullopt;
    v = (v << 8) | octet;
    ++parts;
    if (parts < 4) {
      if (j >= s.size() || s[j] != '.') return std::nullopt;
      ++j;
    }
    i = j;
  }
  if (i != s.size()) return std::nullopt;
  return v;
}

std::string hex16(unsigned v, bool pad, bool upper) {
  static constexpr char lo[] = "0123456789abcdef";
  static constexpr char up[] = "0123456789ABCDEF";
  const char* d = upper ? up : lo;
  std::string s;
  for (int shift = 12; shift >= 0; shift -= 4) {
    const unsigned n = (v >> shift) & 0xFu;
    if (s.empty() && n == 0 && shift > 0 && !pad) continue;
    s.push_back(d[n]);
  }
  return s;
}

}  // namespace

std::optional<TextAddress> parse_ipv4_text(std::string_view text) {
  const auto v = dotted(text);
  if (!v) return std::nullopt;
  TextAddress a;
  a.v4 = *v;
  return a;
}

std::optional<TextAddress> parse_ipv6_text(std::string_view text) {
  TextAddress a;
  a.v6 = true;
  if (text.starts_with('[')) {
    if (!text.ends_with(']') || text.size() < 4) return std::nullopt;
    a.bracketed = true;
    text = text.substr(1, text.size() - 2);
  }
  if (text.find(':') == std::string_view::npos) return std::nullopt;
  // RFC 3986 §3.2.2: h16 groups, at most one "::", optionally ending in a dotted IPv4.
  std::vector<unsigned> head, tail;
  bool elided = false;
  bool mixed = false;
  bool letter_seen = false;
  bool all_padded = true;
  std::size_t i = 0;
  if (text.starts_with("::")) {
    elided = true;
    i = 2;
  } else if (text.starts_with(':')) {
    return std::nullopt;
  }
  while (i < text.size()) {
    std::size_t j = i;
    while (j < text.size() && text[j] != ':') ++j;
    const auto group = text.substr(i, j - i);
    if (group.empty()) return std::nullopt;
    auto& out = elided ? tail : head;
    if (group.find('.') != std::string_view::npos) {
      if (j != text.size()) return std::nullopt;  // the IPv4 part must come last
      const auto v4 = dotted(group);
      if (!v4) return std::nullopt;
      out.push_back(*v4 >> 16);
      out.push_back(*v4 & 0xFFFFu);
      mixed = true;
      i = j;
      break;
    }
    if (group.size() > 4) return std::nullopt;
    unsigned v = 0;
    for (char c : group) {
      const int h = hex_value(c);
      if (h < 0) return std::nullopt;
      if (!letter_seen && std::isalpha(static_cast<unsigned char>(c)) != 0) {
        letter_seen = true;
        a.upper = std::isupper(static_cast<unsigned char>(c)) != 0;
      }
      v = (v << 4) | static_cast<unsigned>(h);
    }
    if (group.size() != 4) all_padded = false;
    out.push_back(v);
    if (j == text.size()) {
      i = j;
      break;
    }
    // j points at ':'
    if (j + 1 < text.size() && text[j + 1] == ':') {
      if (elided) return std::nullopt;  // a second "::"
      elided = true;
      i = j + 2;
    } else {
      if (j + 1 == text.size()) return std::nullopt;  // trailing single ':'
      i = j + 1;
    }
  }
  const std::size_t groups = head.size() + tail.size();
  if (elided ? groups > 7 : groups != 8) return std::nullopt;
  std::array<unsigned, 8> g{};
  for (std::size_t k = 0; k < head.size(); ++k) g[k] = head[k];
  for (std::size_t k = 0; k < tail.size(); ++k) g[8 - tail.size() + k] = tail[k];
  for (std::size_t k = 0; k < 8; ++k) {
    a.v6addr[2 * k] = static_cast<std::uint8_t>(g[k] >> 8);
    a.v6addr[2 * k + 1] = static_cast<std::uint8_t>(g[k]);
  }
  a.form = mixed ? TextAddress::Form::mixed
                 : (elided ? TextAddress::Form::compressed : TextAddress::Form::full);
  a.padded = all_padded && !elided && !mixed;
  return a;
}

std::optional<TextAddress> parse_address_text(std::string_view text) {
  if (auto a = parse_ipv4_text(text)) return a;
  return parse_ipv6_text(text);
}

std::string format_address(const TextAddress& a) {
  if (!a.v6) {
    return std::to_string(a.v4 >> 24) + "." + std::to_string((a.v4 >> 16) & 0xFFu) + "." +
           std::to_string((a.v4 >> 8) & 0xFFu) + "." + std::to_string(a.v4 & 0xFFu);
  }
  std::array<unsigned, 8> g{};
  for (std::size_t k = 0; k < 8; ++k) {
    g[k] = (static_cast<unsigned>(a.v6addr[2 * k]) << 8) | a.v6addr[2 * k + 1];
  }
  const std::size_t hex_groups = a.form == TextAddress::Form::mixed ? 6 : 8;
  std::string out;
  if (a.form == TextAddress::Form::full) {
    for (std::size_t k = 0; k < 8; ++k) {
      if (k) out.push_back(':');
      out += hex16(g[k], a.padded, a.upper);
    }
  } else {
    // Longest run of >= 2 zero groups among the hex groups; the first one on a tie.
    std::size_t best = 0, best_len = 0;
    for (std::size_t k = 0; k < hex_groups;) {
      if (g[k] != 0) {
        ++k;
        continue;
      }
      std::size_t e = k;
      while (e < hex_groups && g[e] == 0) ++e;
      if (e - k > best_len) {
        best = k;
        best_len = e - k;
      }
      k = e;
    }
    if (best_len < 2) best_len = 0;
    for (std::size_t k = 0; k < hex_groups;) {
      if (best_len && k == best) {
        out += "::";
        k += best_len;
        continue;
      }
      if (!out.empty() && !out.ends_with(':')) out.push_back(':');
      out += hex16(g[k], false, a.upper);
      ++k;
    }
    if (a.form == TextAddress::Form::mixed) {
      if (!out.ends_with(':')) out.push_back(':');
      out += std::to_string(g[6] >> 8) + "." + std::to_string(g[6] & 0xFFu) + "." +
             std::to_string(g[7] >> 8) + "." + std::to_string(g[7] & 0xFFu);
    }
  }
  return a.bracketed ? "[" + out + "]" : out;
}

Result<std::optional<std::string>> map_address_text(std::string_view text, AddressMapper& mapper) {
  auto a = parse_address_text(text);
  if (!a) return std::optional<std::string>{};
  if (a->v6) {
    auto p = mapper.ipv6(a->v6addr);
    if (!p) return std::unexpected(p.error());
    a->v6addr = *p;
  } else {
    auto p = mapper.ipv4(a->v4);
    if (!p) return std::unexpected(p.error());
    a->v4 = *p;
  }
  return std::optional<std::string>(format_address(*a));
}

Result<std::optional<std::string>> map_port_text(std::string_view text, AddressMapper& mapper,
                                                 bool pseudonymise_ports) {
  if (text.empty() || text.size() > 5) return std::optional<std::string>{};
  unsigned v = 0;
  for (char c : text) {
    if (c < '0' || c > '9') return std::optional<std::string>{};
    v = v * 10 + static_cast<unsigned>(c - '0');
  }
  if (v > 65535) return std::optional<std::string>{};
  if (!pseudonymise_ports) return std::optional<std::string>(std::string(text));
  auto p = mapper.port(static_cast<std::uint16_t>(v));
  if (!p) return std::unexpected(p.error());
  return std::optional<std::string>(std::to_string(*p));
}

}  // namespace mcxanon::sip
