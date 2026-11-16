// SPDX-License-Identifier: GPL-3.0-or-later
//
// Candidate producers: the exact-string matcher for the text
// categories, and the lexical recognisers for host chains, addresses, numbers, telephone
// numbers, IMEIs, location composites and the shapes of unknown pseudonyms.
#include "bytes/base64.hpp"
#include "bytes/hex.hpp"
#include "pseudo/special_addresses.hpp"
#include "pseudo/text_formats.hpp"
#include "reveal/candidate.hpp"
#include "reveal/render.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <string>

namespace mcxanon::reveal {
namespace {

using Text = std::string_view;

unsigned char at(Text t, std::size_t i) { return i < t.size() ? static_cast<unsigned char>(t[i]) : 0; }
unsigned char before(Text t, std::size_t i) { return i > 0 ? static_cast<unsigned char>(t[i - 1]) : 0; }

int hexval(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string hex_nopad(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::uint64_t be_value(ByteView b) {
  std::uint64_t v = 0;
  for (auto x : b) v = (v << 8) | x;
  return v;
}

Bytes be_bytes(std::uint64_t v, std::size_t octets) {
  Bytes b(octets);
  for (std::size_t k = 0; k < octets; ++k) b[octets - 1 - k] = static_cast<std::uint8_t>(v >> (8 * k));
  return b;
}

// A left neighbour that continues a hex token ("a1b2-c3d4", "1.2"): the byte before is '-' or
// '.' and the one before that is a hex digit.
bool hex_continuation_left(Text t, std::size_t i) {
  const auto p = before(t, i);
  return (p == '-' || p == '.') && i >= 2 && is_hex(static_cast<unsigned char>(t[i - 2]));
}
bool hex_continuation_right(Text t, std::size_t j) {
  const auto n = at(t, j);
  return (n == '-' || n == '.' || n == ':') && is_hex(at(t, j + 1));
}

void push(std::vector<Candidate>& out, Candidate&& c) {
  if (!c.hits.empty() || c.shaped) out.push_back(std::move(c));
}

// --- domain chains (R4) -----------------------------------------------------------------

bool d_label(Text t, std::size_t j) {
  if (!((at(t, j) == 'd' || at(t, j) == 'D') && at(t, j + 1) == '-')) return false;
  for (std::size_t k = 0; k < 8; ++k) {
    if (!is_hex(at(t, j + 2 + k))) return false;
  }
  return true;
}

std::vector<std::string> split_dots(std::string_view s) {
  std::vector<std::string> out;
  std::size_t from = 0;
  while (true) {
    const auto dot = s.find('.', from);
    out.emplace_back(s.substr(from, dot == std::string_view::npos ? std::string_view::npos : dot - from));
    if (dot == std::string_view::npos) break;
    from = dot + 1;
  }
  return out;
}

void domain_chain(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  // A wildcard "*." before the first label (a dNSName, RFC 5280 §4.2.1.6) is a boundary too.
  const bool wildcard = p == '.' && i >= 2 && at(t, i - 2) == '*' && (i < 3 || !is_word(at(t, i - 3)));
  if (is_word(p) || p == '-' || (p == '.' && !wildcard)) return;
  if (!d_label(t, i)) return;
  std::vector<std::string> labels;
  std::size_t j = i;
  while (true) {
    labels.push_back(lower(t.substr(j, 10)));
    j += 10;
    if (at(t, j) == '.' && d_label(t, j + 1)) {
      ++j;
      continue;
    }
    break;
  }
  bool invalid = false;
  if (lower(t.substr(j, 8)) == ".invalid") {
    j += 8;
    invalid = true;
  }
  const auto n = at(t, j);
  if (is_word(n) || n == '-') return;
  Candidate c;
  c.start = i;
  c.end = j;
  c.shaped = invalid;
  c.shape_category = Category::domain;
  const std::string matched(t.substr(i, j - i));
  c.forms.push_back(lower(matched));
  const auto first = idx.by_pseudonym(Family::domain, labels[0]);
  for (auto e : first) {
    const std::string orig = as_string(idx.entry(e).original);
    // The following labels must be the pseudonyms of the original's parent suffixes.
    const auto orig_labels = split_dots(orig);
    for (std::size_t k = 1; k < labels.size(); ++k) {
      bool ok = false;
      if (k < orig_labels.size()) {
        std::string suffix;
        for (std::size_t m = k; m < orig_labels.size(); ++m) suffix += (m > k ? "." : "") + orig_labels[m];
        for (auto e2 : idx.by_pseudonym(Family::domain, labels[k])) {
          if (as_string(idx.entry(e2).original) == suffix) ok = true;
        }
      }
      if (!ok) c.inconsistent = true;
    }
    c.hits.push_back(Hit{Category::domain, all_upper(matched) ? upper(orig) : orig});
  }
  push(out, std::move(c));
}

// --- shapes of the tool's text pseudonyms (R9) -----------------------------------------------

struct Shape {
  const char* prefix;
  std::size_t hex;
  Category category;
};
constexpr std::array<Shape, 12> kShapes{{
    {"z9hG4bKb-", 12, Category::branch},
    {"mcxb-", 24, Category::boundary},
    {"ms-", 20, Category::msrp_session},
    {"rt-", 8, Category::reg_token},
    {"cn-", 12, Category::cname},
    {"u-", 8, Category::sip_user},
    {"n-", 8, Category::display_name},
    {"c-", 16, Category::call_id},
    {"t-", 8, Category::tag},
    {"b-", 12, Category::branch},
    {"e-", 12, Category::entity_tag},
    {"i-", 16, Category::charging_id},
}};

void shapes(Text t, std::size_t i, std::vector<Candidate>& out) {
  if (is_word(before(t, i)) || before(t, i) == '-') return;
  for (const auto& s : kShapes) {
    const std::string_view prefix(s.prefix);
    if (t.substr(i, prefix.size()) != prefix) continue;
    std::size_t j = i + prefix.size();
    std::size_t k = 0;
    while (k < s.hex && ((at(t, j) >= '0' && at(t, j) <= '9') || (at(t, j) >= 'a' && at(t, j) <= 'f'))) {
      ++j;
      ++k;
    }
    if (k != s.hex || is_word(at(t, j)) || at(t, j) == '-') continue;
    Candidate c;
    c.start = i;
    c.end = j;
    c.shaped = true;
    c.shape_category = s.category;
    out.push_back(std::move(c));
    return;
  }
}

// --- IPv4 -----------------------------------------------------------------------------------

}  // namespace

bool parse_ipv4(std::string_view t, std::size_t i, std::size_t& j, std::array<std::uint8_t, 4>& a) {
  j = i;
  for (int octet = 0; octet < 4; ++octet) {
    if (octet > 0) {
      if (at(t, j) != '.') return false;
      ++j;
    }
    unsigned v = 0;
    std::size_t d = 0;
    while (d < 3 && is_digit(at(t, j))) {
      v = v * 10 + (at(t, j) - '0');
      ++j;
      ++d;
    }
    if (d == 0 || v > 255 || is_digit(at(t, j))) return false;
    a[static_cast<std::size_t>(octet)] = static_cast<std::uint8_t>(v);
  }
  return true;
}

namespace {

void ipv4(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  if (is_word(p) || p == '.') return;
  std::size_t j = 0;
  std::array<std::uint8_t, 4> a{};
  if (!parse_ipv4(t, i, j, a)) return;
  const auto n = at(t, j);
  if (is_word(n) || (n == '.' && is_digit(at(t, j + 1)))) return;
  Candidate c;
  c.start = i;
  c.end = j;
  char buf[16];
  std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  c.forms.emplace_back(buf);
  for (auto e : idx.by_pseudonym(Family::ipv4, ByteView(a))) {
    const auto& en = idx.entry(e);
    c.hits.push_back(Hit{en.category, text_form(en.category, en.original)});
  }
  const bool broadcast = a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255;
  c.shaped = c.hits.empty() && a[0] >= 240 && !broadcast && n != '/';
  c.shape_category = Category::ipv4;
  push(out, std::move(c));
}

// --- IPv6 -----------------------------------------------------------------------------------

}  // namespace

bool parse_ipv6(std::string_view tok, Ipv6& a, Ipv6Style& st) {
  if (tok.size() < 2) return false;
  std::size_t colons = 0;
  for (char ch : tok) colons += ch == ':' ? 1 : 0;
  if (colons < 2) return false;
  const auto dc = tok.find("::");
  if (dc != Text::npos && tok.find("::", dc + 1) != Text::npos) return false;
  st.compressed = dc != Text::npos;
  st.upper = all_upper(tok);
  std::vector<std::uint16_t> head, tail;
  bool full = true;
  bool dotted = false;
  bool zero_written = false;  // zero groups written out (so the text is not RFC 5952 compressed)
  bool prev_zero = false;
  std::array<std::uint8_t, 4> v4{};
  const auto parse_part = [&](Text part, std::vector<std::uint16_t>& groups, bool last) -> bool {
    if (part.empty()) return true;
    std::size_t from = 0;
    while (from <= part.size()) {
      const auto colon = part.find(':', from);
      const Text g = part.substr(from, colon == Text::npos ? Text::npos : colon - from);
      if (g.empty()) return false;
      if (last && colon == Text::npos && g.find('.') != Text::npos) {
        std::size_t j = 0;
        if (!parse_ipv4(g, 0, j, v4) || j != g.size()) return false;
        dotted = true;
        return true;
      }
      if (g.size() > 4) return false;
      unsigned v = 0;
      for (char ch : g) {
        const int h = hexval(static_cast<unsigned char>(ch));
        if (h < 0) return false;
        v = v * 16 + static_cast<unsigned>(h);
      }
      if (g.size() != 4) full = false;
      // Two zero groups written out next to each other: RFC 5952 would have compressed them.
      if (v == 0 && prev_zero) zero_written = true;
      prev_zero = v == 0;
      groups.push_back(static_cast<std::uint16_t>(v));
      if (colon == Text::npos) break;
      from = colon + 1;
    }
    return true;
  };
  if (st.compressed) {
    if (!parse_part(tok.substr(0, dc), head, false)) return false;
    prev_zero = false;
    if (!parse_part(tok.substr(dc + 2), tail, true)) return false;
  } else {
    if (!parse_part(tok, head, true)) return false;
  }
  const std::size_t words = head.size() + tail.size() + (dotted ? 2 : 0);
  if (st.compressed ? words > 7 : words != 8) return false;
  a.fill(0);
  std::size_t k = 0;
  for (auto g : head) {
    a[k++] = static_cast<std::uint8_t>(g >> 8);
    a[k++] = static_cast<std::uint8_t>(g);
  }
  k = 16 - 2 * tail.size() - (dotted ? 4 : 0);
  for (auto g : tail) {
    a[k++] = static_cast<std::uint8_t>(g >> 8);
    a[k++] = static_cast<std::uint8_t>(g);
  }
  if (dotted) std::copy(v4.begin(), v4.end(), a.begin() + 12);
  st.dotted = dotted;
  st.full = full && dc == Text::npos;
  // Without "::" and without a zero group the text cannot tell whether it was compressed; the
  // RFC 5952 form (what tshark prints) is assumed.
  st.compressed = !st.full && (dc != Text::npos || !zero_written);
  return true;
}

namespace {

void ipv6(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  if (is_word(p) || p == ':' || p == '.') return;
  std::size_t j = i;
  while (j < t.size() && j - i < 64 && (is_hex(at(t, j)) || at(t, j) == ':' || at(t, j) == '.')) ++j;
  // A sentence full stop or a trailing single colon is not part of the address.
  while (j > i && (at(t, j - 1) == '.' || (at(t, j - 1) == ':' && at(t, j - 2) != ':'))) --j;
  if (is_word(at(t, j))) return;
  Ipv6 a{};
  Ipv6Style st;
  const Text tok = t.substr(i, j - i);
  if (!parse_ipv6(tok, a, st)) return;
  Candidate c;
  c.start = i;
  c.end = j;
  Ipv6Style canon;
  canon.compressed = true;
  c.forms.push_back(format_ipv6(a, canon));
  const auto rebuild = [&](std::size_t from, ByteView orig) {
    Ipv6 o = a;
    std::copy(orig.begin(), orig.end(), o.begin() + static_cast<std::ptrdiff_t>(from));
    return format_ipv6(o, st);
  };
  switch (classify_ipv6(a)) {
    case Ipv6Class::keep:
      return;
    case Ipv6Class::solicited_node:
      for (auto e : idx.by_pseudonym(Family::ipv6_sn24, ByteView(a).subspan(13, 3))) {
        c.hits.push_back(Hit{Category::ipv6_sn24, rebuild(13, idx.entry(e).original)});
      }
      break;
    case Ipv6Class::link_local:
      for (auto e : idx.by_pseudonym(Family::ipv6_iid, ByteView(a).subspan(8, 8))) {
        c.hits.push_back(Hit{Category::ipv6_iid_ll, rebuild(8, idx.entry(e).original)});
      }
      break;
    case Ipv6Class::embedded_ipv4:
      for (auto e : idx.by_pseudonym(Family::ipv4, ByteView(a).subspan(12, 4))) {
        c.hits.push_back(Hit{idx.entry(e).category, rebuild(12, idx.entry(e).original)});
      }
      break;
    case Ipv6Class::multicast: {
      std::string k(a.begin() + 2, a.end());
      k += "\x01m";
      for (auto e : idx.by_pseudonym(Family::ipv6, k)) {
        const auto& orig = idx.entry(e).original;
        if (orig.size() == 16) c.hits.push_back(Hit{idx.entry(e).category, rebuild(2, ByteView(orig).subspan(2))});
      }
      break;
    }
    case Ipv6Class::unicast:
      for (auto e : idx.by_pseudonym(Family::ipv6, ByteView(a))) {
        c.hits.push_back(Hit{idx.entry(e).category, rebuild(0, idx.entry(e).original)});
      }
      c.shaped = c.hits.empty() && a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8;
      c.shape_category = Category::ipv6;
      break;
  }
  push(out, std::move(c));
}

// --- MAC ------------------------------------------------------------------------------------

void mac(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  if (is_word(p) || p == ':' || p == '-' || p == '.') return;
  std::array<std::uint8_t, 6> m{};
  char sep = 0;
  std::size_t j = i;
  const auto octet = [&](std::size_t k) -> int {
    const int a = hexval(at(t, k)), b = hexval(at(t, k + 1));
    return a < 0 || b < 0 ? -1 : a * 16 + b;
  };
  if ((at(t, i + 2) == ':' || at(t, i + 2) == '-')) {
    sep = static_cast<char>(at(t, i + 2));
    for (std::size_t k = 0; k < 6; ++k) {
      if (k > 0) {
        if (at(t, j) != static_cast<unsigned char>(sep)) return;
        ++j;
      }
      const int v = octet(j);
      if (v < 0) return;
      m[k] = static_cast<std::uint8_t>(v);
      j += 2;
    }
  } else {
    for (std::size_t k = 0; k < 6; ++k) {
      const int v = octet(j);
      if (v < 0) return;
      m[k] = static_cast<std::uint8_t>(v);
      j += 2;
    }
  }
  if (is_word(at(t, j)) || hex_continuation_right(t, j)) return;
  Candidate c;
  c.start = i;
  c.end = j;
  const bool up = all_upper(t.substr(i, j - i));
  c.forms.push_back(text_form(Category::mac, ByteView(m)));
  std::vector<Bytes> originals;
  for (auto e : idx.by_pseudonym(Family::mac, ByteView(m))) originals.push_back(idx.entry(e).original);
  // Multicast MACs follow the pseudonymised IP group (feature 001): 33:33 + the low 32 bits of an
  // IPv6 group (RFC 2464 §7; a solicited-node group through its ipv6-sn24 mapping), and
  // 01:00:5e + the low 23 bits of an IPv4 group (RFC 1112 §6.4).
  if (m[0] == 0x33 && m[1] == 0x33) {
    if (m[2] == 0xff) {
      for (auto e : idx.by_pseudonym(Family::ipv6_sn24, ByteView(m).subspan(3, 3))) {
        Bytes o(m.begin(), m.end());
        std::copy(idx.entry(e).original.begin(), idx.entry(e).original.end(), o.begin() + 3);
        originals.push_back(std::move(o));
      }
    }
    std::string k(m.begin() + 2, m.end());
    k += "\x01v6m";
    for (auto e : idx.by_pseudonym(Family::ipv6, k)) {
      const auto& g = idx.entry(e).original;
      if (g.size() != 16) continue;
      Bytes o(m.begin(), m.end());
      std::copy(g.begin() + 12, g.end(), o.begin() + 2);
      originals.push_back(std::move(o));
    }
  } else if (m[0] == 0x01 && m[1] == 0x00 && m[2] == 0x5e && (m[3] & 0x80) == 0) {
    std::string k(m.begin() + 3, m.end());
    k += "\x01v4m";
    for (auto e : idx.by_pseudonym(Family::ipv4, k)) {
      const auto& g = idx.entry(e).original;
      if (g.size() != 4) continue;
      Bytes o(m.begin(), m.end());
      o[3] = static_cast<std::uint8_t>(g[1] & 0x7f);
      o[4] = g[2];
      o[5] = g[3];
      originals.push_back(std::move(o));
    }
  }
  for (const auto& o : originals) {
    if (o.size() != 6) continue;
    std::string s;
    char buf[4];
    for (std::size_t k = 0; k < 6; ++k) {
      if (k > 0 && sep) s.push_back(sep);
      std::snprintf(buf, sizeof buf, up ? "%02X" : "%02x", o[k]);
      s += buf;
    }
    c.hits.push_back(Hit{Category::mac, s});
  }
  push(out, std::move(c));
}

// --- numbers ------------------------------------------------------------------------------

struct NumCat {
  Category c;
  unsigned bits;
  std::size_t hex_digits;  // width of a bare hex form
};
constexpr std::array<NumCat, 13> kNumCats{{
    {Category::ssrc, 32, 8},
    {Category::key_id, 32, 8},  // feature 005
    {Category::spi, 32, 8},
    {Category::fc_ref, 32, 8},
    {Category::eci, 28, 7},
    {Category::nci, 36, 9},
    {Category::nr_tac, 24, 6},
    {Category::mbs_fsa, 24, 6},
    {Category::tac, 16, 4},
    {Category::mbms_sai, 16, 4},
    {Category::mbsfn_area, 8, 2},
    {Category::vlan, 12, 0},
    {Category::port_eph, 16, 0},
}};

std::size_t octets_of(const NumCat& n) {
  if (n.c == Category::vlan || n.c == Category::port_eph) return 2;
  return (n.bits + 7) / 8;
}

void add_binary_hits(const Index& idx, std::uint64_t v, bool hex, std::size_t width, bool prefix, bool up,
                     std::string_view prefix_text, Candidate& c) {
  for (const auto& n : kNumCats) {
    if (n.bits < 64 && v >= (std::uint64_t{1} << n.bits)) continue;
    if (hex && !prefix && width != n.hex_digits) continue;
    for (auto e : idx.by_pseudonym(family_of(n.c), be_bytes(v, octets_of(n)))) {
      const auto& en = idx.entry(e);
      const std::uint64_t ov = be_value(en.original);
      c.hits.push_back(
          Hit{en.category, hex ? std::string(prefix_text) + hex_width(ov, width, up) : std::to_string(ov)});
    }
  }
}

void numbers(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  if (is_word(p) || p == '+' || hex_continuation_left(t, i)) return;
  bool prefix = false;
  std::size_t from = i;
  if (at(t, i) == '0' && (at(t, i + 1) == 'x' || at(t, i + 1) == 'X') && is_hex(at(t, i + 2))) {
    prefix = true;
    from = i + 2;
  }
  std::size_t j = from;
  bool letters = false;
  while (j < t.size() && is_hex(at(t, j)) && j - from <= 20) {
    letters = letters || !is_digit(at(t, j));
    ++j;
  }
  const std::size_t width = j - from;
  if (width == 0 || width > 20) return;
  if (is_word(at(t, j)) || hex_continuation_right(t, j)) return;
  Candidate c;
  c.start = i;
  c.end = j;
  const Text run = t.substr(from, width);
  const bool up = all_upper(run);
  if (!prefix && !letters) {
    // Decimal.
    std::uint64_t v = 0;
    bool overflow = false;
    for (char ch : run) {
      if (v > (~std::uint64_t{0} - 9) / 10) overflow = true;
      v = v * 10 + static_cast<std::uint64_t>(ch - '0');
    }
    if (!overflow) {
      c.forms.push_back(std::to_string(v));
      add_binary_hits(idx, v, false, width, false, false, {}, c);
    }
    const std::string digits(run);
    for (auto e : idx.by_pseudonym(Family::tel, digits)) {
      c.hits.push_back(Hit{Category::tel, as_string(idx.entry(e).original)});
    }
    for (auto e : idx.by_pseudonym(Family::sdp_sess, digits)) {
      c.hits.push_back(Hit{Category::sdp_sess, as_string(idx.entry(e).original)});
    }
    if (width == 15 && luhn_digit(digits.substr(0, 14)) == digits[14]) {
      for (auto e : idx.by_pseudonym(Family::imei, digits.substr(0, 14))) {
        const std::string o = as_string(idx.entry(e).original);
        c.hits.push_back(Hit{Category::imei, o + luhn_digit(o)});
      }
    }
  }
  if (prefix || letters || width == 4 || width == 6 || width == 8 || width == 2) {
    if (width <= 16) {
      std::uint64_t v = 0;
      for (char ch : run) v = v * 16 + static_cast<std::uint64_t>(hexval(static_cast<unsigned char>(ch)));
      if (prefix || letters) c.forms.push_back(hex_nopad(v));
      add_binary_hits(idx, v, true, width, prefix, up, prefix ? t.substr(i, 2) : Text{}, c);
    }
  }
  if (!c.hits.empty()) {
    bool all_small = true;
    for (const auto& h : c.hits) {
      all_small = all_small && (small_space(h.category) || (h.category == Category::tel && width <= 6));
    }
    c.small_space = all_small;
  }
  push(out, std::move(c));
}

// --- certificate serial numbers (feature 007) --------------------------------
// The anonymiser writes a serial number as the nonce pseudonym of its octets after a leading zero
// octet, with the sign bit set again, or with the sign bit cleared (a positive, minimal INTEGER,
// RFC 5280 §4.1.2.2; src/tls/x509.cpp). tshark shows it as hex with the leading zero octet
// (x509af.serialNumber). The mapping holds the octets before that adjustment, so each possible
// first octet is looked up.
void serial(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  if (is_word(before(t, i)) || hex_continuation_left(t, i)) return;
  std::size_t from = i;
  if (at(t, i) == '0' && (at(t, i + 1) == 'x' || at(t, i + 1) == 'X') && is_hex(at(t, i + 2))) from = i + 2;
  std::size_t j = from;
  while (j < t.size() && is_hex(at(t, j)) && j - from <= 42) ++j;
  const std::size_t width = j - from;
  // At most 20 octets (RFC 5280 §4.1.2.2) and the leading zero; an even number of digits.
  if (width < 4 || width > 42 || width % 2 != 0) return;
  if (is_word(at(t, j)) || hex_continuation_right(t, j)) return;
  const Text run = t.substr(from, width);
  Bytes b(width / 2);
  for (std::size_t k = 0; k < b.size(); ++k) {
    b[k] = static_cast<std::uint8_t>(hexval(static_cast<unsigned char>(run[2 * k])) * 16 +
                                     hexval(static_cast<unsigned char>(run[2 * k + 1])));
  }
  const bool lead = b[0] == 0;
  Bytes body(b.begin() + (lead ? 1 : 0), b.end());
  std::vector<std::uint8_t> firsts;
  if (lead) {
    if ((body[0] & 0x80) == 0) return;  // DER: a leading zero octet only before a set sign bit
    firsts = {body[0], static_cast<std::uint8_t>(body[0] & 0x7F)};
  } else {
    if ((body[0] & 0x80) != 0) return;  // a negative INTEGER is never written
    firsts = {body[0], static_cast<std::uint8_t>(body[0] | 0x80)};
    if (body[0] == 1 && body.size() > 1) {
      firsts.push_back(0);
      firsts.push_back(0x80);
    }
  }
  const bool up = all_upper(run);
  Candidate c;
  c.start = from;
  c.end = j;
  c.forms.push_back(lower(run));
  std::vector<std::string> seen;
  for (const auto f : firsts) {
    body[0] = f;
    for (auto e : idx.by_pseudonym(family_of(Category::nonce), body)) {
      std::string o = (lead ? std::string("00") : std::string()) + to_hex(idx.entry(e).original, up);
      if (std::find(seen.begin(), seen.end(), o) != seen.end()) continue;
      seen.push_back(o);
      c.hits.push_back(Hit{Category::nonce, std::move(o)});
    }
  }
  push(out, std::move(c));
}

// --- ServerHello randoms with a downgrade sentinel (RFC 8446 §4.1.3; feature 007) ------------
// The anonymiser keeps the last 8 octets ("DOWNGRD" and 0x00 or 0x01) and maps the 24 before them.
void downgrade_random(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  if (is_word(before(t, i)) || hex_continuation_left(t, i)) return;
  std::size_t j = i;
  while (j < t.size() && is_hex(at(t, j)) && j - i <= 64) ++j;
  if (j - i != 64 || is_word(at(t, j)) || hex_continuation_right(t, j)) return;
  const std::string tail = lower(t.substr(i + 48, 16));
  if (tail != "444f574e47524401" && tail != "444f574e47524400") return;
  const Text run = t.substr(i, 48);
  Bytes b(24);
  for (std::size_t k = 0; k < b.size(); ++k) {
    b[k] = static_cast<std::uint8_t>(hexval(static_cast<unsigned char>(run[2 * k])) * 16 +
                                     hexval(static_cast<unsigned char>(run[2 * k + 1])));
  }
  const bool up = all_upper(run);
  Candidate c;
  c.start = i;
  c.end = j;
  c.forms.push_back(lower(t.substr(i, 64)));
  for (auto e : idx.by_pseudonym(family_of(Category::nonce), b)) {
    c.hits.push_back(Hit{Category::nonce, to_hex(idx.entry(e).original, up) + std::string(t.substr(i + 48, 16))});
  }
  push(out, std::move(c));
}

// --- telephone numbers with visual separators (RFC 3966 visual-separator) -----------------

bool visual(unsigned char c) { return c == '-' || c == '.' || c == '(' || c == ')'; }

void telephone(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  const auto p = before(t, i);
  if (is_word(p) || p == '+' || visual(p)) return;
  const bool plus = at(t, i) == '+';
  std::size_t j = plus ? i + 1 : i;
  if (!is_digit(at(t, j))) return;
  bool separators = false;
  std::string digits;
  std::size_t last_digit = j;
  while (j < t.size() && j - i < 64 && (is_digit(at(t, j)) || visual(at(t, j)))) {
    if (is_digit(at(t, j))) {
      digits.push_back(static_cast<char>(at(t, j)));
      last_digit = j;
    } else {
      separators = true;
    }
    ++j;
  }
  j = last_digit + 1;
  if (!plus && !separators) return;  // a plain digit run is a number
  if (digits.size() < 4 || is_word(at(t, j))) return;
  Candidate c;
  c.start = i;
  c.end = j;
  const std::string canon = (plus ? "+" : "") + digits;
  c.forms.push_back(canon);
  c.forms.push_back(digits);
  for (auto e : idx.by_pseudonym(Family::tel, canon)) {
    const std::string orig = as_string(idx.entry(e).original);
    std::string orig_digits;
    for (char ch : orig) {
      if (is_digit(static_cast<unsigned char>(ch))) orig_digits.push_back(ch);
    }
    std::string rendered;
    if (orig_digits.size() == digits.size()) {
      rendered = std::string(t.substr(i, j - i));
      std::size_t k = 0;
      for (auto& ch : rendered) {
        if (is_digit(static_cast<unsigned char>(ch))) ch = orig_digits[k++];
      }
    } else {
      rendered = orig;
    }
    c.hits.push_back(Hit{Category::tel, rendered});
  }
  c.small_space = digits.size() <= 6;
  push(out, std::move(c));
}

// --- location composites (R5): PLMN digits + a bit field ------------------------------------

void location(Text t, std::size_t i, const Index& idx, std::vector<Candidate>& out) {
  if (is_word(before(t, i))) return;
  std::size_t j = i;
  while (j < t.size() && is_digit(at(t, j)) && j - i <= 42) ++j;
  const std::size_t n = j - i;
  if (is_word(at(t, j))) return;
  Category cat;
  if (n == 34) {
    cat = Category::eci;
  } else if (n == 42) {
    cat = Category::nci;
  } else if (n == 22) {
    cat = Category::tac;
  } else {
    return;
  }
  const std::size_t nbits = n - 6;
  std::uint64_t v = 0;
  for (std::size_t k = i + 6; k < j; ++k) {
    if (at(t, k) != '0' && at(t, k) != '1') return;
    v = (v << 1) | (at(t, k) - '0');
  }
  const std::string plmn(t.substr(i, 6));
  const auto plmns = idx.by_pseudonym(Family::plmn, plmn);
  const auto fields = idx.by_pseudonym(family_of(cat), be_bytes(v, (nbits + 7) / 8));
  if (plmns.empty() || fields.empty()) return;
  Candidate c;
  c.start = i;
  c.end = j;
  c.forms.emplace_back(t.substr(i, n));
  for (auto pe : plmns) {
    for (auto fe : fields) {
      const std::uint64_t ov = be_value(idx.entry(fe).original);
      std::string bits;
      for (std::size_t k = nbits; k-- > 0;) bits.push_back(((ov >> k) & 1) ? '1' : '0');
      c.hits.push_back(Hit{cat, as_string(idx.entry(pe).original) + bits});
    }
  }
  push(out, std::move(c));
}

}  // namespace

void exact_candidates(const View& v, std::size_t begin, std::size_t limit, const Index& index,
                      std::vector<Candidate>& out) {
  const auto& m = index.matcher();
  if (m.size() == 0 || v.text.size() < scan::detail::kMinPattern) return;
  const Text t = v.text;
  const std::span<const std::uint8_t> data(reinterpret_cast<const std::uint8_t*>(t.data()), t.size());
  m.scan(data, limit, 0, [&](std::size_t mi, std::uint64_t off) {
    const auto start = static_cast<std::size_t>(off);
    if (start < begin) return;
    const std::size_t end = start + m.length(mi);
    if (end > t.size()) return;
    const auto& info = index.pattern(m.token(mi));
    const Entry& e = index.entry(info.entry);
    if (is_alnum(at(t, start)) && is_word(before(t, start))) return;
    if (is_alnum(at(t, end - 1)) && is_word(at(t, end))) return;
    Candidate c;
    c.start = start;
    c.end = end;
    std::string orig = as_string(e.original);
    if (info.form == PatternForm::hex) {
      orig = to_hex(e.original, all_upper(t.substr(start, end - start)));
    } else if (info.form == PatternForm::base64) {
      orig = base64::encode(e.original);
    }
    // A Call-ID "local@host" is written as c-<hex> "@" <host pseudonym> (feature 002): the
    // mapping holds the whole original, so the host part that follows is part of the match.
    if (e.category == Category::call_id && orig.find('@') != std::string::npos && at(t, end) == '@') {
      std::size_t j = end + 1;
      while (j < t.size() && j - end < 128 &&
             (is_alnum(at(t, j)) || at(t, j) == '.' || at(t, j) == '-' || at(t, j) == ':' || at(t, j) == '[' ||
              at(t, j) == ']')) {
        ++j;
      }
      while (j > end + 1 && (at(t, j - 1) == '.' || at(t, j - 1) == ':')) --j;
      if (j > end + 1) c.end = j;
    }
    const Text matched = t.substr(start, c.end - start);
    c.forms.push_back(lower(matched));
    if ((e.category == Category::uuid || e.category == Category::session_id) && all_upper(matched)) {
      orig = upper(orig);
    }
    c.hits.push_back(Hit{e.category, std::move(orig)});
    out.push_back(std::move(c));
  });
}

void recognised_candidates(const View& v, std::size_t begin, std::size_t limit, const Index& index,
                           std::vector<Candidate>& out) {
  const Text t = v.text;
  for (std::size_t i = begin; i < limit && i < t.size(); ++i) {
    const auto ch = at(t, i);
    const auto p = before(t, i);
    // Every recogniser starts at a byte whose left neighbour is not a word byte; skip the rest
    // quickly.
    if (is_word(p)) continue;
    if (ch == 'd' || ch == 'D') domain_chain(t, i, index, out);
    if (ch == 'u' || ch == 'n' || ch == 'c' || ch == 't' || ch == 'e' || ch == 'i' || ch == 'r' || ch == 'm' ||
        ch == 'b' || ch == 'z') {
      shapes(t, i, out);
    }
    if (is_digit(ch)) {
      ipv4(t, i, index, out);
      location(t, i, index, out);
    }
    if (is_hex(ch) || ch == ':') ipv6(t, i, index, out);
    if (is_hex(ch)) {
      mac(t, i, index, out);
      numbers(t, i, index, out);
      serial(t, i, index, out);
      downgrade_random(t, i, index, out);
    }
    if (ch == '+' || is_digit(ch)) telephone(t, i, index, out);
  }
}

}  // namespace mcxanon::reveal
