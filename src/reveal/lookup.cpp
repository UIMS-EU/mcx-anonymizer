// SPDX-License-Identifier: GPL-3.0-or-later
//
// project lookup (FR-020, FR-021, FR-022, P2): a pseudonym to its original
// through the reveal engine, or an already seen original to its pseudonym. Never issues a
// pseudonym: only the mapping is read.
#include "bytes/base64.hpp"
#include "bytes/hex.hpp"
#include "pseudo/project_impl.hpp"
#include "pseudo/special_addresses.hpp"
#include "pseudo/text_formats.hpp"
#include "reveal/candidate.hpp"
#include "reveal/engine.hpp"
#include "reveal/render.hpp"
#include "reveal/resolve.hpp"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <set>

namespace mcxanon {
namespace reveal {
namespace {

std::string name(Category c) { return std::string(to_string(c)); }

std::string trim(std::string_view v) {
  while (!v.empty() && (v.front() == ' ' || v.front() == '\t' || v.front() == '\r' || v.front() == '\n')) v.remove_prefix(1);
  while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r' || v.back() == '\n')) v.remove_suffix(1);
  return std::string(v);
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

std::vector<Category> text_categories() {
  std::vector<Category> out;
  for (int c = static_cast<int>(Category::sip_user); c <= static_cast<int>(Category::mbs_fsa); ++c) {
    if (is_text(static_cast<Category>(c))) out.push_back(static_cast<Category>(c));
  }
  return out;
}

struct NumCat {
  Category c;
  unsigned bits;
  std::size_t octets;
};
constexpr NumCat kNumCats[] = {
    {Category::ssrc, 32, 4},   {Category::spi, 32, 4},         {Category::fc_ref, 32, 4},
    {Category::eci, 28, 4},    {Category::nci, 36, 5},         {Category::nr_tac, 24, 3},
    {Category::mbs_fsa, 24, 3}, {Category::tac, 16, 2},        {Category::mbms_sai, 16, 2},
    {Category::mbsfn_area, 8, 1}, {Category::vlan, 12, 2},     {Category::port_eph, 16, 2},
};

bool all_digits(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// --- pseudonym -> original -------------------------------------------------------------------

// Feature 005: a key identifier (8 hex digits) and the byte categories nonce and uid (hex, a uid
// also in base64), in either direction.
void key_material(const Index& idx, const std::string& v, bool to_original, std::vector<LookupResult>& out) {
  Bytes b;
  bool from_base64 = false;
  if (auto h = from_hex(v); h && !h->empty()) {
    b = std::move(*h);
  } else if (auto d = base64::decode(v); d && d->bytes.size() == 32) {
    b = std::move(d->bytes);
    from_base64 = true;
  } else {
    return;
  }
  const auto add = [&](Family f, std::string_view cat) {
    const auto hits = to_original ? idx.by_pseudonym(f, ByteView(b)) : idx.by_original(f, ByteView(b));
    for (auto e : hits) {
      const auto& en = idx.entry(e);
      const Bytes& other = to_original ? en.original : en.pseudonym;
      out.push_back({std::string(cat), v, from_base64 ? base64::encode(other) : to_hex(other)});
    }
  };
  if (b.size() == 4 && !from_base64) add(Family::key_id, "key-id");
  if (b.size() == 32) add(Family::uid, "uid");
  if (!from_base64 && b.size() <= 255) add(Family::nonce, "nonce");
}

std::vector<LookupResult> direct_to_original(const Index& idx, const std::string& v) {
  std::vector<LookupResult> out;
  key_material(idx, v, true, out);
  std::set<Family> seen;
  for (auto c : text_categories()) {
    const Family f = family_of(c);
    if (!seen.insert(f).second) continue;
    for (auto e : idx.by_pseudonym(f, folded(c) ? lower(v) : v)) {
      out.push_back({name(idx.entry(e).category), v, as_string(idx.entry(e).original)});
    }
  }
  if (all_digits(v) && v.size() <= 19) {
    const std::uint64_t n = std::stoull(v);
    for (const auto& k : kNumCats) {
      if (k.bits < 64 && n >= (std::uint64_t{1} << k.bits)) continue;
      for (auto e : idx.by_pseudonym(family_of(k.c), be_bytes(n, k.octets))) {
        out.push_back({name(idx.entry(e).category), v, std::to_string(be_value(idx.entry(e).original))});
      }
    }
  }
  std::sort(out.begin(), out.end(), [](const LookupResult& a, const LookupResult& b) {
    return a.category != b.category ? a.category < b.category : a.counterpart < b.counterpart;
  });
  out.erase(std::unique(out.begin(), out.end(),
                        [](const LookupResult& a, const LookupResult& b) {
                          return a.category == b.category && a.counterpart == b.counterpart;
                        }),
            out.end());
  return out;
}

std::vector<LookupResult> engine_to_original(const Index& idx, const std::string& v) {
  const View raw = make_view(v, false);
  std::vector<Candidate> cands;
  exact_candidates(raw, 0, raw.text.size(), idx, cands);
  recognised_candidates(raw, 0, raw.text.size(), idx, cands);
  for (auto& c : cands) {
    c.src_start = c.start;
    c.src_end = c.end;
  }
  RevealOptions o;
  o.replace_ambiguous = true;
  const auto matches = resolve(std::move(cands), v.size(), idx, o);
  std::vector<LookupResult> out;
  std::string composite;
  std::size_t pos = 0, revealed = 0;
  for (const auto& m : matches) {
    if (m.cand.hits.empty()) continue;
    const std::string q = v.substr(m.cand.src_start, m.cand.src_end - m.cand.src_start);
    std::set<std::string> cats;
    for (const auto& h : m.cand.hits) {
      if (cats.insert(name(h.category)).second) out.push_back({name(h.category), q, h.original});
    }
    composite += v.substr(pos, m.cand.src_start - pos) + m.cand.hits.front().original;
    pos = m.cand.src_end;
    ++revealed;
  }
  composite += v.substr(pos);
  if (revealed > 1 || (revealed == 1 && (matches.front().cand.src_start != 0 || matches.front().cand.src_end != v.size()))) {
    out.push_back({"composite", v, composite});
  }
  return out;
}

// --- original -> pseudonym -------------------------------------------------------------------

bool ldh(std::string_view label) {
  return !label.empty() && std::all_of(label.begin(), label.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
  });
}

std::optional<std::string> domain_forward(const Index& idx, std::string_view host) {
  bool absolute = host.size() > 1 && host.back() == '.';
  if (absolute) host.remove_suffix(1);
  const std::string canon = lower(host);
  std::vector<std::string> labels;
  for (std::size_t from = 0;;) {
    const auto dot = canon.find('.', from);
    labels.push_back(canon.substr(from, dot == std::string::npos ? std::string::npos : dot - from));
    if (dot == std::string::npos) break;
    from = dot + 1;
  }
  const bool is_host = std::all_of(labels.begin(), labels.end(), [](const std::string& l) { return ldh(l); });
  std::string out;
  const auto pseudo_of = [&](std::string_view key) -> std::optional<std::string> {
    const auto e = idx.by_original(Family::domain, key);
    if (e.empty()) return std::nullopt;
    return as_string(idx.entry(e.front()).pseudonym);
  };
  if (!is_host || labels.size() == 1) {
    auto p = pseudo_of(canon);
    if (!p) return std::nullopt;
    out = *p;
  } else {
    std::size_t offset = 0;
    for (std::size_t i = 0; i + 1 < labels.size(); ++i) {
      auto p = pseudo_of(std::string_view(canon).substr(offset));
      if (!p) return std::nullopt;
      out += *p + ".";
      offset += labels[i].size() + 1;
    }
    out.pop_back();
  }
  out += ".invalid";
  if (absolute) out.push_back('.');
  return out;
}

std::optional<std::string> tel_forward(const Index& idx, std::string_view number) {
  std::string canon;
  bool plus = false;
  for (char ch : number) {
    if (ch >= '0' && ch <= '9') {
      canon.push_back(ch);
    } else if (ch == '+' && canon.empty()) {
      plus = true;
    } else if (ch != '-' && ch != '.' && ch != '(' && ch != ')' && ch != ' ') {
      return std::nullopt;
    }
  }
  if (canon.size() < 4) return std::nullopt;
  const auto e = idx.by_original(Family::tel, (plus ? "+" : "") + canon);
  if (e.empty()) return std::nullopt;
  const std::string p = as_string(idx.entry(e.front()).pseudonym);
  const std::string_view digits = std::string_view(p).substr(plus ? 1 : 0);
  if (digits.size() != canon.size()) return p;
  std::string out(number);
  std::size_t k = 0;
  for (auto& ch : out) {
    if (ch >= '0' && ch <= '9') ch = digits[k++];
  }
  return out;
}

std::optional<std::string> address_forward(const Index& idx, std::string_view v, std::string& category) {
  std::array<std::uint8_t, 4> a4{};
  std::size_t j = 0;
  if (parse_ipv4(v, 0, j, a4) && j == v.size()) {
    const auto e = idx.by_original(Family::ipv4, ByteView(a4));
    if (e.empty()) return std::nullopt;
    category = name(idx.entry(e.front()).category);
    return text_form(Category::ipv4, idx.entry(e.front()).pseudonym);
  }
  Ipv6 a{};
  Ipv6Style st;
  if (parse_ipv6(v, a, st)) {
    Ipv6 out = a;
    const auto put = [&](Family f, std::size_t from, std::size_t len, Category cat) -> bool {
      const auto e = idx.by_original(f, ByteView(a).subspan(from, len));
      if (e.empty()) return false;
      const auto& p = idx.entry(e.front()).pseudonym;
      std::copy(p.begin(), p.end(), out.begin() + static_cast<std::ptrdiff_t>(from));
      category = name(cat == Category::mac ? idx.entry(e.front()).category : cat);
      return true;
    };
    bool ok = false;
    switch (classify_ipv6(a)) {
      case Ipv6Class::keep: return std::nullopt;
      case Ipv6Class::solicited_node: ok = put(Family::ipv6_sn24, 13, 3, Category::ipv6_sn24); break;
      case Ipv6Class::link_local: ok = put(Family::ipv6_iid, 8, 8, Category::ipv6_iid_ll); break;
      case Ipv6Class::embedded_ipv4: ok = put(Family::ipv4, 12, 4, Category::mac); break;
      case Ipv6Class::multicast: {
        const auto e = idx.by_original(Family::ipv6, ByteView(a));
        if (!e.empty()) {
          const auto& p = idx.entry(e.front()).pseudonym;
          std::copy(p.begin() + 2, p.end(), out.begin() + 2);
          category = name(idx.entry(e.front()).category);
          ok = true;
        }
        break;
      }
      case Ipv6Class::unicast: ok = put(Family::ipv6, 0, 16, Category::mac); break;
    }
    if (!ok) return std::nullopt;
    return format_ipv6(out, st);
  }
  // MAC.
  if (v.size() == 17 && (v[2] == ':' || v[2] == '-')) {
    Bytes m;
    for (std::size_t k = 0; k < 17; k += 3) {
      const auto byte = [&](char c) { return c >= '0' && c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
      if (!is_hex(static_cast<unsigned char>(v[k])) || !is_hex(static_cast<unsigned char>(v[k + 1]))) return std::nullopt;
      m.push_back(static_cast<std::uint8_t>(byte(v[k]) * 16 + byte(v[k + 1])));
    }
    const auto e = idx.by_original(Family::mac, ByteView(m));
    if (e.empty()) return std::nullopt;
    category = "mac";
    std::string out = text_form(Category::mac, idx.entry(e.front()).pseudonym);
    if (v[2] == '-') std::replace(out.begin(), out.end(), ':', '-');
    return out;
  }
  return std::nullopt;
}

bool looks_like_address(std::string_view v) {
  std::array<std::uint8_t, 4> a4{};
  std::size_t j = 0;
  if (parse_ipv4(v, 0, j, a4) && j == v.size()) return true;
  Ipv6 a{};
  Ipv6Style st;
  return parse_ipv6(v, a, st) || (v.size() == 17 && (v[2] == ':' || v[2] == '-'));
}

bool looks_like_host(std::string_view v) {
  return v.find('.') != std::string_view::npos && std::all_of(v.begin(), v.end(), [](char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
         });
}

std::vector<LookupResult> to_pseudonym(const Index& idx, const std::string& v, std::string* unresolved) {
  std::vector<LookupResult> out;
  const auto missing = [&](std::string_view what) {
    if (unresolved) *unresolved = std::string(what);
    return std::vector<LookupResult>{};
  };
  const std::string lv = lower(v);
  {
    std::vector<LookupResult> km;
    key_material(idx, v, false, km);
    if (!km.empty()) return km;
  }
  // URIs: every identity component must resolve (P2).
  for (const std::string_view scheme : {"sips:", "sip:", "tel:"}) {
    if (!lv.starts_with(scheme)) continue;
    const std::string rest = v.substr(scheme.size());
    if (scheme == "tel:") {
      const auto semi = rest.find(';');
      const std::string number = rest.substr(0, semi);
      auto p = tel_forward(idx, number);
      if (!p) return missing(number);
      out.push_back({"tel", number, *p});
      out.push_back({"composite", v, v.substr(0, scheme.size()) + *p + (semi == std::string::npos ? "" : rest.substr(semi))});
      return out;
    }
    const auto at_sign = rest.find('@');
    std::string user, hostpart;
    if (at_sign != std::string::npos) {
      user = rest.substr(0, at_sign);
      hostpart = rest.substr(at_sign + 1);
    } else {
      hostpart = rest;
    }
    const auto end_host = hostpart.find_first_of(";?>");
    std::string params = end_host == std::string::npos ? "" : hostpart.substr(end_host);
    hostpart = hostpart.substr(0, end_host);
    std::string host = hostpart, port;
    if (!host.empty() && host.front() == '[') {
      const auto close = host.find(']');
      if (close == std::string::npos) return missing(host);
      port = host.substr(close + 1);
      host = host.substr(1, close - 1);
    } else if (std::count(host.begin(), host.end(), ':') == 1) {
      port = host.substr(host.find(':'));
      host = host.substr(0, host.find(':'));
    }
    std::string user_p;
    if (!user.empty()) {
      const auto e = idx.by_original(Family::sip_user, user);
      if (!e.empty()) {
        user_p = as_string(idx.entry(e.front()).pseudonym);
        out.push_back({"sip-user", user, user_p});
      } else if (auto t = tel_forward(idx, user)) {
        user_p = *t;
        out.push_back({"tel", user, user_p});
      } else {
        return missing(user);
      }
    }
    std::string host_p, cat;
    if (looks_like_address(host)) {
      auto a = address_forward(idx, host, cat);
      if (!a) return missing(host);
      host_p = *a;
    } else {
      auto d = domain_forward(idx, host);
      if (!d) return missing(host);
      host_p = *d;
      cat = "domain";
    }
    out.push_back({cat, host, host_p});
    const bool bracket = !hostpart.empty() && hostpart.front() == '[';
    const std::string composite = v.substr(0, scheme.size()) + (user.empty() ? "" : user_p + "@") +
                                  (bracket ? "[" + host_p + "]" : host_p) + port + params;
    out.push_back({"composite", v, composite});
    return out;
  }
  std::string cat;
  if (looks_like_address(v)) {
    auto a = address_forward(idx, v, cat);
    if (!a) return missing(v);
    out.push_back({cat, v, *a});
    return out;
  }
  // A telephone number, or a decimal value of a binary category.
  if (!v.empty() && (v[0] == '+' || all_digits(v))) {
    if (auto t = tel_forward(idx, v)) out.push_back({"tel", v, *t});
  }
  if (all_digits(v) && v.size() <= 19) {
    const std::uint64_t n = std::stoull(v);
    for (const auto& k : kNumCats) {
      if (k.bits < 64 && n >= (std::uint64_t{1} << k.bits)) continue;
      for (auto e : idx.by_original(family_of(k.c), be_bytes(n, k.octets))) {
        out.push_back({name(idx.entry(e).category), v, std::to_string(be_value(idx.entry(e).pseudonym))});
      }
    }
    if (v.size() == 14 || v.size() == 15) {
      for (auto e : idx.by_original(Family::imei, v.substr(0, 14))) {
        const std::string p = as_string(idx.entry(e).pseudonym);
        out.push_back({"imei", v, v.size() == 15 ? p + luhn_digit(p) : p});
      }
    }
  }
  // Text categories (exact; lower case for the folded ones).
  std::set<Family> seen;
  for (auto c : text_categories()) {
    const Family f = family_of(c);
    if (f == Family::domain || f == Family::tel || f == Family::imei || !seen.insert(f).second) continue;
    for (auto e : idx.by_original(f, folded(c) ? lv : v)) {
      out.push_back({name(idx.entry(e).category), v, as_string(idx.entry(e).pseudonym)});
    }
  }
  if (looks_like_host(v) || out.empty()) {
    if (auto d = domain_forward(idx, v)) out.push_back({"domain", v, *d});
  }
  if (out.empty()) return missing(v);
  return out;
}

}  // namespace

Result<std::vector<LookupResult>> lookup_mapping(const Mapping& mapping, std::string_view value,
                                                 LookupDirection direction, std::string* unresolved) {
  try {
    auto idx = Index::build(mapping);
    if (!idx) return std::unexpected(idx.error());
    return lookup_index(*idx, value, direction, unresolved);
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

Result<std::vector<LookupResult>> lookup_index(const Index& index, std::string_view value,
                                               LookupDirection direction, std::string* unresolved) {
  try {
    const std::string v = trim(value);
    if (v.empty()) return std::vector<LookupResult>{};
    if (direction == LookupDirection::to_pseudonym) return to_pseudonym(index, v, unresolved);
    auto direct = direct_to_original(index, v);
    if (!direct.empty()) return direct;
    return engine_to_original(index, v);
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

}  // namespace reveal

Result<std::vector<LookupResult>> lookup(const Project& project, std::string_view value, LookupDirection direction,
                                         std::string* unresolved) {
  return reveal::lookup_mapping(project.impl().mapping, value, direction, unresolved);
}

}  // namespace mcxanon
