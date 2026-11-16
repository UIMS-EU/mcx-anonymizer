// SPDX-License-Identifier: GPL-3.0-or-later
#include "reveal/index.hpp"

#include "bytes/base64.hpp"

#include "bytes/hex.hpp"
#include "reveal/render.hpp"

#include <algorithm>
#include <cstdio>

namespace mcxanon::reveal {

bool is_text(Category c) {
  return static_cast<int>(c) >= static_cast<int>(Category::sip_user) && !is_binary_category(c) &&
         !is_byte_category(c);
}

bool exact_searchable(Category c) {
  if (is_byte_category(c)) return true;  // feature 005: searched as hex (uid also as base64)
  if (!is_text(c)) return false;
  switch (c) {
    case Category::domain:    // domain chains
    case Category::tel:       // digit strings with visual separators
    case Category::imei:      // 15 digits with the check digit
    case Category::sdp_sess:  // digit strings
      return false;
    default:
      return true;
  }
}

bool folded(Category c) {
  switch (c) {
    case Category::domain:
    case Category::call_id:
    case Category::tag:
    case Category::branch:
    case Category::entity_tag:
    case Category::charging_id:
    case Category::session_id:
    case Category::boundary:
    case Category::msrp_session:
    case Category::reg_token:
    case Category::cname:
    case Category::uuid:
      return true;
    default:
      return false;
  }
}

bool small_space(Category c) {
  switch (c) {
    case Category::vlan:
    case Category::port_eph:
    case Category::tac:
    case Category::nr_tac:
    case Category::mbsfn_area:
    case Category::mbms_sai:
    case Category::mbs_fsa:
      return true;
    default:
      return false;
  }
}

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return o;
}

std::string as_string(ByteView b) { return std::string(b.begin(), b.end()); }

namespace {

std::uint64_t be_value(ByteView b) {
  std::uint64_t v = 0;
  for (auto x : b) v = (v << 8) | x;
  return v;
}

std::string hex_nopad(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

}  // namespace

std::string text_form(Category c, ByteView b) {
  if (is_text(c)) return as_string(b);
  if (c == Category::key_id && b.size() == 4) return to_hex(b);
  if (is_byte_category(c)) return to_hex(b);
  if (is_binary_category(c) || c == Category::vlan || c == Category::port_eph) {
    return std::to_string(be_value(b));
  }
  if ((c == Category::ipv4 || c == Category::ipv4_pp || c == Category::ipv4_mcast) && b.size() == 4) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
  }
  if (c == Category::mac && b.size() == 6) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return buf;
  }
  if (b.size() == 16) {
    Ipv6Style st;
    st.compressed = true;
    return format_ipv6(b, st);
  }
  return to_hex(b);
}

std::vector<std::string> original_forms(const Entry& e) {
  std::vector<std::string> out;
  const Category c = e.category;
  if (is_text(c)) {
    out.push_back(lower(as_string(e.original)));
    if (c == Category::tel && !e.original.empty() && e.original[0] == '+') {
      out.push_back(as_string(ByteView(e.original).subspan(1)));
    }
    return out;
  }
  if (c == Category::key_id) {
    out.push_back(to_hex(e.original));  // 8 hex digits (feature 005)
    return out;
  }
  if (is_binary_category(c) || c == Category::vlan || c == Category::port_eph) {
    const auto v = be_value(e.original);
    out.push_back(std::to_string(v));
    out.push_back(hex_nopad(v));
    return out;
  }
  if (is_byte_category(c)) {
    out.push_back(to_hex(e.original));
    if (c == Category::uid) out.push_back(lower(base64::encode(e.original)));
    return out;
  }
  out.push_back(lower(text_form(c, e.original)));
  return out;
}

std::string Index::key(Family f, ByteView b) {
  std::string k;
  k.reserve(b.size() + 1);
  k.push_back(static_cast<char>(f));
  k.append(b.begin(), b.end());
  return k;
}

namespace {
const std::vector<std::uint32_t> kNone;

std::span<const std::uint32_t> find_in(const std::unordered_map<std::string, std::vector<std::uint32_t>>& m,
                                       const std::string& k) {
  const auto it = m.find(k);
  if (it == m.end()) return kNone;
  return it->second;
}
}  // namespace

std::span<const std::uint32_t> Index::by_pseudonym(Family f, ByteView key_bytes) const {
  return find_in(by_pseudonym_, key(f, key_bytes));
}
std::span<const std::uint32_t> Index::by_original(Family f, ByteView key_bytes) const {
  return find_in(by_original_, key(f, key_bytes));
}
std::span<const std::uint32_t> Index::by_pseudonym(Family f, std::string_view k) const {
  return by_pseudonym(f, ByteView(reinterpret_cast<const std::uint8_t*>(k.data()), k.size()));
}
std::span<const std::uint32_t> Index::by_original(Family f, std::string_view k) const {
  return by_original(f, ByteView(reinterpret_cast<const std::uint8_t*>(k.data()), k.size()));
}

bool Index::is_original_form(std::string_view normalised) const {
  return original_forms_.contains(std::string(normalised));
}

Result<Index> Index::build(const Mapping& mapping) {
  Index idx;
  idx.entries_.reserve(mapping.size());
  for (const auto& [k, e] : mapping.entries()) {
    idx.entries_.push_back(Entry{e.category, e.original, e.pseudonym});
  }
  std::vector<scan::detail::Pattern> patterns;
  std::size_t pattern_bytes = 0;
  for (std::uint32_t i = 0; i < idx.entries_.size(); ++i) {
    const Entry& e = idx.entries_[i];
    const Family f = family_of(e.category);
    const bool fold = folded(e.category);
    const std::string ptext = fold ? lower(as_string(e.pseudonym)) : std::string();
    const ByteView pkey = fold ? ByteView(reinterpret_cast<const std::uint8_t*>(ptext.data()), ptext.size())
                               : ByteView(e.pseudonym);
    idx.by_pseudonym_[key(f, pkey)].push_back(i);
    // An IPv6 multicast group keeps the flags and scope of the original: index the group ID too,
    // and its low 32 bits, which the Ethernet multicast MAC carries (RFC 2464 §7).
    if (f == Family::ipv6 && e.pseudonym.size() == 16) {
      idx.by_pseudonym_[key(f, ByteView(e.pseudonym).subspan(2)) + "\x01m"].push_back(i);
      if (!e.original.empty() && e.original[0] == 0xff) {
        idx.by_pseudonym_[key(f, ByteView(e.pseudonym).subspan(12)) + "\x01v6m"].push_back(i);
      }
    }
    // An IPv4 multicast group: the low 23 bits, which its Ethernet MAC carries (RFC 1112 §6.4).
    if (e.category == Category::ipv4_mcast && e.pseudonym.size() == 4) {
      const Bytes low{static_cast<std::uint8_t>(e.pseudonym[1] & 0x7f), e.pseudonym[2], e.pseudonym[3]};
      idx.by_pseudonym_[key(f, low) + "\x01v4m"].push_back(i);
    }
    const std::string otext = fold ? lower(as_string(e.original)) : std::string();
    const ByteView okey = fold ? ByteView(reinterpret_cast<const std::uint8_t*>(otext.data()), otext.size())
                               : ByteView(e.original);
    idx.by_original_[key(f, okey)].push_back(i);
    for (auto& form : original_forms(e)) idx.original_forms_.insert(std::move(form));

    const std::string shown = text_form(e.category, e.pseudonym);
    if (shown.size() <= 3) {
      ++idx.not_searchable_;
      continue;
    }
    if (!exact_searchable(e.category)) continue;
    if (is_byte_category(e.category)) {
      // Feature 005: hex in either case; a uid also in base64 (case kept).
      const auto add = [&](const std::string& text, bool fold_it, PatternForm form) {
        scan::detail::Pattern q;
        q.bytes.assign(text.begin(), text.end());
        q.fold = fold_it;
        q.token = static_cast<std::uint32_t>(idx.patterns_.size());
        idx.patterns_.push_back(PatternInfo{i, Escape::none, form});
        idx.max_pattern_ = std::max(idx.max_pattern_, text.size());
        pattern_bytes += text.size();
        patterns.push_back(std::move(q));
      };
      add(shown, true, PatternForm::hex);
      if (e.category == Category::uid) add(base64::encode(e.pseudonym), false, PatternForm::base64);
      continue;
    }
    scan::detail::Pattern p;
    const std::string bytes = fold ? lower(shown) : shown;
    p.bytes.assign(bytes.begin(), bytes.end());
    p.fold = fold;
    p.token = static_cast<std::uint32_t>(idx.patterns_.size());
    idx.patterns_.push_back(PatternInfo{i, Escape::none});
    idx.max_pattern_ = std::max(idx.max_pattern_, bytes.size());
    pattern_bytes += bytes.size();
    patterns.push_back(std::move(p));
  }
  std::size_t folded_count = 0;
  for (const auto& p : patterns) folded_count += p.fold ? 1 : 0;
  idx.matcher_.reserve(patterns.size() - folded_count, folded_count, pattern_bytes);
  for (const auto& p : patterns) idx.matcher_.add(p);
  idx.matcher_.seal();
  return idx;
}

}  // namespace mcxanon::reveal
