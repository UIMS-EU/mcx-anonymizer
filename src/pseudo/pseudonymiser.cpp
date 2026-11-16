// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/pseudonymiser.hpp"

#include "pseudo/prefix_preserving.hpp"
#include "pseudo/special_addresses.hpp"
#include "pseudo/text_formats.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace mcxanon {
namespace {

Bytes be32_bytes(std::uint32_t v) {
  return {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16),
          static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
}
std::uint32_t from_be32(ByteView b) {
  return (static_cast<std::uint32_t>(b[0]) << 24) | (static_cast<std::uint32_t>(b[1]) << 16) |
         (static_cast<std::uint32_t>(b[2]) << 8) | b[3];
}

constexpr std::uint32_t kMaxCounter = 1u << 20;

// The counter value that keys the o= sess-version offset in the sdp-sess HMAC domain. Session
// id pseudonyms use counters 0 .. kMaxCounter - 1, so the two never share a derivation.
constexpr std::uint32_t kSdpVersionCounter = 0xFFFFFFFFu;

std::string_view as_text(ByteView b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}
Bytes as_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

bool is_digit(char c) { return c >= '0' && c <= '9'; }

std::string lower(std::string_view s) {
  std::string out(s);
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

// A label of an RFC 3261 §25.1 hostname (letters, digits, hyphens). Underscores are accepted
// too, and a label is at most 63 characters; anything else is not a host name and is treated
// as one opaque label (a Digest realm).
bool is_ldh_label(std::string_view l) {
  if (l.empty() || l.size() > 63) return false;
  return std::all_of(l.begin(), l.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_';
  });
}

std::vector<std::string_view> split_labels(std::string_view name) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  for (;;) {
    const auto dot = name.find('.', start);
    out.push_back(name.substr(start, dot == std::string_view::npos ? dot : dot - start));
    if (dot == std::string_view::npos) break;
    start = dot + 1;
  }
  return out;
}

}  // namespace

Pseudonymiser::Pseudonymiser(const Secret& secret, Mapping& mapping, PseudonymiserOptions options)
    : secret_(secret), mapping_(mapping), options_(options) {}

Result<Bytes> Pseudonymiser::candidate(Category c, ByteView original, std::uint32_t counter,
                                       bool& excluded) const {
  excluded = false;
  const Digest32 d = derive(secret_, to_string(c), original, counter);
  switch (c) {
    case Category::mac: {
      const Mac m = place_mac(d, original[0]);
      return Bytes(m.begin(), m.end());
    }
    case Category::ipv4_pp: {
      const std::uint32_t v = pp_ipv4(secret_, from_be32(original));
      if (v == 0xFFFFFFFFu) {
        excluded = true;
        return Bytes{};
      }
      return be32_bytes(v);
    }
    case Category::ipv6_pp: {
      Ipv6 in{};
      std::copy(original.begin(), original.end(), in.begin());
      const Ipv6 a = pp_ipv6(secret_, in);
      return Bytes(a.begin(), a.end());
    }
    case Category::ipv4: {
      const auto v = place_ipv4(d);
      if (!v) {
        excluded = true;
        return Bytes{};
      }
      return be32_bytes(*v);
    }
    case Category::ipv4_mcast:
      return be32_bytes(place_ipv4_mcast(d));
    case Category::ipv6: {
      const Ipv6 a = place_ipv6(d);
      return Bytes(a.begin(), a.end());
    }
    case Category::ipv6_iid_ll: {
      const auto iid = place_iid(d);
      if (!iid) {
        excluded = true;
        return Bytes{};
      }
      return Bytes(iid->begin(), iid->end());
    }
    case Category::ipv6_sn24: {
      const auto sn = place_sn24(d);
      return Bytes(sn.begin(), sn.end());
    }
    case Category::vlan: {
      const auto v = place_vlan(d);
      return Bytes{static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
    }
    case Category::port_eph: {
      const auto p = place_port(d, options_.ephemeral_lo, options_.ephemeral_hi);
      return Bytes{static_cast<std::uint8_t>(p >> 8), static_cast<std::uint8_t>(p)};
    }
    default:
      break;
  }
  // Text and numeric categories.
  const std::string_view orig = as_text(original);
  DigestStream st(d);
  switch (c) {
    case Category::sip_user: return as_bytes(render_hex("u-", st, 8));
    case Category::domain: return as_bytes(render_hex("d-", st, 8));
    case Category::display_name: return as_bytes(render_hex("n-", st, 8));
    case Category::call_id: return as_bytes(render_hex("c-", st, 16));
    case Category::tag: return as_bytes(render_hex("t-", st, 8));
    case Category::branch:
      // The RFC 3261 §8.1.1.7 magic cookie is kept when the original has it.
      return as_bytes(render_hex(orig.starts_with("z9hG4bK") ? "z9hG4bKb-" : "b-", st, 12));
    case Category::entity_tag: return as_bytes(render_hex("e-", st, 12));
    case Category::charging_id: return as_bytes(render_hex("i-", st, 16));
    case Category::session_id: return as_bytes(render_hex("", st, 32));
    case Category::boundary: return as_bytes(render_hex("mcxb-", st, 24));
    case Category::msrp_session: return as_bytes(render_hex("ms-", st, 20));
    case Category::reg_token: return as_bytes(render_hex("rt-", st, 8));
    case Category::cname: return as_bytes(render_hex("cn-", st, 12));
    case Category::uuid: return as_bytes(render_uuid_v4(st));
    case Category::imei: return as_bytes(render_digits(st, orig.size(), false));
    case Category::sdp_sess:
      return as_bytes(render_digits(st, orig.size(), !orig.empty() && orig[0] != '0'));
    case Category::tel: {
      const bool plus = orig.starts_with('+');
      const std::string digits = render_digits(st, orig.size() - (plus ? 1 : 0), false);
      return as_bytes((plus ? "+" : "") + digits);
    }
    case Category::digest:
    case Category::cell_id:
      return as_bytes(render_like(orig, st));
    case Category::spi: {
      const std::uint32_t v = (static_cast<std::uint32_t>(st.byte()) << 24) |
                              (static_cast<std::uint32_t>(st.byte()) << 16) |
                              (static_cast<std::uint32_t>(st.byte()) << 8) | st.byte();
      if (v < 256) {  // RFC 4303 §2.1: SPI values 1 to 255 are reserved (0 is not used)
        excluded = true;
        return Bytes{};
      }
      return be32_bytes(v);
    }
    case Category::ssrc:
    case Category::fc_ref:
    case Category::eci:
    case Category::tac:
    case Category::mbms_sai:
    case Category::mbsfn_area:
    case Category::nr_tac:
    case Category::mbs_fsa: {
      // A uniform value of the category's width, big-endian in the original's octet count.
      const unsigned bits = binary_bits(c);
      std::uint32_t v = (static_cast<std::uint32_t>(st.byte()) << 24) |
                        (static_cast<std::uint32_t>(st.byte()) << 16) |
                        (static_cast<std::uint32_t>(st.byte()) << 8) | st.byte();
      if (bits < 32) v &= (std::uint32_t{1} << bits) - 1;
      Bytes out = be32_bytes(v);
      out.erase(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(4 - original.size()));
      return out;
    }
    case Category::key_id: {
      // The purpose tag (4 most significant bits, TS 33.180 Annex G) is kept; 28 bits are drawn.
      if (original.size() != 4) return fail(ErrorCode::internal, "a key identifier has 4 octets");
      std::uint32_t v = (static_cast<std::uint32_t>(st.byte()) << 24) |
                        (static_cast<std::uint32_t>(st.byte()) << 16) |
                        (static_cast<std::uint32_t>(st.byte()) << 8) | st.byte();
      v = (static_cast<std::uint32_t>(original[0] & 0xF0u) << 24) | (v & 0x0FFFFFFFu);
      return be32_bytes(v);
    }
    case Category::nonce:
    case Category::uid: {
      Bytes out(original.size());
      for (auto& x : out) x = st.byte();
      return out;
    }
    case Category::nci: {
      // 36 bits in 5 octets (feature 003).
      std::uint64_t v = 0;
      for (int k = 0; k < 5; ++k) v = (v << 8) | st.byte();
      v &= (std::uint64_t{1} << 36) - 1;
      Bytes out;
      for (int k = 4; k >= 0; --k) out.push_back(static_cast<std::uint8_t>(v >> (8 * k)));
      return out;
    }
    case Category::opaque:
      // Length and character classes kept.
      return as_bytes(render_like(orig, st));
    case Category::plmn:
    case Category::msrp_tid:
    case Category::msrp_msgid:
      // Digits stay digits (PLMN BCD stays valid); ident characters keep their class, so a
      // leading ALPHANUM stays ALPHANUM (RFC 4975 §9).
      return as_bytes(render_like(orig, st));
    default:
      break;
  }
  return fail(ErrorCode::internal, "unknown category");
}

Result<Bytes> Pseudonymiser::assign(Category c, ByteView original) {
  if (const auto* e = mapping_.find(c, original)) {
    auto key = std::make_pair(c, Bytes(original.begin(), original.end()));
    if (!used_.contains(key)) {
      used_[key] = true;
      ++stats_.reused_entries[std::string(to_string(c))];
    }
    return e->pseudonym;
  }
  // FR-025: an original equal to an issued pseudonym makes the output ambiguous.
  // VLAN IDs and ports share one small value space with their pseudonyms by
  // design and are not scan tokens, so the rule applies to addresses only.
  // Values shorter than the scanner's 4-byte minimum (1- to 3-digit SDP session ids, short digest
  // or cell-id values, short opaque values such as GKTP ids "k1") are no scan tokens either, and
  // their value space is small, so a later original equal to an issued pseudonym is likely and
  // harmless (feature 002).
  const bool small_space = c == Category::vlan || c == Category::port_eph || c == Category::tac ||
                           c == Category::mbms_sai || c == Category::mbsfn_area ||
                           c == Category::nr_tac || c == Category::mbs_fsa ||
                           ((c == Category::sdp_sess || c == Category::digest || c == Category::cell_id ||
                             c == Category::opaque) &&
                            original.size() < 4);
  if (!small_space && mapping_.is_issued_pseudonym(c, original)) {
    return fail(ErrorCode::collision,
                std::string("an original ") + std::string(to_string(c)) +
                    " value equals a pseudonym already issued in this project; the output "
                    "would be ambiguous (use a new project for this capture)");
  }
  // Class-keeping text categories (render_like) change only ASCII letters and digits: without
  // any, every candidate is the original itself, and with few the candidates repeat. Fail at once,
  // or after a bounded number of draws, instead of drawing kMaxCounter candidates (feature 007,
  // the outcome is the same error as before).
  const bool shaped = c == Category::opaque || c == Category::plmn || c == Category::msrp_tid ||
                      c == Category::msrp_msgid;
  if (shaped && std::none_of(original.begin(), original.end(), [](std::uint8_t b) {
        return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
      })) {
    return fail(ErrorCode::internal, "pseudonym range exhausted for " + std::string(to_string(c)));
  }
  const std::uint32_t max_counter = shaped ? 4096u : kMaxCounter;
  for (std::uint32_t counter = 0; counter < max_counter; ++counter) {
    bool excluded = false;
    auto cand = candidate(c, original, counter, excluded);
    if (!cand) return std::unexpected(cand.error());
    const bool pp = c == Category::ipv4_pp || c == Category::ipv6_pp;
    const bool taken = !excluded && (mapping_.pseudonym_taken(c, *cand) ||
                                     (!small_space && (mapping_.is_known_original(c, *cand) ||
                                                       mapping_.is_issued_pseudonym(c, *cand))));
    if (pp && (excluded || taken)) {
      // A prefix-preserving pseudonym cannot be re-drawn without breaking the prefix
      // structure.
      return fail(ErrorCode::collision,
                  "prefix-preserving pseudonym collision; run without --prefix-preserving or use a new project");
    }
    if (excluded) continue;
    if (taken) {
      ++stats_.collisions_resolved;
      continue;
    }
    if (Bytes(original.begin(), original.end()) == *cand) {
      continue;  // never map a value onto itself
    }
    auto ins = mapping_.insert(MappingEntry{c, Bytes(original.begin(), original.end()), *cand,
                                            counter, 0});
    if (!ins) return std::unexpected(ins.error());
    used_[{c, Bytes(original.begin(), original.end())}] = true;
    ++stats_.new_entries[std::string(to_string(c))];
    return *cand;
  }
  return fail(ErrorCode::internal, "pseudonym range exhausted for " + std::string(to_string(c)));
}

Result<Mac> Pseudonymiser::mac(const Mac& original) {
  // Group (multicast/broadcast) and all-zero addresses carry no identity.
  if ((original[0] & 0x01u) != 0 ||
      std::all_of(original.begin(), original.end(), [](auto v) { return v == 0; })) {
    return original;
  }
  auto p = assign(Category::mac, original);
  if (!p) return std::unexpected(p.error());
  Mac out{};
  std::copy_n(p->begin(), 6, out.begin());
  return out;
}

Result<std::uint32_t> Pseudonymiser::ipv4(std::uint32_t original) {
  switch (classify_ipv4(original)) {
    case Ipv4Class::keep:
      return original;
    case Ipv4Class::multicast: {
      auto p = assign(Category::ipv4_mcast, be32_bytes(original));
      if (!p) return std::unexpected(p.error());
      return from_be32(*p);
    }
    case Ipv4Class::unicast: {
      auto p = assign(options_.prefix_preserving ? Category::ipv4_pp : Category::ipv4,
                      be32_bytes(original));
      if (!p) return std::unexpected(p.error());
      return from_be32(*p);
    }
  }
  return original;
}

Result<Ipv6> Pseudonymiser::ipv6(const Ipv6& original) {
  Ipv6 out = original;
  switch (classify_ipv6(original)) {
    case Ipv6Class::keep:
      return original;
    case Ipv6Class::solicited_node: {
      auto p = assign(Category::ipv6_sn24, ByteView(original).subspan(13, 3));
      if (!p) return std::unexpected(p.error());
      std::copy(p->begin(), p->end(), out.begin() + 13);
      return out;
    }
    case Ipv6Class::link_local: {
      auto p = assign(Category::ipv6_iid_ll, ByteView(original).subspan(8, 8));
      if (!p) return std::unexpected(p.error());
      std::copy(p->begin(), p->end(), out.begin() + 8);
      return out;
    }
    case Ipv6Class::embedded_ipv4: {
      auto v4 = ipv4(from_be32(ByteView(original).subspan(12, 4)));
      if (!v4) return std::unexpected(v4.error());
      const Bytes b = be32_bytes(*v4);
      std::copy(b.begin(), b.end(), out.begin() + 12);
      return out;
    }
    case Ipv6Class::multicast: {
      // Transient group: keep ff, flags and scope; pseudonymise the group ID.
      auto p = assign(Category::ipv6, original);
      if (!p) return std::unexpected(p.error());
      std::copy(p->begin() + 2, p->end(), out.begin() + 2);
      return out;
    }
    case Ipv6Class::unicast: {
      auto p = assign(options_.prefix_preserving ? Category::ipv6_pp : Category::ipv6, original);
      if (!p) return std::unexpected(p.error());
      std::copy(p->begin(), p->end(), out.begin());
      return out;
    }
  }
  return original;
}

Result<std::uint16_t> Pseudonymiser::vlan(std::uint16_t vid) {
  if (vid == 0 || vid == 4095) return vid;  // priority tag / reserved
  auto p = assign(Category::vlan, Bytes{static_cast<std::uint8_t>(vid >> 8),
                                        static_cast<std::uint8_t>(vid)});
  if (!p) return std::unexpected(p.error());
  return static_cast<std::uint16_t>(((*p)[0] << 8) | (*p)[1]);
}

Result<std::uint16_t> Pseudonymiser::port(std::uint16_t port) {
  if (port < options_.ephemeral_lo || port > options_.ephemeral_hi) return port;
  auto p = assign(Category::port_eph, Bytes{static_cast<std::uint8_t>(port >> 8),
                                            static_cast<std::uint8_t>(port)});
  if (!p) return std::unexpected(p.error());
  return static_cast<std::uint16_t>(((*p)[0] << 8) | (*p)[1]);
}

Result<std::string> Pseudonymiser::text(Category c, std::string_view original) {
  switch (c) {
    case Category::domain: return domain(original);
    case Category::tel: return tel(original);
    default:
      break;
  }
  if (is_binary_category(c)) return fail(ErrorCode::internal, "a binary value category is not text");
  if (!is_text_category(c)) return fail(ErrorCode::internal, "not a text category");
  // Canonical originals: UUIDs and session ids are case-insensitive hex; every
  // other value is taken exactly as it appears.
  std::string canon(original);
  if (c == Category::uuid || c == Category::session_id) canon = lower(original);
  if (c == Category::imei || c == Category::sdp_sess || c == Category::plmn) {
    if (canon.empty() || !std::all_of(canon.begin(), canon.end(), is_digit)) {
      return fail(ErrorCode::internal, "a numeric pseudonym needs a digit string");
    }
  }
  if (c == Category::imei && canon.size() != 14) {
    return fail(ErrorCode::internal, "an IMEI pseudonym needs the 14 digits of TAC and SNR");
  }
  auto p = assign(c, as_bytes(canon));
  if (!p) return std::unexpected(p.error());
  std::string out(as_text(*p));
  if (c == Category::imei) out.push_back(luhn_digit(out));  // TS 23.003 §B.2
  return out;
}

Result<std::string> Pseudonymiser::domain(std::string_view name) {
  if (name.empty()) return std::string();
  const bool absolute = name.size() > 1 && name.back() == '.';
  if (absolute) name.remove_suffix(1);
  const std::string canon = lower(name);
  const auto labels = split_labels(canon);
  const bool host = std::all_of(labels.begin(), labels.end(), is_ldh_label);
  std::string out;
  if (!host || labels.size() == 1) {
    // One label under "invalid": a single-label host, or a realm that is not a host name.
    auto p = assign(Category::domain, as_bytes(canon));
    if (!p) return std::unexpected(p.error());
    out.assign(as_text(*p));
  } else {
    // Each label except the top one, derived together with its parent suffix (FR-009).
    std::size_t offset = 0;
    for (std::size_t i = 0; i + 1 < labels.size(); ++i) {
      auto p = assign(Category::domain, as_bytes(std::string_view(canon).substr(offset)));
      if (!p) return std::unexpected(p.error());
      out.append(as_text(*p));
      out.push_back('.');
      offset += labels[i].size() + 1;
    }
    out.pop_back();
  }
  out += ".invalid";  // RFC 2606 §2
  if (absolute) out.push_back('.');
  return out;
}

Result<std::string> Pseudonymiser::tel(std::string_view number) {
  std::string canon;
  bool plus = false;
  for (char ch : number) {
    if (is_digit(ch)) {
      canon.push_back(ch);
    } else if (ch == '+' && canon.empty()) {
      plus = true;
    }
  }
  // Special numbers of up to 3 digits (emergency and short codes) are kept.
  if (canon.size() <= 3) return std::string(number);
  auto p = assign(Category::tel, as_bytes((plus ? "+" : "") + canon));
  if (!p) return std::unexpected(p.error());
  const std::string_view digits = as_text(*p).substr(plus ? 1 : 0);
  std::string out(number);
  std::size_t k = 0;
  for (auto& ch : out) {
    if (is_digit(ch)) ch = digits[k++];
  }
  return out;
}

Result<std::string> Pseudonymiser::sdp_version(std::string_view sess_id,
                                               std::string_view version) {
  const auto numeric = [](std::string_view v) {
    return !v.empty() && std::all_of(v.begin(), v.end(), is_digit);
  };
  if (!numeric(sess_id) || !numeric(version)) {
    return fail(ErrorCode::internal, "sess-id and sess-version must be digit strings");
  }
  // RFC 3264 §8: the version "MUST increment by one", so it is shifted by an offset keyed by
  // the session id, modulo 10^digits, digit by digit (any length).
  DigestStream st(derive(secret_, to_string(Category::sdp_sess), as_bytes(sess_id),
                         kSdpVersionCounter));
  const std::string offset = render_digits(st, version.size(), false);
  std::string out(version);
  int carry = 0;
  for (std::size_t i = out.size(); i-- > 0;) {
    const int sum = (version[i] - '0') + (offset[i] - '0') + carry;
    out[i] = static_cast<char>('0' + sum % 10);
    carry = sum / 10;
  }
  return out;
}

Result<std::uint32_t> Pseudonymiser::spi(std::uint32_t original) {
  if (original < 256) return original;  // RFC 4303 §2.1: reserved values carry no identity
  auto p = assign(Category::spi, be32_bytes(original));
  if (!p) return std::unexpected(p.error());
  return from_be32(*p);
}

Result<std::uint32_t> Pseudonymiser::binary(Category c, std::uint32_t original) {
  const unsigned bits = binary_bits(c);
  if (bits == 0 || bits > 32 || c == Category::spi || c == Category::ssrc) {
    return fail(ErrorCode::internal, "not a binary media category");
  }
  if (bits < 32 && original >= (std::uint32_t{1} << bits)) {
    return fail(ErrorCode::internal, "value wider than its category");
  }
  Bytes o = be32_bytes(original);
  const std::size_t octets = (bits + 7) / 8;
  o.erase(o.begin(), o.begin() + static_cast<std::ptrdiff_t>(4 - octets));
  auto p = assign(c, o);
  if (!p) return std::unexpected(p.error());
  std::uint32_t v = 0;
  for (auto b : *p) v = (v << 8) | b;
  return v;
}

Result<std::uint32_t> Pseudonymiser::key_id(std::uint32_t original) {
  auto p = assign(Category::key_id, be32_bytes(original));
  if (!p) return std::unexpected(p.error());
  return from_be32(*p);
}

std::optional<std::uint32_t> Pseudonymiser::find_key_id(std::uint32_t original) const {
  const auto* e = mapping_.find(Category::key_id, be32_bytes(original));
  if (e == nullptr || e->pseudonym.size() != 4) return std::nullopt;
  return from_be32(e->pseudonym);
}

Result<Bytes> Pseudonymiser::bytes(Category c, ByteView original) {
  if (c == Category::nonce) {
    if (original.empty() || original.size() > 255) return fail(ErrorCode::internal, "a nonce has 1 to 255 octets");
  } else if (c == Category::uid) {
    if (original.size() != 32) return fail(ErrorCode::internal, "a UID has 32 octets");
  } else {
    return fail(ErrorCode::internal, "not a byte-string category");
  }
  return assign(c, original);
}

Result<std::uint64_t> Pseudonymiser::binary64(Category c, std::uint64_t original) {
  if (c != Category::nci) return fail(ErrorCode::internal, "not a 64-bit binary category");
  if (original >= (std::uint64_t{1} << 36)) return fail(ErrorCode::internal, "value wider than its category");
  Bytes o;
  for (int k = 4; k >= 0; --k) o.push_back(static_cast<std::uint8_t>(original >> (8 * k)));
  auto p = assign(c, o);
  if (!p) return std::unexpected(p.error());
  std::uint64_t v = 0;
  for (auto b : *p) v = (v << 8) | b;
  return v;
}

Result<std::uint32_t> Pseudonymiser::ssrc(std::uint32_t original) {
  auto p = assign(Category::ssrc, be32_bytes(original));
  if (!p) return std::unexpected(p.error());
  return from_be32(*p);
}

void Pseudonymiser::finish_run() {
  for (const auto& [key, used] : used_) {
    if (used) mapping_.mark_seen(key.first, key.second);
  }
}

}  // namespace mcxanon
