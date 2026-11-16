// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/location.hpp"

#include <algorithm>
#include <cctype>

namespace mcxanon::xml {
namespace {

using Opt = Result<std::optional<std::string>>;
const auto kNone = std::optional<std::string>{};

bool all_of(std::string_view s, int (*pred)(int)) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [pred](char c) { return pred(static_cast<unsigned char>(c)) != 0; });
}
bool binary_digits(std::string_view s) {
  return !s.empty() && s.find_first_not_of("01") == std::string_view::npos;
}

std::uint64_t from_bits(std::string_view s) {
  std::uint64_t v = 0;
  for (const char c : s) v = (v << 1) | static_cast<std::uint64_t>(c == '1');
  return v;
}
std::string to_bits(std::uint64_t v, std::size_t n) {
  std::string out(n, '0');
  for (std::size_t i = 0; i < n; ++i) out[n - 1 - i] = ((v >> i) & 1u) != 0 ? '1' : '0';
  return out;
}

// Hex digits of `v` with the width and the per-position letter case of `like`.
std::string to_hex_like(std::uint64_t v, std::string_view like) {
  std::string out(like.size(), '0');
  for (std::size_t i = 0; i < like.size(); ++i) {
    const auto nib = static_cast<unsigned>((v >> (4 * (like.size() - 1 - i))) & 0xFu);
    char c = "0123456789abcdef"[nib];
    if (std::isupper(static_cast<unsigned char>(like[i])) != 0 ||
        (std::isdigit(static_cast<unsigned char>(like[i])) != 0 &&
         std::any_of(like.begin(), like.end(), [](char x) { return std::isupper(static_cast<unsigned char>(x)) != 0; }))) {
      c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    out[i] = c;
  }
  return out;
}

Opt plmn(std::string_view v, AddressMapper& m) {
  if (v.size() != 6 || !all_of(v, std::isdigit)) return kNone;
  auto p = m.text(Category::plmn, v);
  if (!p) return std::unexpected(p.error());
  return std::optional<std::string>(std::move(*p));
}

// PLMN + n binary digits of `c`.
Opt plmn_bits(std::string_view v, std::size_t n, Category c, AddressMapper& m) {
  if (v.size() != 6 + n || !binary_digits(v.substr(6))) return kNone;
  auto p = plmn(v.substr(0, 6), m);
  if (!p || !*p) return p;
  const auto value = from_bits(v.substr(6));
  std::uint64_t mapped = 0;
  if (c == Category::nci) {
    auto r = m.binary64(c, value);
    if (!r) return std::unexpected(r.error());
    mapped = *r;
  } else {
    auto r = m.binary(c, static_cast<std::uint32_t>(value));
    if (!r) return std::unexpected(r.error());
    mapped = *r;
  }
  return std::optional<std::string>(**p + to_bits(mapped, n));
}

Opt hex_value(std::string_view v, Category c, AddressMapper& m) {
  if (!all_of(v, std::isxdigit)) return kNone;
  const auto value = static_cast<std::uint32_t>(std::stoul(std::string(v), nullptr, 16));
  auto r = m.binary(c, value);
  if (!r) return std::unexpected(r.error());
  return std::optional<std::string>(to_hex_like(*r, v));
}

Opt decimal(std::string_view v, Category c, std::uint32_t max, AddressMapper& m) {
  if (v.size() > 5 || !all_of(v, std::isdigit)) return kNone;
  const auto value = static_cast<std::uint32_t>(std::stoul(std::string(v)));
  if (value > max) return kNone;
  auto r = m.binary(c, value);
  if (!r) return std::unexpected(r.error());
  return std::optional<std::string>(std::to_string(*r));
}

}  // namespace

bool is_location_category(XmlCategory c) {
  switch (c) {
    case XmlCategory::ecgi:
    case XmlCategory::ncgi:
    case XmlCategory::tai:
    case XmlCategory::tac_bin:
    case XmlCategory::plmn:
    case XmlCategory::mbms_sai:
    case XmlCategory::mbsfn_area:
    case XmlCategory::mbs_fsa:
    case XmlCategory::nr_tac:
    case XmlCategory::mbms_sai_hex:
    case XmlCategory::ssrc:
    case XmlCategory::fc_ref: return true;
    default: return false;
  }
}

Result<std::optional<std::string>> map_location(XmlCategory c, std::string_view v, AddressMapper& m) {
  switch (c) {
    case XmlCategory::ecgi: return plmn_bits(v, 28, Category::eci, m);
    case XmlCategory::ncgi: return plmn_bits(v, 36, Category::nci, m);
    case XmlCategory::tai: return plmn_bits(v, 16, Category::tac, m);
    case XmlCategory::tac_bin:
      if (v.size() == 4) return hex_value(v, Category::tac, m);
      if (v.size() == 6) return hex_value(v, Category::nr_tac, m);
      return kNone;
    case XmlCategory::plmn: return plmn(v, m);
    case XmlCategory::mbms_sai: return decimal(v, Category::mbms_sai, 65535, m);
    case XmlCategory::mbsfn_area: return decimal(v, Category::mbsfn_area, 255, m);
    case XmlCategory::mbs_fsa: return v.size() == 6 ? hex_value(v, Category::mbs_fsa, m) : kNone;
    case XmlCategory::nr_tac: return v.size() == 6 ? hex_value(v, Category::nr_tac, m) : kNone;
    case XmlCategory::mbms_sai_hex: return v.size() == 4 ? hex_value(v, Category::mbms_sai, m) : kNone;
    case XmlCategory::ssrc:
    case XmlCategory::fc_ref: {
      // A14: decimal text of xs:unsignedLong; values above 4294967295 do not fit.
      if (v.empty() || v.size() > 10 || !all_of(v, std::isdigit)) return kNone;
      const auto value = std::stoull(std::string(v));
      if (value > 0xFFFFFFFFull) return kNone;
      auto r = c == XmlCategory::ssrc ? m.ssrc(static_cast<std::uint32_t>(value))
                                      : m.binary(Category::fc_ref, static_cast<std::uint32_t>(value));
      if (!r) return std::unexpected(r.error());
      return std::optional<std::string>(std::to_string(*r));
    }
    default: return kNone;
  }
}

}  // namespace mcxanon::xml
