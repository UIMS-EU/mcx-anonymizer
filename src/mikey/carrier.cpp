// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/carrier.hpp"

#include "mikey/decode.hpp"
#include "mikey/limits.hpp"

#include <cctype>

namespace mcxanon::mikey {

namespace {

bool iequal(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
  }
  return true;
}

std::string_view trim_lws(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

bool xml_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::optional<CarrierValue> as_base64(std::string_view v) {
  if (v.size() > kMaxBase64Text) return std::nullopt;
  auto d = base64::decode(v);
  if (!d) return std::nullopt;
  CarrierValue c;
  c.encoding = CarrierValue::Encoding::base64;
  c.bytes = std::move(d->bytes);
  c.layout = d->layout;
  return c;
}

}  // namespace

std::optional<CarrierValue> decode_carrier(sip::MikeyCarrierKind kind, std::string_view value, std::string_view cte,
                                           const MikeyRuleSet& rules) {
  switch (kind) {
    case sip::MikeyCarrierKind::sdp:
      return as_base64(value);
    case sip::MikeyCarrierKind::body:
    case sip::MikeyCarrierKind::mcpc: {
      const auto t = trim_lws(cte);
      if (iequal(t, "base64")) return as_base64(value);
      if (!t.empty() && !iequal(t, "binary") && !iequal(t, "8bit") && !iequal(t, "7bit")) return std::nullopt;
      // No transfer encoding declared: base64 when the text is base64 of a MIKEY-SAKKE message
      // binary otherwise.
      if (base64::alphabet_only(value)) {
        if (auto c = as_base64(value); c && decode(c->bytes, rules).verdict == Verdict::sakke) return c;
      }
      if (value.size() > kMaxMessage) return std::nullopt;
      CarrierValue c;
      c.encoding = CarrierValue::Encoding::binary;
      c.bytes.assign(value.begin(), value.end());
      return c;
    }
    case sip::MikeyCarrierKind::gktp: {
      CarrierValue c;
      c.encoding = CarrierValue::Encoding::hex;
      std::size_t a = 0;
      std::size_t b = value.size();
      while (a < b && xml_space(value[a])) ++a;
      while (b > a && xml_space(value[b - 1])) --b;
      c.lead = std::string(value.substr(0, a));
      c.trail = std::string(value.substr(b));
      const auto digits = value.substr(a, b - a);
      if (digits.empty() || digits.size() % 2 != 0 || digits.size() > 2 * kMaxMessage) return std::nullopt;
      bool seen_letter = false;
      for (std::size_t i = 0; i < digits.size(); i += 2) {
        const int hi = hexval(digits[i]);
        const int lo = hexval(digits[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        c.bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        for (char ch : {digits[i], digits[i + 1]}) {
          if (!seen_letter && std::isalpha(static_cast<unsigned char>(ch))) {
            seen_letter = true;
            c.upper = std::isupper(static_cast<unsigned char>(ch)) != 0;
          }
        }
      }
      if (!seen_letter) c.upper = true;
      return c;
    }
  }
  return std::nullopt;
}

std::string encode_carrier(const CarrierValue& form, ByteView message) {
  switch (form.encoding) {
    case CarrierValue::Encoding::base64:
      return base64::encode(message, form.layout);
    case CarrierValue::Encoding::binary:
      return std::string(message.begin(), message.end());
    case CarrierValue::Encoding::hex: {
      static constexpr char kLower[] = "0123456789abcdef";
      static constexpr char kUpper[] = "0123456789ABCDEF";
      const char* d = form.upper ? kUpper : kLower;
      std::string out = form.lead;
      for (auto x : message) {
        out += d[x >> 4];
        out += d[x & 15];
      }
      return out + form.trail;
    }
  }
  return {};
}

}  // namespace mcxanon::mikey
