// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/text_formats.hpp"

#include <algorithm>

namespace mcxanon {
namespace {

constexpr std::string_view kHex = "0123456789abcdef";
constexpr std::string_view kHexUpper = "0123456789ABCDEF";
constexpr std::string_view kBase64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_lower(char c) { return c >= 'a' && c <= 'z'; }
bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
bool is_hex_lower(char c) { return is_digit(c) || (c >= 'a' && c <= 'f'); }
bool is_hex_upper(char c) { return is_digit(c) || (c >= 'A' && c <= 'F'); }
bool is_b64(char c) { return is_digit(c) || is_lower(c) || is_upper(c) || c == '+' || c == '/'; }

template <class Pred>
bool all_of(std::string_view s, Pred p) {
  return !s.empty() && std::all_of(s.begin(), s.end(), p);
}

std::string from_alphabet(std::string_view original, std::string_view alphabet, DigestStream& s) {
  std::string out(original.size(), '\0');
  for (auto& c : out) c = alphabet[s.uniform(static_cast<std::uint32_t>(alphabet.size()))];
  return out;
}

}  // namespace

DigestStream::DigestStream(const Digest32& d) : seed_(d), block_(d) {}

std::uint8_t DigestStream::byte() {
  if (pos_ == block_.size()) {
    ++index_;
    const std::uint8_t be[4] = {static_cast<std::uint8_t>(index_ >> 24),
                                static_cast<std::uint8_t>(index_ >> 16),
                                static_cast<std::uint8_t>(index_ >> 8),
                                static_cast<std::uint8_t>(index_)};
    block_ = hmac_sha256(ByteView(seed_.data(), seed_.size()), ByteView(be, 4));
    pos_ = 0;
  }
  return block_[pos_++];
}

std::uint32_t DigestStream::uniform(std::uint32_t n) {
  const std::uint32_t limit = 256u - 256u % n;
  for (;;) {
    const std::uint32_t b = byte();
    if (b < limit) return b % n;
  }
}

std::string render_hex(std::string_view prefix, DigestStream& s, std::size_t n) {
  std::string out(prefix);
  for (std::size_t i = 0; i < n; ++i) out.push_back(kHex[s.uniform(16)]);
  return out;
}

std::string render_digits(DigestStream& s, std::size_t n, bool first_nonzero) {
  std::string out;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    if (i == 0 && first_nonzero) {
      out.push_back(static_cast<char>('1' + s.uniform(9)));
    } else {
      out.push_back(static_cast<char>('0' + s.uniform(10)));
    }
  }
  return out;
}

char luhn_digit(std::string_view digits) {
  // TS 23.003 §B.2: double the odd-labelled digits D1, D3, ... (D1 is the least significant),
  // add up the digits of the results and the even-labelled digits; CD completes the sum to the
  // next multiple of 10.
  unsigned sum = 0;
  for (std::size_t i = 0; i < digits.size(); ++i) {
    unsigned d = static_cast<unsigned>(digits[digits.size() - 1 - i] - '0');
    if (i % 2 == 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return static_cast<char>('0' + (10 - sum % 10) % 10);
}

std::string render_uuid_v4(DigestStream& s) {
  std::string h = render_hex("", s, 32);
  h[12] = '4';                             // version 4 (RFC 9562 §5.4)
  h[16] = kHex[8 + s.uniform(4)];          // variant 10xx (RFC 9562 §4.1)
  return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) +
         "-" + h.substr(20);
}

std::string render_like(std::string_view original, DigestStream& s) {
  if (all_of(original, is_digit)) return from_alphabet(original, "0123456789", s);
  if (all_of(original, is_hex_lower)) return from_alphabet(original, kHex, s);
  if (all_of(original, is_hex_upper)) return from_alphabet(original, kHexUpper, s);
  // base64 (RFC 4648 §4): alphabet characters, then at most two "=" of padding.
  const auto body_end = original.find_last_not_of('=');
  if (body_end != std::string_view::npos && original.size() - body_end - 1 <= 2 &&
      all_of(original.substr(0, body_end + 1), is_b64) && original.size() % 4 == 0) {
    std::string out = from_alphabet(original.substr(0, body_end + 1), kBase64, s);
    out.append(original.size() - body_end - 1, '=');
    return out;
  }
  std::string out(original);
  for (auto& c : out) {
    if (is_digit(c)) {
      c = static_cast<char>('0' + s.uniform(10));
    } else if (is_lower(c)) {
      c = static_cast<char>('a' + s.uniform(26));
    } else if (is_upper(c)) {
      c = static_cast<char>('A' + s.uniform(26));
    }
  }
  return out;
}

}  // namespace mcxanon
