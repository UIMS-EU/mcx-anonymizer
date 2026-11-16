// SPDX-License-Identifier: GPL-3.0-or-later
//
// Rendering of text and numeric pseudonyms from an HMAC derivation digest.
// Every function is deterministic in the digest; none sees the original except where the
// format depends on it (length, alphabet, leading "+", magic cookie).
#pragma once

#include "pseudo/hmac.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mcxanon {

// A deterministic byte stream keyed by a derivation digest. Block 0 is the digest itself,
// block i > 0 is HMAC-SHA-256(digest, be32(i)), so a format can draw as many bytes as it
// needs without changing the derivation.
class DigestStream {
 public:
  explicit DigestStream(const Digest32& d);
  std::uint8_t byte();
  // Uniform in [0, n) for 1 <= n <= 256, by rejection sampling.
  std::uint32_t uniform(std::uint32_t n);

 private:
  Digest32 seed_;
  Digest32 block_;
  std::uint32_t index_ = 0;
  std::size_t pos_ = 0;
};

// prefix + n lowercase hex digits.
std::string render_hex(std::string_view prefix, DigestStream& s, std::size_t n);
// n decimal digits; the first is 1-9 when first_nonzero is set.
std::string render_digits(DigestStream& s, std::size_t n, bool first_nonzero);
// The Luhn check digit of a digit string, as computed for the IMEI (TS 23.003 §B.2).
char luhn_digit(std::string_view digits);
// An RFC 9562 version 4 UUID in lowercase text form.
std::string render_uuid_v4(DigestStream& s);
// Same length and character class as the original: all digits stay digits, lowercase hex
// stays lowercase hex, uppercase hex stays uppercase hex, base64 stays base64 (padding kept);
// any other value is mapped character by character (digit, lowercase, uppercase letter),
// with every other character kept in place.
std::string render_like(std::string_view original, DigestStream& s);

}  // namespace mcxanon
