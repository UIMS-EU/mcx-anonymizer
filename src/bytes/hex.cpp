// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/hex.hpp"

namespace mcxanon {
namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
}  // namespace

std::string to_hex(ByteView b, bool upper) {
  const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string out;
  out.reserve(b.size() * 2);
  for (auto v : b) {
    out.push_back(digits[v >> 4]);
    out.push_back(digits[v & 0x0F]);
  }
  return out;
}

Result<Bytes> from_hex(std::string_view s) {
  if (s.size() % 2 != 0) return fail(ErrorCode::input, "hex string has odd length");
  Bytes out;
  out.reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    const int hi = nibble(s[i]);
    const int lo = nibble(s[i + 1]);
    if (hi < 0 || lo < 0) return fail(ErrorCode::input, "invalid hex digit");
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

}  // namespace mcxanon
