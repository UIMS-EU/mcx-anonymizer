// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/uid.hpp"

#include <openssl/sha.h>

#include <array>

namespace mcxanon::mikey {

namespace {

void part(Bytes& s, ByteView p) {
  s.insert(s.end(), p.begin(), p.end());
  s.push_back(static_cast<std::uint8_t>(p.size() >> 8));
  s.push_back(static_cast<std::uint8_t>(p.size()));
}

Bytes integer(std::uint64_t v) {
  Bytes out;
  do {
    out.insert(out.begin(), static_cast<std::uint8_t>(v & 0xFF));
    v >>= 8;
  } while (v != 0);
  return out;
}

ByteView text(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }

}  // namespace

Bytes uid(std::string_view identifier, std::string_view kms, std::uint64_t period, std::uint64_t offset,
          std::uint64_t number) {
  Bytes s{0x00};
  part(s, text("MIKEY-SAKKE-UID"));
  part(s, text(identifier));
  part(s, text(kms));
  part(s, integer(period));
  part(s, integer(offset));
  part(s, integer(number));
  std::array<unsigned char, SHA256_DIGEST_LENGTH> d{};
  SHA256(s.data(), s.size(), d.data());
  return Bytes(d.begin(), d.end());
}

std::uint64_t period_number(std::uint64_t ntp_seconds, std::uint64_t period, std::uint64_t offset) {
  if (period == 0 || ntp_seconds < offset) return 0;
  return (ntp_seconds - offset) / period;
}

}  // namespace mcxanon::mikey
