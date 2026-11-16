// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/hmac.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>

namespace mcxanon {

Digest32 hmac_sha256(ByteView key, ByteView data) {
  Digest32 out{};
  unsigned int len = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
           out.data(), &len) == nullptr ||
      len != out.size()) {
    throw std::runtime_error("HMAC-SHA-256 failed");  // only on a broken crypto library
  }
  return out;
}

Bytes derivation_message(std::string_view category, ByteView original, std::uint32_t counter) {
  constexpr std::string_view prefix = "mcxanon/v1";
  Bytes m;
  m.reserve(prefix.size() + category.size() + original.size() + 6);
  m.insert(m.end(), prefix.begin(), prefix.end());
  m.push_back(0);
  m.insert(m.end(), category.begin(), category.end());
  m.push_back(0);
  m.insert(m.end(), original.begin(), original.end());
  for (int shift = 24; shift >= 0; shift -= 8) {
    m.push_back(static_cast<std::uint8_t>((counter >> shift) & 0xFFu));
  }
  return m;
}

Digest32 derive(const Secret& secret, std::string_view category, ByteView original,
                std::uint32_t counter) {
  return hmac_sha256(secret, derivation_message(category, original, counter));
}

}  // namespace mcxanon
