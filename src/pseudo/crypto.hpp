// SPDX-License-Identifier: GPL-3.0-or-later
//
// Passphrase encryption of project files (FR-023b):
// Argon2id key derivation and a ChaCha20-Poly1305 container
//   "MCXENC01" | m_kib(4) | t(4) | p(4) | salt(16) | nonce(12) | ciphertext | tag(16)
// with the 48-byte header and the file's role ("secret", "mapping") as AAD.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace mcxanon {

struct KdfParams {
  std::uint32_t m_kib = 65536;
  std::uint32_t t = 3;
  std::uint32_t p = 1;
  std::array<std::uint8_t, 16> salt{};
};

using Key = std::array<std::uint8_t, 32>;

Result<KdfParams> new_kdf_params();
Result<Key> derive_key(std::string_view passphrase, const KdfParams& params);
Result<Bytes> seal(const Key& key, const KdfParams& params, std::string_view role, ByteView plaintext);
Result<Bytes> open_sealed(const Key& key, std::string_view role, ByteView container);
Result<KdfParams> container_params(ByteView container);

}  // namespace mcxanon
