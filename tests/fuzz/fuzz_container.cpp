// SPDX-License-Identifier: GPL-3.0-or-later
// Encrypted project container parsing and authentication over arbitrary bytes.
#include "pseudo/crypto.hpp"

#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const mcxanon::Key key = [] {
    mcxanon::Key k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(i);
    return k;
  }();
  const mcxanon::ByteView in(data, size);
  (void)mcxanon::container_params(in);
  auto opened = mcxanon::open_sealed(key, "mapping", in);
  if (opened) std::abort();  // forging a valid tag would be a break of ChaCha20-Poly1305
  // A container sealed with the key opens again, and only with the same role.
  mcxanon::KdfParams p;
  p.m_kib = 8;
  p.t = 1;
  auto sealed = mcxanon::seal(key, p, "secret", in);
  if (!sealed) return 0;
  auto back = mcxanon::open_sealed(key, "secret", *sealed);
  if (!back || *back != mcxanon::Bytes(data, data + size)) std::abort();
  if (mcxanon::open_sealed(key, "mapping", *sealed)) std::abort();
  return 0;
}
