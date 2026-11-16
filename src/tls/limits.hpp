// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounds of the TLS layer (feature 007).
#pragma once

#include <cstddef>

namespace mcxanon::tls {

inline constexpr std::size_t kMaxRecord = 16384 + 2048;     // TLSCiphertext.length bound (RFC 8446 §5.2)
inline constexpr std::size_t kOutRecord = 16384;            // re-fragmented handshake records (2^14)
inline constexpr std::size_t kMaxHandshakeUnit = 256u * 1024;
inline constexpr std::size_t kMaxCertificate = 64u * 1024;
inline constexpr std::size_t kMaxChain = 32;
inline constexpr std::size_t kMaxDerDepth = 32;
inline constexpr std::size_t kMaxDerNodes = 4096;
inline constexpr std::size_t kMaxExtensions = 128;

}  // namespace mcxanon::tls
