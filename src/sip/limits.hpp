// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounds of the SIP parsers. Exceeding one counts as malformed.
#pragma once

#include <cstddef>

namespace mcxanon::sip {

inline constexpr std::size_t kMaxMessageBytes = 1024 * 1024;   // whole message
inline constexpr std::size_t kMaxHeaderLineBytes = 64 * 1024;  // one header field, folding included
inline constexpr std::size_t kMaxHeaders = 512;                // header fields per message
inline constexpr std::size_t kMaxParamsPerHeader = 1024;       // parameters of one header field
inline constexpr std::size_t kMaxQuotedBytes = 8 * 1024;       // one quoted string
inline constexpr std::size_t kMaxMultipartDepth = 4;           // nested multipart bodies
inline constexpr std::size_t kMaxParts = 64;                   // parts of one multipart body

}  // namespace mcxanon::sip
