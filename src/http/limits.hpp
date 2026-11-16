// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounds of the HTTP layer (feature 007). Every bound leads to removal or zeroing,
// never to a failure of the run.
#pragma once

#include <cstddef>
#include <cstdint>

namespace mcxanon::http {

inline constexpr std::size_t kMaxHeadBytes = 64u * 1024;         // start line + fields + empty line
inline constexpr std::size_t kMaxFields = 512;                   // header fields per message
inline constexpr std::size_t kMaxFieldBytes = 8u * 1024;         // one field line
inline constexpr std::size_t kMaxRewrittenBody = 1024u * 1024 - kMaxHeadBytes;  // body handled as one message
inline constexpr std::size_t kMaxParams = 256;                   // query or form parameters
inline constexpr std::size_t kMaxJsonDepth = 32;
inline constexpr std::size_t kMaxJsonMembers = 4096;             // members and elements in one document
inline constexpr std::size_t kMaxJsonString = 64u * 1024;
inline constexpr std::size_t kMaxToken = 16u * 1024;             // a JWT or opaque token
inline constexpr std::size_t kMaxPendingMethods = 64;            // HTTP/1.1 requests awaiting a response
inline constexpr std::size_t kMaxChunkLine = 4096;               // chunk-size line with extensions
inline constexpr std::size_t kMaxTrailer = 16u * 1024;           // trailer section
inline constexpr std::uint64_t kDropRest = ~std::uint64_t{0};    // drop_after: the rest of the direction

// HTTP/2.
inline constexpr std::size_t kMaxFrame = 1024u * 1024;
inline constexpr std::size_t kMaxUnit = 1024u * 1024;
inline constexpr std::size_t kMaxHeaderList = 64u * 1024;        // decoded header list of one block
inline constexpr std::size_t kMaxHeaderBlock = 64u * 1024;       // encoded block incl. CONTINUATION
inline constexpr std::size_t kMaxTable = 64u * 1024;             // HPACK dynamic table size
inline constexpr std::size_t kMaxHpackString = 16u * 1024;
inline constexpr std::size_t kMaxStreams = 1024;                 // open h2 streams per direction
inline constexpr std::size_t kOutFrame = 16384;                  // RFC 9113 §4.2 minimum maximum

}  // namespace mcxanon::http
