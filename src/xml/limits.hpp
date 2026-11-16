// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounds of the XML reader (FR-003). Exceeding one empties the body
// with the reason `limit`.
#pragma once

#include <cstddef>

namespace mcxanon::xml {

inline constexpr std::size_t kMaxDepth = 32;              // element nesting (the root is depth 1)
inline constexpr std::size_t kMaxElements = 10'000;       // elements per body
inline constexpr std::size_t kMaxAttributes = 64;         // attributes per element, xmlns included
inline constexpr std::size_t kMaxNameBytes = 256;         // one element or attribute name
inline constexpr std::size_t kMaxValueBytes = 64 * 1024;  // one attribute value or text run, raw bytes
inline constexpr std::size_t kMaxBodyBytes = 1024 * 1024; // the 002 message bound (sip::kMaxMessageBytes)
inline constexpr std::size_t kMaxEmbedDepth = 1;          // bodies inside resource-lists entry URIs (FR-014a)

}  // namespace mcxanon::xml
