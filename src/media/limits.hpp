// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace mcxanon::media {

// Bounds of the media layer. Every bound leads to zeroing, never to
// pass-through.

// Endpoints announced by SDP that the table holds at once. On overflow the least
// recently used one is evicted and its later packets are zeroed (FR-002).
inline constexpr std::size_t kMaxMediaEndpoints = 65536;

}  // namespace mcxanon::media
