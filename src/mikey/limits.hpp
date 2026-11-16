// SPDX-License-Identifier: GPL-3.0-or-later
// Bounds of the MIKEY parser.
#pragma once

#include <cstddef>

namespace mcxanon::mikey {

inline constexpr std::size_t kMaxMessage = 65535;      // the MCPC field 192 maximum
inline constexpr std::size_t kMaxPayloads = 64;
inline constexpr std::size_t kMaxIdData = 1024;
inline constexpr std::size_t kMaxBase64Text = 87384;   // 4 * ceil(65535 / 3) plus CRLF every 76

}  // namespace mcxanon::mikey
