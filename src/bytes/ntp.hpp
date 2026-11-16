// SPDX-License-Identifier: GPL-3.0-or-later
//
// A 64-bit NTP timestamp (32-bit seconds since 1900, 32-bit fraction; RFC 3830 §6.6 NTP-UTC)
// moved by a signed nanosecond shift (001 FR-039; feature 005). Seconds wrap
// modulo 2^32 (NTP eras).
#pragma once

#include <cstdint>

namespace mcxanon {

std::uint64_t shift_ntp64(std::uint64_t ntp, std::int64_t shift_ns);

}  // namespace mcxanon
