// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shifting a 64-bit NTP timestamp (RFC 3830 §6.6 NTP-UTC).
#include "bytes/ntp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

using namespace mcxanon;

TEST_CASE("ntp: whole seconds move the seconds field only", "[ntp]") {
  const std::uint64_t t = (std::uint64_t{3599719634} << 32) | 0x80000000u;
  CHECK(shift_ntp64(t, 3LL * 86400 * 1000000000) == ((std::uint64_t{3599719634 + 259200} << 32) | 0x80000000u));
  CHECK(shift_ntp64(t, -1000000000LL) == ((std::uint64_t{3599719633} << 32) | 0x80000000u));
  CHECK(shift_ntp64(t, 0) == t);
}

TEST_CASE("ntp: sub-second shifts carry into the seconds", "[ntp]") {
  const std::uint64_t t = (std::uint64_t{100} << 32) | 0x80000000u;  // 100.5 s
  // +0.5 s: exactly the next second.
  CHECK(shift_ntp64(t, 500000000) == (std::uint64_t{101} << 32));
  // -0.75 s: 99.75 s.
  CHECK(shift_ntp64(t, -750000000) == ((std::uint64_t{99} << 32) | 0xC0000000u));
}

TEST_CASE("ntp: the era wraps modulo 2^32 seconds", "[ntp]") {
  const std::uint64_t t = std::uint64_t{0xFFFFFFFFu} << 32;
  CHECK(shift_ntp64(t, 2000000000LL) == (std::uint64_t{1} << 32));
  CHECK(shift_ntp64(std::uint64_t{0}, -1000000000LL) == (std::uint64_t{0xFFFFFFFFu} << 32));
}
