// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/ntp.hpp"

namespace mcxanon {

std::uint64_t shift_ntp64(std::uint64_t ntp, std::int64_t shift_ns) {
  constexpr std::int64_t kNs = 1000000000;
  std::int64_t whole = shift_ns / kNs;
  std::int64_t rest = shift_ns % kNs;
  if (rest < 0) {
    rest += kNs;
    whole -= 1;
  }
  const std::uint64_t frac_add = (static_cast<std::uint64_t>(rest) << 32) / static_cast<std::uint64_t>(kNs);
  std::uint64_t frac = (ntp & 0xFFFFFFFFu) + frac_add;
  const std::uint64_t carry = frac >> 32;
  frac &= 0xFFFFFFFFu;
  const std::uint32_t secs = static_cast<std::uint32_t>(
      static_cast<std::uint64_t>(ntp >> 32) + carry + static_cast<std::uint64_t>(whole));
  return (static_cast<std::uint64_t>(secs) << 32) | frac;
}

}  // namespace mcxanon
