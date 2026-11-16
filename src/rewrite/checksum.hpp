// SPDX-License-Identifier: GPL-3.0-or-later
//
// Internet checksum (RFC 1071, RFC 1624), Ethernet CRC-32 and CRC32c (SCTP).
#pragma once

#include "bytes/bytes.hpp"

#include <cstdint>

namespace mcxanon {

// Adds the 16-bit big-endian words of `data` to `acc` (one's-complement sum,
// unfolded). An odd final byte is padded with zero; only the last chunk of a
// multi-chunk sum may have odd length.
std::uint32_t inet_accumulate(ByteView data, std::uint32_t acc = 0);
// Folds an accumulator into a 16-bit one's-complement sum (not complemented).
std::uint16_t inet_fold_sum(std::uint32_t acc);
// The Internet checksum: complement of the folded sum.
std::uint16_t inet_checksum(ByteView data);
// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m').
std::uint16_t inet_update16(std::uint16_t hc, std::uint16_t old_word, std::uint16_t new_word);

std::uint32_t crc32_ethernet(ByteView data);
std::uint32_t crc32c(ByteView data);

}  // namespace mcxanon
