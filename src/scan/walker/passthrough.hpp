// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own passthrough locator (feature 005, spec FR-018): the byte ranges
// of an output payload that --encrypted passthrough copies as they were, found by the scanner's
// own decoding: the four MIKEY carriers whose text decodes to a data-type-26
// message, and xenc:EncryptedData subtrees. A hit is downgraded to a warning only when it lies
// wholly inside one range.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mcxanon::scan::detail {

struct PassthroughRange {
  std::uint64_t offset = 0;
  std::uint64_t length = 0;
  std::string carrier;  // sdp, body, gktp, mcpc, encrypted-xml
};

// In payload order (carriers first, then EncryptedData subtrees).
std::vector<PassthroughRange> passthrough_ranges(std::span<const std::uint8_t> payload);

// The range that contains [offset, offset + length), or nullptr.
const PassthroughRange* covering(const std::vector<PassthroughRange>& ranges, std::uint64_t offset,
                                 std::uint64_t length);

}  // namespace mcxanon::scan::detail
