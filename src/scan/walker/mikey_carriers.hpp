// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY carriers of an output payload, located and decoded by the scanner itself (feature 005,
// FR-022): the scanner searches the decoded bytes too, because the text forms of a
// short token (a 32-bit key identifier) do not cover every base64 alignment. Shares no code with
// the anonymiser.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mcxanon::scan::detail {

struct MikeyCarrierSpan {
  std::size_t offset = 0;  // of the carrier text within the payload
  std::size_t length = 0;
  std::string carrier;     // sdp, body, gktp, mcpc
  std::vector<std::uint8_t> decoded;
};

std::vector<MikeyCarrierSpan> find_mikey_carriers(std::span<const std::uint8_t> payload);

}  // namespace mcxanon::scan::detail
