// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace mcxanon::scan::detail {

// The scanner's own copy of the pcapng option allowlist: options that the rule
// set keeps because they are needed to decode packets. Everything else in a
// pcapng file is harvested as a sensitive value. A unit test compares this
// table with rules/pcapng.yaml.
bool harvest_allows(std::uint32_t block_type, std::uint16_t code);

}  // namespace mcxanon::scan::detail
