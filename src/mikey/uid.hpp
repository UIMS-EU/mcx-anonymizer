// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY-SAKKE UID of TS 33.180 §F.2.1.1: SHA-256 over FC || P0 || L0 || ... || P5 || L5 with
// FC = 0x00, P0 = "MIKEY-SAKKE-UID", P1 the identifier, P2 the KMS identifier, P3 the key period
// length, P4 the key period offset and P5 the current key period number, the integers in the
// fewest big-endian octets and every Li a 2-octet length (TS 33.220 Annex B.2 as referenced).
// Checked against the example of §F.2.1.2.
#pragma once

#include "bytes/bytes.hpp"

#include <cstdint>
#include <string_view>

namespace mcxanon::mikey {

Bytes uid(std::string_view identifier, std::string_view kms, std::uint64_t period, std::uint64_t offset,
          std::uint64_t number);

// P5 = floor((TIME - P4) / P3) for an NTP seconds value (§F.2.1.1). P3 must not be zero.
std::uint64_t period_number(std::uint64_t ntp_seconds, std::uint64_t period, std::uint64_t offset);

}  // namespace mcxanon::mikey
