// SPDX-License-Identifier: GPL-3.0-or-later
//
// The encodings of the MIKEY carriers: base64 in SDP a=key-mgmt (RFC 4567 §3.1),
// binary or base64 in application/mikey bodies (RFC 3830 §10.1) and the MCPC PCK I_MESSAGE field
// (TS 24.380 §8.3.3.10), xs:hexBinary in <GKTP> (TS 24.481 §7.7.4.2). A decoded value remembers
// its form, so the rewritten message goes back in the same one.
#pragma once

#include "bytes/base64.hpp"
#include "bytes/bytes.hpp"
#include "policy/mikey_rules.hpp"
#include "sip/value_map.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::mikey {

struct CarrierValue {
  enum class Encoding { binary, base64, hex } encoding = Encoding::binary;
  Bytes bytes;
  base64::Layout layout;  // base64
  bool upper = false;     // hex: upper-case letters
  std::string lead;       // hex: XML whitespace before the digits
  std::string trail;      // hex: XML whitespace after them
};

// nullopt: the value is not in the carrier's encoding (fallback reason "encoding").
std::optional<CarrierValue> decode_carrier(sip::MikeyCarrierKind kind, std::string_view value, std::string_view cte,
                                           const MikeyRuleSet& rules);
std::string encode_carrier(const CarrierValue& form, ByteView message);

}  // namespace mcxanon::mikey
