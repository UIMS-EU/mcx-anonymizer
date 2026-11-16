// SPDX-License-Identifier: GPL-3.0-or-later
//
// The '3GPP key parameters' general extension (type 7, TS 33.180 §E.6.1): an MCData protected
// payload (TS 33.180 Table 8.5.4.1-1) whose header is delimited by trial. The
// Signalling algorithm octet is optional and has no presence flag, so both layouts are tried; a
// layout is accepted only when its DPPK-ID equals the CSB ID of the message ("The DPPK-ID of the
// Protected Payload shall be the same as the CSB-ID", §E.6.1) and its TLV-E elements end exactly at
// the end of the extension data. The IV is 16 octets (Table 8.5.4.1-1).
#pragma once

#include "bytes/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace mcxanon::mikey {

inline constexpr std::size_t kKpDateOff = 1;   // Date and Time, 5 octets
inline constexpr std::size_t kKpDateLen = 5;
inline constexpr std::size_t kKpIvLen = 16;

struct KeyParams {
  bool signalling = false;      // the Signalling algorithm octet is present
  std::size_t iv_off = 0;       // 16 octets
  std::size_t dppk_off = 0;     // 4 octets
  std::size_t payload_off = 0;  // the value of the Payload TLV-E (kept ciphertext)
  std::size_t payload_len = 0;
  std::optional<std::pair<std::size_t, std::size_t>> i_message;  // value (offset, length) of the nested TLV-E
};

// The unique layout of `data`, or nullopt (none or both fit).
std::optional<KeyParams> delimit_key_parameters(ByteView data, std::uint32_t csb_id);

}  // namespace mcxanon::mikey
