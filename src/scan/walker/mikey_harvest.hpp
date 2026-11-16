// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own MIKEY reader (feature 005): a bounded walk over a data-type-26
// message that reports the values the anonymiser must not leave in the output, by syntax alone.
// It shares no code with src/mikey. Kept ciphertext (SAKKE data, the key parameters
// payload) is never reported: the project plan keeps it in ciphertext mode.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::scan::detail {

struct MikeyValues {
  std::vector<std::string> uris;                 // identities and KMS identities (text)
  std::vector<std::vector<std::uint8_t>> keys;   // 32-bit key identifiers
  std::vector<std::vector<std::uint8_t>> bytes;  // UIDs, RAND, IV, the signature
  [[nodiscard]] bool empty() const { return uris.empty() && keys.empty() && bytes.empty(); }
};

MikeyValues walk_mikey(std::span<const std::uint8_t> msg);

// The scanner's own decoders for the MIKEY carriers: base64 (RFC 4648 §4, CRLF or LF line breaks
// skipped) and hexBinary (XML whitespace around the digits skipped).
std::optional<std::vector<std::uint8_t>> decode_base64(std::string_view text);
std::optional<std::vector<std::uint8_t>> decode_hex(std::string_view text);

}  // namespace mcxanon::scan::detail
