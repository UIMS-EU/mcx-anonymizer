// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the MIKEY rewriter counts for the report.
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace mcxanon::mikey {

struct CarrierCounts {
  std::uint64_t rewritten = 0;
  std::uint64_t passed_through = 0;
  std::map<std::string, std::uint64_t> fallback;  // reason -> count
};

struct Counters {
  std::map<std::string, CarrierCounts> carriers;  // sdp, body, gktp, mcpc
  std::uint64_t unexpected_carrier = 0;
  std::map<std::string, std::map<std::string, std::uint64_t>> payloads;  // "T" -> "shifted" -> n
  std::uint64_t incomplete = 0;
  std::uint64_t uids_resolved = 0;
  std::uint64_t uids_unresolved = 0;
  std::map<std::string, std::uint64_t> key_ids;  // purpose tag name -> distinct identifiers
  std::map<std::string, std::uint64_t> cs_ids;   // "undefined-cs-id"
  std::uint64_t encrypted_uri_structured = 0;
  std::uint64_t encrypted_uri_whole_user_part = 0;

  [[nodiscard]] bool any() const {
    return !carriers.empty() || unexpected_carrier != 0 || encrypted_uri_structured != 0 || encrypted_uri_whole_user_part != 0;
  }
};

}  // namespace mcxanon::mikey
