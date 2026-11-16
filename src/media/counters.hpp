// SPDX-License-Identifier: GPL-3.0-or-later
//
// Counters of the media layer.
// Keys are packet types, names, subtypes, field IDs, rule header names or fixed reason words:
// never an input value.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mcxanon::media {

using CountMap = std::map<std::string, std::uint64_t>;
using ActionMap = std::map<std::string, std::map<std::string, std::uint64_t>>;

// Feature 005: the SRTP and SRTCP MKIs.
struct MkiCounters {
  std::uint64_t pseudonymised = 0;
  std::uint64_t unmatched = 0;
  std::uint64_t ambiguous = 0;
};

struct MediaCounters {
  // RTP
  std::uint64_t rtp_packets = 0;
  CountMap rtp_by_payload_type;
  CountMap rtp_by_stream;  // pseudonymised SSRC (8 hex digits) -> packets
  CountMap rtp_zeroed;     // reason -> packets
  // RTCP
  CountMap rtcp_by_packet_type;
  ActionMap rtcp_feedback;  // "pt/fmt" -> action -> count
  ActionMap rtcp_xr;        // "bt" -> action -> count
  CountMap sdes_removed;    // item name -> count
  CountMap srtcp_view;      // secure / undecodable -> datagrams
  CountMap rtcp_zeroed;     // malformed -> packets whose body is zeroed (FR-032)
  // MCX RTCP APP
  CountMap app_messages;    // "NAME/subtype" -> count
  ActionMap app_fields;     // "family/id" -> action -> count
  CountMap app_unknown;     // name / subtype / field / malformed -> count
  // MSRP
  CountMap msrp_requests;   // method (SEND, REPORT, other) -> count
  CountMap msrp_responses;  // "2xx" ... -> count
  ActionMap msrp_headers;   // rule header name (or "other") -> action -> count
  CountMap msrp_zeroed;     // reason -> messages
  MkiCounters mki;          // feature 005

  // Values removed by a rule (SDES items, BYE reasons, Reject Phrases, Warning Texts, MSRP
  // comments and removed headers): in-memory scan tokens (FR-031), each value once.
  std::vector<std::pair<std::string, std::string>> removed_values;

  void count(ActionMap& m, const std::string& key, std::string_view action, std::uint64_t n = 1) {
    m[key][std::string(action)] += n;
  }
  void removed(std::string_view value) {
    if (value.empty()) return;
    std::string v(value);
    if (removed_seen_.insert(v).second) removed_values.emplace_back("string", std::move(v));
  }

 private:
  std::unordered_set<std::string> removed_seen_;
};

}  // namespace mcxanon::media
