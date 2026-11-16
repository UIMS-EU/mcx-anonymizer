// SPDX-License-Identifier: GPL-3.0-or-later
//
// The media rule set (`ruleset: mcxanon-media`, feature 004): RTP header elements, RTCP packet
// types, SDES items, feedback formats and XR blocks, MCX RTCP APP families, messages and fields,
// and MSRP methods and headers. Every entry cites its source; the loader accepts only the
// documents of the "Media plane" section of rules/SOURCES.md.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/ruleset.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon {

enum class MediaAction { keep, pseudonymise, remove, zero };

// APP field value encodings. Each one is a decoder
// in src/media/app.cpp.
enum class AppEncoding {
  u8,                      // 1 octet
  u16,                     // 2 octets
  u8_spare,                // 1 octet + 1 spare octet
  ssrc_spare,              // 32-bit SSRC + 16 spare bits
  uri,                     // a URI (MCPTT ID, group ID, functional alias, ...)
  uri_list,                // count, then (length, URI) pairs
  ssrc_list,               // count, spare, n x 32-bit SSRC
  reject_cause,            // 16-bit cause + optional Reject Phrase (always removed)
  session_identity,        // 8-bit session type + URI
  track_info,              // TS 24.380 §8.2.3.13 / TS 24.581 §9.2.3.13
  location,                // TS 24.380 §8.2.3.21
  location_list,           // TS 24.380 §8.2.3.22
  subchannel,              // TS 24.380 §8.4.3.3 (MBMS Subchannel)
  mbs_subchannel,          // TS 24.380 §8.6.3.3
  mcvideo_subchannel,      // TS 24.581 §9.3.3.3
  mcvideo_mbs_subchannel,  // TS 24.581 §9.5.3.3
  mcdm_subchannel,         // TS 24.582 §11.2.3.3
  message_name,            // 4 ASCII octets + 16 spare bits (TS 24.581 §9.2.3.18)
  mikey,                   // a MIKEY-SAKKE I_MESSAGE, binary or base64 (TS 24.380 §8.3.3.10, feature 005)
  opaque,                  // not understood: zero or remove only
};

struct AppFieldRule {
  std::uint16_t id = 0;
  std::string name;
  AppEncoding encoding = AppEncoding::opaque;
  MediaAction action = MediaAction::remove;
  Source source;
};

struct AppMessageRule {
  std::string name;
  std::uint8_t subtype = 0;
  bool ack_variant = false;  // subtype + 16 is the acknowledgement-required variant
  Source source;
};

struct AppFamily {
  std::string id;                               // rule namespace, e.g. "mcpt", "mcv-tc"
  std::vector<std::array<char, 4>> names;       // APP names, 4 ASCII octets
  std::map<std::uint8_t, AppMessageRule> messages;  // by subtype (both variants registered)
  std::map<std::uint16_t, AppFieldRule> fields;     // by field ID
  Source source;
  [[nodiscard]] const AppMessageRule* message(std::uint8_t subtype) const;
  [[nodiscard]] const AppFieldRule* field(std::uint16_t id) const;
};

struct MediaItemRule {
  std::string name;
  MediaAction action = MediaAction::zero;
  Source source;
};

struct RtcpRules {
  std::map<std::uint8_t, MediaItemRule> packet_types;  // PT -> keep (decoded) / zero (body)
  std::map<std::uint8_t, MediaItemRule> sdes_items;    // item type -> pseudonymise / remove
  std::map<std::pair<std::uint8_t, std::uint8_t>, MediaItemRule> feedback;  // (PT, FMT)
  std::map<std::uint8_t, MediaItemRule> xr_blocks;     // BT -> keep / zero
  std::optional<MediaItemRule> bye_reason;
};

struct MsrpHeaderRule {
  std::string name;  // as registered, compared case-insensitively
  MediaAction action = MediaAction::remove;
  Source source;
};

struct MsrpRules {
  std::map<std::string, MediaItemRule> methods;    // upper-case method -> keep
  std::map<std::string, MsrpHeaderRule> headers;   // lower-case header name
  std::map<std::string, MediaItemRule> elements;   // tid, content, comment
};

struct MediaRuleSet {
  std::string name;
  std::string version;
  std::string digest;
  std::map<std::string, MediaItemRule> rtp;  // RTP element -> action
  RtcpRules rtcp;
  std::vector<AppFamily> app;
  MsrpRules msrp;

  [[nodiscard]] const AppFamily* family_by_name(std::string_view name4) const;
  [[nodiscard]] const AppFamily* family_by_id(std::string_view id) const;
};

// The RTP elements every rule set must classify, each with its only allowed action.
std::span<const std::pair<std::string_view, MediaAction>> rtp_elements();

std::string_view to_string(MediaAction a);
std::string_view to_string(AppEncoding e);

Result<MediaRuleSet> load_media_ruleset(std::span<const RuleFile> files);
Result<MediaRuleSet> load_embedded_media_ruleset();
std::string_view embedded_media_ruleset_digest();

}  // namespace mcxanon
