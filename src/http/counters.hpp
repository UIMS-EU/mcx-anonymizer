// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the HTTP layer did in one run (feature 007, report format 6).
// Counts only: never a value. Header, parameter and JSON member names are protocol vocabulary;
// unknown names are counted as written when they are tokens, otherwise as "(invalid)".
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace mcxanon::http {

using Actions = std::map<std::string, std::map<std::string, std::uint64_t>>;

struct Counters {
  std::uint64_t messages = 0;
  std::map<std::string, std::uint64_t> requests;   // method -> count
  std::map<std::string, std::uint64_t> responses;  // "2xx" -> count
  std::uint64_t malformed = 0;                     // messages zeroed
  std::map<std::string, std::uint64_t> streams;    // http1, h2
  std::map<std::string, std::uint64_t> upgrades;   // h2c, websocket, connect
  std::map<std::string, std::uint64_t> h2_frames;  // frame type name -> count
  std::uint64_t header_blocks = 0;
  std::uint64_t h2_undecodable = 0;
  Actions headers;          // rule name -> action -> count
  Actions removed_unknown;  // http-header / http-param / json-member / jwt-member -> name -> count
  Actions params;           // parameter name -> action -> count
  Actions bodies;           // content type -> handling or removed:<reason> -> count
  std::map<std::string, std::uint64_t> credentials_removed;  // kind -> count
  std::map<std::string, std::uint64_t> tokens;                // jwt, jwe, opaque, malformed-jwt
  std::uint64_t cookie_names = 0;
  std::uint64_t cookie_values_removed = 0;
  std::uint64_t xcap_selectors = 0;
  std::uint64_t xcap_malformed = 0;
  std::uint64_t oauth_messages = 0;
  Actions jwt_claims;  // claim -> action -> count
  std::uint64_t kms_messages = 0;
  std::map<std::string, std::uint64_t> zero_rest;  // reason -> directions

  static void bump(Actions& a, std::string_view key, std::string_view action, std::uint64_t n = 1) {
    a[std::string(key)][std::string(action)] += n;
  }
  static void bump(std::map<std::string, std::uint64_t>& m, std::string_view key, std::uint64_t n = 1) {
    m[std::string(key)] += n;
  }
};

// The name as counted: a token as written (at most 64 characters), otherwise "(invalid)".
std::string counted_name(std::string_view name);

}  // namespace mcxanon::http
