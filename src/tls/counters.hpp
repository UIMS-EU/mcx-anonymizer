// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the TLS layer did in one run (feature 007, report format 6).
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace mcxanon::tls {

using Actions = std::map<std::string, std::map<std::string, std::uint64_t>>;

struct Counters {
  std::uint64_t connections = 0;  // directions with a TLS session
  std::map<std::string, std::uint64_t> records;     // content type name -> count
  std::uint64_t protected_zeroed = 0;               // protected records zeroed
  std::map<std::string, std::uint64_t> handshakes;  // handshake type name -> count
  Actions extensions;                               // extension name -> action -> count
  std::uint64_t server_names = 0;
  std::map<std::string, std::uint64_t> psk_identities;  // opaque, b-tid, zeroed
  std::uint64_t certificates_rewritten = 0;
  std::map<std::string, std::uint64_t> certificates_zeroed;  // reason -> count
  std::map<std::string, std::uint64_t> alerts;               // level/description -> count
  std::map<std::string, std::uint64_t> zero_rest;            // reason -> directions
  Actions x509;  // attribute or extension name -> action -> count

  static void bump(std::map<std::string, std::uint64_t>& m, std::string_view k, std::uint64_t n = 1) {
    m[std::string(k)] += n;
  }
  static void bump(Actions& a, std::string_view k, std::string_view action) { a[std::string(k)][std::string(action)] += 1; }
};

}  // namespace mcxanon::tls
