// SPDX-License-Identifier: GPL-3.0-or-later
//
// State shared by the two directions of one TCP connection (feature 007): the
// HTTP/1.1 requests that await a response (RFC 9112 §6.3 needs the request method to delimit a
// response), the upgrades the client asked for, and the TLS version and cipher suite the server
// selected (the TLS 1.2 ClientKeyExchange is parsed by the suite's key exchange). The web and TLS
// sessions of both directions hold it; it dies with the last of them.
#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>

namespace mcxanon::stream {

struct Connection {
  std::deque<std::string> methods;  // HTTP/1.1 request methods awaiting a final response
  bool h2_preface = false;          // the client sent the HTTP/2 connection preface
  bool upgrade_h2c = false;         // the client asked for an h2c upgrade
  bool upgrade_websocket = false;   // the client asked for a WebSocket upgrade
  std::optional<std::uint16_t> tls_version;  // selected by the ServerHello
  std::optional<std::uint16_t> tls_suite;
};

}  // namespace mcxanon::stream
