// SPDX-License-Identifier: GPL-3.0-or-later
//
// The web session of one TCP direction (feature 007): HTTP/1.1 messages
// framed by RFC 9112 §6.3 and rewritten by the HTTP rules, with the switches a connection may
// make at a message boundary: h2c (prior knowledge or Upgrade), a CONNECT tunnel (TLS), and a
// WebSocket upgrade (the rest is zeroed).
#pragma once

#include "http/env.hpp"
#include "stream/connection.hpp"
#include "stream/tcp.hpp"

#include <memory>

namespace mcxanon::http {

enum class Start { http1, h2_client, h2_server };

std::unique_ptr<stream::Session> open_web_session(Env& env, std::shared_ptr<stream::Connection> connection,
                                                  Start start);

// The first octets of an HTTP/2 frame that a server sends first (a SETTINGS frame on stream 0,
// RFC 9113 §3.4); nullopt when more bytes are needed.
std::optional<bool> is_h2_server_start(std::string_view b);

}  // namespace mcxanon::http
