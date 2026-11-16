// SPDX-License-Identifier: GPL-3.0-or-later
//
// TLS handshake messages in the clear (RFC 8446 §4, RFC 5246 §7.4; feature 007 FR-019 to FR-023):
// each message body rewritten by the rule of its type. Every length inside a
// message is recomputed; anything that does not parse is zeroed with its type and length kept.
#pragma once

#include "mcxanon/error.hpp"

#include "stream/connection.hpp"
#include "tls/env.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace mcxanon::tls {

// The rewritten message (type, 24-bit length and body).
Result<std::string> rewrite_handshake(std::uint8_t type, std::string_view body, stream::Connection& conn, Env& env);

// Exposed for tests and fuzzing: hello bodies (client: ClientHello).
Result<std::string> rewrite_hello(std::string_view body, bool client, stream::Connection& conn, Env& env);

}  // namespace mcxanon::tls
