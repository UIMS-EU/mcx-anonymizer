// SPDX-License-Identifier: GPL-3.0-or-later
//
// The TLS session of one TCP direction (feature 007, FR-018 to FR-023): records are
// framed by their headers; consecutive handshake records in the clear form one unit that ends
// where a record end coincides with a message end, and are re-fragmented after the rewrite;
// change_cipher_spec and alerts in the clear are kept; every protected record (after a
// change_cipher_spec of the same direction, and every application data record) keeps its header
// with zeroed content. A record that is not TLS zeroes the rest of the direction.
#pragma once

#include "stream/connection.hpp"
#include "stream/tcp.hpp"
#include "tls/env.hpp"

#include <memory>
#include <optional>
#include <string_view>

namespace mcxanon::tls {

std::unique_ptr<stream::Session> open_tls_session(Env& env, std::shared_ptr<stream::Connection> connection);

// A plausible TLS record header at the front of `b` (types 20-23, version 3.x, a bounded length);
// nullopt when more bytes are needed.
std::optional<bool> is_record_start(std::string_view b);

}  // namespace mcxanon::tls
