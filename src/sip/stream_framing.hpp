// SPDX-License-Identifier: GPL-3.0-or-later
//
// SIP over a byte stream (RFC 3261 §18.3): recognising the start of a message
// before its first line is complete, and framing messages, keep-alive CRLFs (RFC 5626 §3.5.1)
// and oversized messages for the TCP stream layer.
#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

namespace mcxanon::sip {

// True or false once the first line is complete; nullopt while the bytes may still become a
// Request-Line or a Status-Line.
std::optional<bool> stream_start(std::string_view data);

struct StreamFrame {
  enum class Kind { more, message, verbatim, invalid, oversized };
  Kind kind = Kind::more;
  std::size_t len = 0;  // message length, keep-alive bytes, or an oversized message's declared length
};

StreamFrame stream_frame(std::string_view data);

}  // namespace mcxanon::sip
