// SPDX-License-Identifier: GPL-3.0-or-later
// A multipart body with a fuzzed boundary: the first byte gives the boundary length, the
// boundary follows; the rest is the body, parsed directly and inside a SIP MESSAGE.
#include "fuzz_sip_common.hpp"
#include "sip/multipart.hpp"
#include "sip/rewrite.hpp"

#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  const std::size_t blen = std::min<std::size_t>(data[0] % 72, size - 1);
  const std::string boundary(reinterpret_cast<const char*>(data + 1), blen);
  const auto body = fuzz::text(data + 1 + blen, size - 1 - blen);
  (void)mcxanon::sip::parse_multipart(body, boundary);
  const std::string msg = "MESSAGE sip:a@example.net SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n"
                          "From: <sip:b@example.net>;tag=1\r\nTo: <sip:a@example.net>\r\nCall-ID: f1\r\n"
                          "CSeq: 1 MESSAGE\r\nContent-Type: multipart/mixed;boundary=\"" + boundary +
                          "\"\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
  fuzz::SipEnv env;
  (void)mcxanon::sip::rewrite_message(msg, mcxanon::sip::Transport::datagram, env.ctx);
  return 0;
}
