// SPDX-License-Identifier: GPL-3.0-or-later
// One SIP message: framing on both transports and the rule-driven rewrite. The rewritten bytes
// must parse again unless the message was zeroed.
#include "fuzz_sip_common.hpp"
#include "sip/message.hpp"
#include "sip/rewrite.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace mcxanon::sip;
  const auto in = fuzz::text(data, size);
  (void)parse_message(in, Transport::stream);
  (void)frame_stream(in);
  (void)is_start_line(in);
  fuzz::SipEnv env;
  auto r = rewrite_message(in, Transport::datagram, env.ctx);
  if (r && r->malformed != Malformed::message) {
    if (!parse_message(r->bytes, Transport::datagram)) std::abort();
    if (map_offset(r->offset_map, in.size()) != r->bytes.size()) std::abort();
  }
  return 0;
}
