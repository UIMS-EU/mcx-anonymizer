// SPDX-License-Identifier: GPL-3.0-or-later
// An SDP body through the rule-driven rewriter.
#include "fuzz_sip_common.hpp"
#include "sip/sdp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  fuzz::SipEnv env;
  (void)mcxanon::sip::rewrite_sdp(fuzz::text(data, size), env.ctx);
  return 0;
}
