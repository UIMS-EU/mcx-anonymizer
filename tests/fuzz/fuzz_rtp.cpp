// SPDX-License-Identifier: GPL-3.0-or-later
// One RTP packet through the rule-driven rewriter (FR-005 to FR-010). The first byte selects
// SRTP. A kept packet has the length of the input (the payload is zeroed in place).
#include "fuzz_media_common.hpp"
#include "media/rtp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  fuzz::MediaEnv env;
  const mcxanon::ByteView p(data + 1, size - 1);
  auto r = mcxanon::media::rewrite_rtp(p, (data[0] & 1) != 0, fuzz::media_rules(), env.mapper, env.media_counters);
  if (r && *r && (*r)->size() != p.size()) std::abort();
  return 0;
}
