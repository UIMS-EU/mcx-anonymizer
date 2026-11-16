// SPDX-License-Identifier: GPL-3.0-or-later
// One RTCP datagram through the tiling rewriter (FR-011 to FR-014, FR-024): compound,
// reduced-size and the SRTCP view. The first byte selects SRTCP. The output is either the SRTCP
// view (the input's length) or packets that tile it exactly: version 2, each length in 32-bit
// words minus one (RFC 3550 §6.4.1). Its length can differ from the input's, since an APP URI
// takes its pseudonym's length and an APP packet without rules is removed.
#include "fuzz_media_common.hpp"

#include <cstdlib>

namespace {
bool tiles(const mcxanon::Bytes& b) {
  std::size_t off = 0;
  while (off < b.size()) {
    if (b.size() - off < 4 || (b[off] >> 6) != 2) return false;
    off += 4 * (std::size_t{1} + ((std::size_t{b[off + 2]} << 8) | b[off + 3]));
  }
  return off == b.size();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  fuzz::MediaEnv env;
  const mcxanon::ByteView p(data + 1, size - 1);
  auto r = mcxanon::media::rewrite_rtcp(p, (data[0] & 1) != 0, env.rtcp);
  if (r && *r && (*r)->size() != p.size() && !tiles(**r)) std::abort();
  return 0;
}
