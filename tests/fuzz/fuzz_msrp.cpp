// SPDX-License-Identifier: GPL-3.0-or-later
// MSRP framing and the rule-driven rewrite (FR-026 to FR-028). The input is framed as a TCP
// stream would be; each framed message, and the whole input, is rewritten. The content and the
// end-line keep their length, which the TCP offset map relies on.
#include "fuzz_media_common.hpp"
#include "media/msrp.hpp"

namespace {
void rewrite(std::string_view m, fuzz::MediaEnv& env) {
  auto r = mcxanon::media::rewrite_msrp(m, fuzz::media_rules(), env.ctx, env.mapper, env.media_counters);
  if (!r || r->zeroed) return;
  if (r->head_orig > m.size() || r->head_out > r->bytes.size()) std::abort();
  if (r->bytes.size() - r->head_out != m.size() - r->head_orig) std::abort();
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  fuzz::MediaEnv env;
  std::string_view in = fuzz::text(data, size);
  rewrite(in, env);
  while (!in.empty()) {
    const auto f = mcxanon::media::msrp_frame(in);
    if (f.kind != mcxanon::media::MsrpFrameKind::message) break;
    if (f.len == 0 || f.len > in.size()) std::abort();
    rewrite(in.substr(0, f.len), env);
    in.remove_prefix(f.len);
  }
  return 0;
}
