// SPDX-License-Identifier: GPL-3.0-or-later
// SDP to the media endpoint table: an SDP body through the rewriter, its media
// descriptions into a small table (so that eviction runs), then lookups of the announced
// endpoints and of keys built from the input. The table never exceeds its bound.
#include "fuzz_sip_common.hpp"
#include "media/endpoints.hpp"
#include "sip/sdp.hpp"

#include <variant>

namespace {
struct Sink : mcxanon::sip::MediaSink {
  mcxanon::media::EndpointTable table{8};
  std::uint64_t ts = 0;
  void announce(const mcxanon::sip::SdpMedia& m) override {
    const auto a = mcxanon::media::from_sdp(m);
    if (const auto* r = std::get_if<mcxanon::media::SkipReason>(&a)) {
      table.skip(*r);
      return;
    }
    for (const auto& e : std::get<std::vector<mcxanon::media::Announcement>>(a)) {
      table.announce(e, ++ts);
      const mcxanon::media::EndpointKey k{e.address, e.port, e.transport};
      (void)table.lookup(k, k, ++ts);
    }
  }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  fuzz::SipEnv env;
  Sink sink;
  env.ctx.media = &sink;
  (void)mcxanon::sip::rewrite_sdp(fuzz::text(data, size), env.ctx);
  for (std::size_t i = 0; i + 6 <= size; i += 6) {
    const auto a = mcxanon::media::Address::v4({data[i], data[i + 1], data[i + 2], data[i + 3]});
    const mcxanon::media::EndpointKey k{a, static_cast<std::uint16_t>((data[i + 4] << 8) | data[i + 5]),
                                        mcxanon::media::Transport::udp};
    (void)sink.table.lookup(k, k, ++sink.ts);
  }
  if (sink.table.size() > sink.table.max_endpoints()) std::abort();
  return 0;
}
