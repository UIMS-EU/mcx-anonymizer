// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's media harvester (feature 004): the input as one UDP payload (RTCP, APP) and as
// one TCP payload (MSRP), into the shared harvest.
#include "scan/walker/media_harvest.hpp"
#include "scan/walker/sip_harvest.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  mcxanon::scan::detail::SipHarvest sip;
  mcxanon::scan::detail::MediaHarvest h(sip);
  h.feed_udp(in);
  h.feed_tcp(in);
  (void)sip.take();
  return 0;
}
