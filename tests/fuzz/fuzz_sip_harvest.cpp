// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's SIP harvester: the input is cut into two TCP segments of one direction (the
// first byte gives the cut) and also fed as one UDP payload.
#include "scan/walker/sip_harvest.hpp"

#include <cstddef>
#include <cstdint>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  const std::span<const std::uint8_t> in(data + 1, size - 1);
  const std::size_t cut = std::min<std::size_t>(data[0] * 16u, in.size());
  mcxanon::scan::detail::SipHarvest h;
  const std::vector<std::uint8_t> dir{1, 2, 3, 4};
  h.feed(in.first(cut), dir, true);
  h.feed(in.subspan(cut), dir, true);
  h.feed(in, {}, false);
  (void)h.take();
  return 0;
}
