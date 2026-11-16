// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's own MIKEY code (feature 005, FR-022, FR-018): the MIKEY walker, the
// carrier locator and the passthrough locator over arbitrary bytes, and the SIP harvester that
// hands carriers and key references to them. Nothing may crash, hang or trip a sanitizer; every
// located range lies inside the input; equal inputs give equal results.
#include "scan/walker/mikey_carriers.hpp"
#include "scan/walker/mikey_harvest.hpp"
#include "scan/walker/passthrough.hpp"
#include "scan/walker/sip_harvest.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

using namespace mcxanon::scan::detail;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  const auto v = walk_mikey(in);
  const auto again = walk_mikey(in);
  if (v.uris != again.uris || v.keys != again.keys || v.bytes != again.bytes) std::abort();
  for (const auto& c : find_mikey_carriers(in)) {
    if (c.offset > size || c.length > size - c.offset) std::abort();
    (void)walk_mikey(c.decoded);
  }
  for (const auto& r : passthrough_ranges(in)) {
    if (r.offset > size || r.length > size - r.offset) std::abort();
  }
  SipHarvest h;
  h.feed(in, {}, false);
  (void)h.take();
  return 0;
}
