// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's XML harvester on any input: it never fails, returns bounded values, and gives the
// same values for the same text; it is also fed through the SIP harvester (which calls it for
// payloads that carry a SIP message).
#include "scan/walker/sip_harvest.hpp"
#include "scan/walker/xml_harvest.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace mcxanon::scan::detail;
  const std::string text = "MESSAGE sip:x@example.net SIP/2.0\r\n\r\n" +
                           std::string(reinterpret_cast<const char*>(data), size);
  const auto a = harvest_xml(text);
  if (a.size() > 4096) std::abort();
  for (const auto& v : a) {
    if (v.empty() || v.size() > text.size() + 2) std::abort();  // a value, or a name with "<", ":" and an end
  }
  if (harvest_xml(text) != a) std::abort();
  SipHarvest h;
  h.feed({reinterpret_cast<const std::uint8_t*>(text.data()), text.size()}, {}, false);
  (void)h.take();
  return 0;
}
