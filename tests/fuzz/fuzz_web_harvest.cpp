// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's web harvest and output carriers (feature 007, FR-024): any payload
// in two directions is harvested without a crash into bounded tokens, the same for the same input;
// the carrier finder returns spans inside the payload.
#include "scan/walker/web_carriers.hpp"
#include "scan/walker/web_harvest.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

using namespace mcxanon::scan::detail;

namespace {

std::size_t harvest(std::span<const std::uint8_t> p) {
  WebHarvest h;
  const std::vector<std::uint8_t> a{1, 2, 3, 4, 0, 80, 1, 1, 1, 1, 0, 1};
  const std::vector<std::uint8_t> b{1, 1, 1, 1, 0, 1, 1, 2, 3, 4, 0, 80};
  const std::size_t half = p.size() / 2;
  h.feed(p.subspan(0, half), a);
  h.feed(p.subspan(half), b);
  h.feed(p, a);
  h.text(std::string_view(reinterpret_cast<const char*>(p.data()), p.size()));
  return h.take().size();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> p(data, size);
  const std::size_t n = harvest(p);
  if (n > 4 * size + 64) std::abort();
  if (harvest(p) != n) std::abort();
  for (const auto& c : find_web_carriers(p)) {
    if (c.offset > size || c.length > size - c.offset) std::abort();
  }
  return 0;
}
