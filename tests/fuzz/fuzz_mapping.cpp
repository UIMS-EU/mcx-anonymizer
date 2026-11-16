// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/mapping.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  auto m = mcxanon::Mapping::from_json(text);
  if (m) {
    // A loaded mapping serialises and loads back to the same document.
    const auto j = m->to_json();
    auto again = mcxanon::Mapping::from_json(j);
    if (!again || again->to_json() != j) std::abort();
  }
  return 0;
}
