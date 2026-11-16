// SPDX-License-Identifier: GPL-3.0-or-later
// JSON (RFC 8259; feature 007, FR-010): any text either fails to parse (depth, size and syntax
// bounds) or parses into a value whose writing parses again and writes identically.
#include "http/json.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto j = http::parse_json(std::string_view(reinterpret_cast<const char*>(data), size));
  if (!j) return 0;
  const std::string once = http::write_json(*j);
  const auto again = http::parse_json(once);
  if (!again || http::write_json(*again) != once) std::abort();
  return 0;
}
