// SPDX-License-Identifier: GPL-3.0-or-later
#include "fuzz_capture_common.hpp"

#include <array>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  // Force the pcap path: prepend a valid little-endian header magic.
  std::vector<std::uint8_t> buf{0xD4, 0xC3, 0xB2, 0xA1};
  buf.insert(buf.end(), data, data + size);
  mcxanon::fuzz::read_capture(buf.data(), buf.size());
  mcxanon::fuzz::read_capture(data, size);
  return 0;
}
