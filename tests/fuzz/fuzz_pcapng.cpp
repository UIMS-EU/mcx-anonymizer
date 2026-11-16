// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/pcapng.hpp"
#include "fuzz_capture_common.hpp"

#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  // Force the pcapng path: prepend an SHB block type.
  std::vector<std::uint8_t> buf{0x0A, 0x0D, 0x0D, 0x0A};
  buf.insert(buf.end(), data, data + size);
  mcxanon::fuzz::read_capture(buf.data(), buf.size());
  // Option lists in both byte orders, and their round trip.
  for (auto e : {mcxanon::Endian::little, mcxanon::Endian::big}) {
    auto opts = mcxanon::parse_options(mcxanon::ByteView(data, size), e);
    if (opts) {
      auto again = mcxanon::parse_options(mcxanon::serialize_options(*opts, e), e);
      if (!again || *again != *opts) std::abort();
    }
  }
  return 0;
}
