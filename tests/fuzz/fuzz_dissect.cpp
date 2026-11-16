// SPDX-License-Identifier: GPL-3.0-or-later
// Dissector: fields always cover the packet exactly once, whatever the bytes.
#include "dissect/packet.hpp"

#include <array>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 1) return 0;
  constexpr std::array<std::uint16_t, 8> kLinks{0, 1, 101, 113, 228, 229, 276, 127};
  const std::uint16_t lt = kLinks[data[0] % kLinks.size()];
  mcxanon::DissectOptions o;
  o.fcs_len = (data[0] & 0x80) ? 4 : 0;
  const mcxanon::ByteView pkt(data + 1, size - 1);
  const auto d = mcxanon::dissect(lt, pkt, o);
  std::size_t at = 0;
  for (const auto& f : d.fields) {
    if (f.offset != at || f.length == 0) std::abort();
    at += f.length;
  }
  if (at != pkt.size()) std::abort();
  return 0;
}
