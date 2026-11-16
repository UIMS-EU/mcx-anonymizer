// SPDX-License-Identifier: GPL-3.0-or-later
// HPACK (RFC 7541; feature 007): any header block either fails to decode or decodes
// into fields whose re-encoding (literals without indexing) decodes again to the same fields; the
// Huffman decoder never crashes and its output re-encodes to a string that decodes back.
#include "http/hpack.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view b(reinterpret_cast<const char*>(data), size);
  http::HpackDecoder dec;
  const auto fields = dec.decode(b);
  if (fields) {
    // A second block on the same decoder exercises the dynamic table the first one built.
    (void)dec.decode(b);
    const auto again = http::HpackDecoder{}.decode(http::hpack_encode(*fields));
    if (!again || again->size() != fields->size()) std::abort();
    for (std::size_t i = 0; i < fields->size(); ++i) {
      if ((*again)[i].name != (*fields)[i].name || (*again)[i].value != (*fields)[i].value) std::abort();
    }
  }
  if (const auto h = http::huffman_decode(b)) {
    const auto back = http::huffman_decode(http::huffman_encode(*h));
    if (!back || *back != *h) std::abort();
  }
  return 0;
}
