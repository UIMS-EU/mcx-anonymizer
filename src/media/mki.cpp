// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/mki.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace mcxanon::media {

namespace {

std::uint32_t word(ByteView b, std::size_t at) {
  return (std::uint32_t{b[at]} << 24) | (std::uint32_t{b[at + 1]} << 16) | (std::uint32_t{b[at + 2]} << 8) | b[at + 3];
}

}  // namespace

Result<void> rewrite_mki(ByteView in, Bytes& out, std::size_t min_off, bool srtcp, const sip::KeyContext* keys,
                         AddressMapper& mapper, MediaCounters& counters) {
  const auto known = [&](std::uint32_t w) {
    if (keys != nullptr && std::find(keys->key_ids.begin(), keys->key_ids.end(), w) != keys->key_ids.end()) return true;
    return mapper.find_key_id(w).has_value();
  };
  // A 4-octet MKI: the PCK-ID or the GMK-ID on SRTP (TS 33.180 §7.4.1, §7.4.2); on SRTCP also the
  // key of floor control (CSK, SPK, MKFC, MSCCK, MuSiK; §9.4.6). An 8-octet MKI is GMK-ID || GUK-ID.
  const auto fits = [&](std::uint32_t w, std::size_t len) {
    const unsigned tag = w >> 28;
    if (len == 8) return tag == 0;
    return srtcp ? tag <= 6 : tag <= 1;
  };
  std::vector<std::size_t> tags;
  const auto& t = keys == nullptr ? std::optional<std::size_t>{} : srtcp ? keys->srtcp_tag : keys->srtp_tag;
  if (t) {
    tags.push_back(*t);
  } else {
    tags = {0, 4};
  }
  struct Candidate {
    std::size_t off;
    std::size_t len;
  };
  std::vector<Candidate> found;
  for (const std::size_t tag : tags) {
    for (const std::size_t len : {std::size_t{8}, std::size_t{4}}) {
      if (in.size() < tag + len || in.size() - tag - len < min_off) continue;
      const std::size_t off = in.size() - tag - len;
      bool ok = true;
      for (std::size_t i = 0; i < len && ok; i += 4) {
        const auto w = word(in, off + i);
        ok = fits(w, len) && known(w);
      }
      // An 8-octet MKI contains the 4-octet one that ends where it ends (GMK-ID || GUK-ID holds a
      // GUK-ID with tag 0): per end position only the longest match counts.
      if (ok && std::none_of(found.begin(), found.end(), [&](const Candidate& c) { return c.off + c.len == off + len; })) {
        found.push_back({off, len});
      }
    }
  }
  if (found.size() > 1) {
    ++counters.mki.ambiguous;
    return {};
  }
  if (found.empty()) {
    if (keys != nullptr && !keys->empty()) ++counters.mki.unmatched;
    return {};
  }
  for (std::size_t i = 0; i < found[0].len; i += 4) {
    auto p = mapper.key_id(word(in, found[0].off + i));
    if (!p) return std::unexpected(p.error());
    for (std::size_t k = 0; k < 4; ++k) out[found[0].off + i + k] = static_cast<std::uint8_t>(*p >> (24 - 8 * k));
  }
  ++counters.mki.pseudonymised;
  return {};
}

}  // namespace mcxanon::media
