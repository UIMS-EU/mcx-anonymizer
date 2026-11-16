// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/rtp.hpp"

#include "media/mki.hpp"

#include <algorithm>
#include <cstdio>
#include <string>

namespace mcxanon::media {
namespace {

std::uint32_t be32(const Bytes& b, std::size_t off) {
  return (std::uint32_t{b[off]} << 24) | (std::uint32_t{b[off + 1]} << 16) | (std::uint32_t{b[off + 2]} << 8) |
         b[off + 3];
}

void put32(Bytes& b, std::size_t off, std::uint32_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 24);
  b[off + 1] = static_cast<std::uint8_t>(v >> 16);
  b[off + 2] = static_cast<std::uint8_t>(v >> 8);
  b[off + 3] = static_cast<std::uint8_t>(v);
}

void zero(Bytes& b, std::size_t from, std::size_t to) {
  std::fill(b.begin() + static_cast<std::ptrdiff_t>(from), b.begin() + static_cast<std::ptrdiff_t>(to), std::uint8_t{0});
}

std::string hex8(std::uint32_t v) {
  char buf[9];
  std::snprintf(buf, sizeof buf, "%08x", v);
  return buf;
}

// Header extension body [begin, end): RFC 5285 §4.2 (one-byte) and §4.3 (two-byte) element
// walks keep IDs, lengths and padding and zero the data. False when an element overruns.
bool rewrite_elements(Bytes& b, std::uint16_t profile, std::size_t begin, std::size_t end) {
  if (profile == 0xBEDE) {
    for (std::size_t i = begin; i < end;) {
      const std::uint8_t h = b[i];
      if (h == 0) {  // padding
        ++i;
        continue;
      }
      const unsigned id = h >> 4;
      if (id == 15) {  // reserved: the extension ends here (§4.2)
        zero(b, i, end);
        return true;
      }
      const std::size_t len = (h & 0x0Fu) + 1u;
      if (i + 1 + len > end) return false;
      zero(b, i + 1, i + 1 + len);
      i += 1 + len;
    }
    return true;
  }
  if ((profile & 0xFFF0u) == 0x1000u) {
    for (std::size_t i = begin; i < end;) {
      if (b[i] == 0) {  // padding
        ++i;
        continue;
      }
      if (i + 2 > end) return false;
      const std::size_t len = b[i + 1];
      if (i + 2 + len > end) return false;
      zero(b, i + 2, i + 2 + len);
      i += 2 + len;
    }
    return true;
  }
  zero(b, begin, end);  // another profile: not understood
  return true;
}

}  // namespace

Result<std::optional<Bytes>> rewrite_rtp(ByteView packet, bool secure, const MediaRuleSet& rules,
                                         AddressMapper& mapper, MediaCounters& counters, const sip::KeyContext* keys) {
  const auto zeroed = [&](const char* why) -> Result<std::optional<Bytes>> {
    ++counters.rtp_zeroed[why];
    return std::optional<Bytes>{};
  };
  if (rules.rtp.empty()) return zeroed("no-rules");
  // RFC 3550 §5.1 and §A.1: version 2, the CSRC list and the extension inside the packet.
  if (packet.size() < 12 || (packet[0] >> 6) != 2) return zeroed("malformed");
  Bytes b(packet.begin(), packet.end());
  const bool padding = (b[0] & 0x20) != 0;
  const bool extension = (b[0] & 0x10) != 0;
  const std::size_t cc = b[0] & 0x0Fu;
  std::size_t hdr = 12 + 4 * cc;
  if (hdr > b.size()) return zeroed("malformed");
  std::size_t ext_begin = 0, ext_end = 0;
  std::uint16_t profile = 0;
  if (extension) {
    if (hdr + 4 > b.size()) return zeroed("malformed");
    profile = static_cast<std::uint16_t>((b[hdr] << 8) | b[hdr + 1]);
    const std::size_t words = static_cast<std::size_t>((b[hdr + 2] << 8) | b[hdr + 3]);
    ext_begin = hdr + 4;
    ext_end = ext_begin + 4 * words;
    if (ext_end > b.size()) return zeroed("malformed");
    hdr = ext_end;
  }
  std::size_t pad = 0;
  if (padding && !secure) {
    // RFC 3550 §5.1: the last octet counts the padding octets, itself included.
    pad = b.back();
    if (pad == 0 || hdr + pad > b.size()) return zeroed("malformed");
  }
  // SSRC and CSRCs (FR-005): the project-wide SSRC mapping.
  for (std::size_t off = 8; off < 12 + 4 * cc; off += 4) {
    auto m = mapper.ssrc(be32(b, off));
    if (!m) return std::unexpected(m.error());
    put32(b, off, *m);
  }
  if (extension && !rewrite_elements(b, profile, ext_begin, ext_end)) {
    zero(b, ext_begin, ext_end);
    ++counters.rtp_zeroed["extension"];
  }
  if (secure) {
    // SRTP (FR-025): the encrypted portion, the MKI and the authentication tag, one block; the
    // MKI alone may carry key identifier pseudonyms (feature 005, FR-012a).
    zero(b, hdr, b.size());
    if (auto m = rewrite_mki(packet, b, hdr, false, keys, mapper, counters); !m) return std::unexpected(m.error());
  } else {
    zero(b, hdr, b.size() - pad);                       // the payload (FR-007, FR-008)
    if (pad > 1) zero(b, b.size() - pad, b.size() - 1);  // padding octets; the count stays (P2)
  }
  ++counters.rtp_packets;
  ++counters.rtp_by_payload_type[std::to_string(b[1] & 0x7Fu)];
  ++counters.rtp_by_stream[hex8(be32(b, 8))];
  return std::optional<Bytes>(std::move(b));
}

}  // namespace mcxanon::media
