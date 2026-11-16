// SPDX-License-Identifier: GPL-3.0-or-later
#include "mikey/keyparams.hpp"

namespace mcxanon::mikey {

namespace {

// Message Type (1), Date and Time (5), Payload ID (4), Payload sequence number (1), Payload
// algorithm (1): 12 octets before the optional Signalling algorithm.
constexpr std::size_t kFixedHead = 12;

std::optional<KeyParams> layout(ByteView d, std::uint32_t csb_id, bool signalling) {
  KeyParams k;
  k.signalling = signalling;
  k.iv_off = kFixedHead + (signalling ? 1 : 0);
  k.dppk_off = k.iv_off + kKpIvLen;
  const std::size_t tlv = k.dppk_off + 4;
  if (d.size() < tlv + 3) return std::nullopt;
  const std::uint32_t dppk = (std::uint32_t{d[k.dppk_off]} << 24) | (std::uint32_t{d[k.dppk_off + 1]} << 16) |
                             (std::uint32_t{d[k.dppk_off + 2]} << 8) | d[k.dppk_off + 3];
  if (dppk != csb_id) return std::nullopt;
  // TLV-E (TS 24.379 Annex I): IEI (1), length (2), value.
  k.payload_off = tlv + 3;
  k.payload_len = (std::size_t{d[tlv + 1]} << 8) | d[tlv + 2];
  std::size_t end = k.payload_off + k.payload_len;
  if (end > d.size()) return std::nullopt;
  if (end == d.size()) return k;
  if (d.size() - end < 3) return std::nullopt;
  const std::size_t len = (std::size_t{d[end + 1]} << 8) | d[end + 2];
  if (end + 3 + len != d.size()) return std::nullopt;
  k.i_message = std::pair{end + 3, len};
  return k;
}

}  // namespace

std::optional<KeyParams> delimit_key_parameters(ByteView data, std::uint32_t csb_id) {
  auto a = layout(data, csb_id, false);
  auto b = layout(data, csb_id, true);
  if (a && b) return std::nullopt;
  return a ? a : b;
}

}  // namespace mcxanon::mikey
