// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own RTCP and MCX APP harvester (FR-031): a minimal decoder that
// extracts SSRCs, SDES item values, BYE reasons and APP header SSRCs and text values from input
// UDP payloads that have the RTCP shape (version 2, packet types 200 to 207, packets that tile the
// datagram). It needs no SDP: a payload it takes for RTCP only adds tokens, which is safe. It
// shares no code with the anonymiser's media decoders.
#pragma once

#include "scan/walker/sip_harvest.hpp"

#include <cstdint>
#include <span>

namespace mcxanon::scan::detail {

class MediaHarvest {
 public:
  explicit MediaHarvest(SipHarvest& out) : out_(out) {}
  void feed_udp(std::span<const std::uint8_t> payload);
  // A TCP payload that starts with an MSRP start line (RFC 4975 §9): the transaction id, the
  // Message-ID and the To-Path / From-Path URIs (with their session ids).
  void feed_tcp(std::span<const std::uint8_t> payload);

 private:
  void app(std::span<const std::uint8_t> p);
  SipHarvest& out_;
};

}  // namespace mcxanon::scan::detail
