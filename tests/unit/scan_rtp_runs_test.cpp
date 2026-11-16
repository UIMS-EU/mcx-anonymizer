// SPDX-License-Identifier: GPL-3.0-or-later
//
// Clarification P7 (extends 001/FR-032a): a 4-octet binary match inside an RTP header that the
// scanner's own walker recognises is a suppressed chance match, unless it starts at an SSRC or
// CSRC position, where it is a hit.
#include "mcxanon/scan.hpp"

#include "capture/pcap.hpp"
#include "packet_builder.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
std::filesystem::path pcap_with(const TempDir& tmp, const Bytes& packet) {
  PcapFileHeader h;
  h.linktype = kLinkRaw;
  Bytes file = build_pcap_file_header(h);
  Bytes rec(16);
  store_pcap_packet_header(rec, PcapPacketHeader{1, 2, static_cast<std::uint32_t>(packet.size()),
                                                 static_cast<std::uint32_t>(packet.size())},
                           Endian::little);
  file = file + rec + packet;
  const auto p = tmp.path() / "x.pcap";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  return p;
}

scan::Token ssrc_token(std::uint32_t v) { return {scan::TokenCategory::binary, b32(v), "ssrc:1"}; }

// V=2, CC=1, M=0, PT=96, seq 0x1234, ts 0x56789ABC, SSRC, one CSRC, zeroed payload.
Bytes rtp(std::uint32_t ssrc, std::uint32_t csrc) {
  return Bytes{0x81, 0x60, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC} + b32(ssrc) + b32(csrc) + Bytes(40, 0);
}
}  // namespace

TEST_CASE("a 4-byte token across RTP sequence number and timestamp is a chance match", "[scan][walker][media]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40000, 50000, rtp(0x01020304, 0x05060708)));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0x12345678)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("an original SSRC at the SSRC or CSRC position of an RTP header is a hit", "[scan][walker][media]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40000, 50000, rtp(0xCAFE0001, 0xCAFE0002)));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0xCAFE0001), ssrc_token(0xCAFE0002)});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 2);
}

TEST_CASE("bytes that only look like RTP after the header are not suppressed", "[scan][walker][media]") {
  TempDir tmp;
  // A non-zero payload after the RTP header is not part of the run: a match there is a hit.
  Bytes pkt = rtp(1, 2);
  pkt[30] = 0xDE;
  pkt[31] = 0xAD;
  pkt[32] = 0xBE;
  pkt[33] = 0xEF;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40000, 50000, pkt));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0xDEADBEEF)});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
}

TEST_CASE("a UDP payload that is not RTP-shaped gets no header run", "[scan][walker][media]") {
  TempDir tmp;
  // Version 0: not RTP; the token in it is a hit.
  const Bytes pkt = Bytes{0x01, 0x60, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC} + Bytes(20, 0);
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40000, 50000, pkt));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0x12345678)});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
}

namespace {
// RTCP SR (RFC 3550 §6.4.1): header, sender SSRC, sender info, one report block.
Bytes rtcp_sr(std::uint32_t sender, std::uint32_t block_ssrc) {
  return Bytes{0x81, 200, 0x00, 0x0C} + b32(sender) + b32(0x11223344) + b32(0x55667788) + b32(0x99AABBCC) +
         b32(0x00000100) + b32(0x00010000) + b32(block_ssrc) + b32(0x01000002) + b32(0x0001000A) + b32(0x00000020) +
         b32(0x12345678) + b32(0x00000005);
}
// MCPT Floor Granted with Duration and Message Sequence Number (TS 24.380 §8.1.2, §8.1.3).
Bytes mcpt(std::uint32_t ssrc) {
  return Bytes{0x81, 204, 0x00, 0x04} + b32(ssrc) + text("MCPT") + Bytes{0x01, 0x02, 0x12, 0x34, 0x08, 0x02, 0x56, 0x78};
}
}  // namespace

TEST_CASE("4-byte chance matches inside RTCP report statistics are suppressed", "[scan][walker][media]") {
  TempDir tmp;
  // 0x55667788 is the NTP timestamp's low word: a chance match.
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40001, 50001, rtcp_sr(1 << 20, 2 << 20)));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0x55667788)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("an original SSRC at an RTCP sender or report block SSRC position is a hit", "[scan][walker][media]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40001, 50001, rtcp_sr(0xCAFE0001, 0xCAFE0002)));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0xCAFE0001), ssrc_token(0xCAFE0002)});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 2);
}

TEST_CASE("APP field headers and short values are a header run; the APP SSRC is a value slot", "[scan][walker][media]") {
  TempDir tmp;
  // 0x12340802 spans the Duration value and the next field's header: a chance match.
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40002, 50002, mcpt(0xCAFE0003)));
  auto r = scan::scan_file(p, std::vector{ssrc_token(0x12340802), ssrc_token(0xCAFE0003)});
  REQUIRE(r.has_value());
  REQUIRE(r->hits.size() == 1);
  CHECK(r->hits[0].label == "ssrc:1");
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("XR block headers are a header run; the source SSRC of a block is a value slot", "[scan][walker][media]") {
  TempDir tmp;
  // XR (RFC 3611 §2): header, sender SSRC; BT 6 Statistics Summary: header, SSRC of source,
  // begin/end sequence, then statistics (raw).
  const Bytes xr = Bytes{0x80, 207, 0x00, 0x05} + b32(0x01000001) + Bytes{6, 0xE0, 0x00, 0x03} + b32(0xCAFE0004) +
                   b32(0x00010064) + b32(0x12345678);
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 40001, 50001, xr));
  // 0xE0000300: the block's type-specific octet and length, then the first SSRC octet: a chance match.
  auto r = scan::scan_file(p, std::vector{ssrc_token(0x06E00003), ssrc_token(0xCAFE0004)});
  REQUIRE(r.has_value());
  REQUIRE(r->hits.size() == 1);
  CHECK(r->suppressed_chance_matches == 1);
}
