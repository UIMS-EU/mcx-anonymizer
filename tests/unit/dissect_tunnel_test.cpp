// SPDX-License-Identifier: GPL-3.0-or-later
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

TEST_CASE("GRE with checksum, key and sequence carrying IPv4", "[dissect][tunnel]") {
  const Bytes inner = udp4(kIpB, kIpA, 1, 2, text("in"));
  const Bytes gre = b16(0xB000) + b16(0x0800) + b16(0) + b16(0) + b32(42) + b32(7) + inner;
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 47, gre));
  CHECK(find(d, Fid::gre_checksum) != nullptr);
  CHECK(find(d, Fid::gre_key) != nullptr);
  CHECK(find(d, Fid::gre_seq) != nullptr);
  CHECK(count(d, Fid::ipv4_src) == 2);
  CHECK(find(d, Fid::payload_l7)->length == 2);
}

TEST_CASE("GRE transparent Ethernet bridging", "[dissect][tunnel]") {
  const Bytes frame = eth(kMacB, kMacA, 0x0800, udp4(kIpB, kIpA, 1, 2, {}));
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 47, b16(0) + b16(0x6558) + frame));
  CHECK(find(d, Fid::eth_src) != nullptr);
  CHECK(count(d, Fid::ipv4_src) == 2);
}

TEST_CASE("GRE with an unknown protocol", "[dissect][tunnel]") {
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 47, b16(0) + b16(0x88BE) + Bytes(10, 1)));
  CHECK(has_unknown(d, "gre_proto", 0x88BE));
}

TEST_CASE("IP-in-IP", "[dissect][tunnel]") {
  const auto d4 = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 4, udp4(kIpB, kIpA, 1, 2, {})));
  CHECK(count(d4, Fid::ipv4_src) == 2);
  const auto d6 = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 41, ipv6(kIp6A, kIp6B, 59, {})));
  CHECK(find(d6, Fid::ipv6_src) != nullptr);
}

TEST_CASE("GTP-U G-PDU with a PDU Session Container and an unknown extension", "[dissect][tunnel]") {
  const Bytes inner = ipv6(kIp6A, kIp6B, 17, udp(5000, 6000, text("voice"), 0));
  const Bytes ext = Bytes{1, 0x09, 0x05, 0x99} + Bytes{1, 0xAB, 0xCD, 0x00};  // 0x85 then 0x99
  Bytes gtp = Bytes{0x34, 0xFF} + b16(static_cast<std::uint16_t>(4 + ext.size() + inner.size())) +
              b32(0x1000) + Bytes{0, 0, 0, 0x85} + ext + inner;
  const auto d = dissect_checked(kLinkRaw, udp4(kIpA, kIpB, 2152, 2152, gtp));
  CHECK(find(d, Fid::gtpu_teid) != nullptr);
  CHECK(find(d, Fid::gtpu_ext_pdu_session) != nullptr);
  CHECK(find(d, Fid::gtpu_ext_other) != nullptr);
  CHECK(has_unknown(d, "gtpu_ext", 0x99));
  CHECK(find(d, Fid::ipv6_src) != nullptr);
  CHECK(find(d, Fid::payload_l7)->length == 5);
}

TEST_CASE("GTP-U signalling messages are payload", "[dissect][tunnel]") {
  const Bytes echo = Bytes{0x32, 0x01} + b16(4) + b32(0) + Bytes{0, 1, 0, 0};
  const auto d = dissect_checked(kLinkRaw, udp4(kIpA, kIpB, 2152, 2152, echo));
  CHECK(find(d, Fid::gtpu_type) != nullptr);
  CHECK(find(d, Fid::payload_l7) == nullptr);  // only the optional fields, nothing after
}

TEST_CASE("tunnel nesting beyond the bound is not dissected", "[dissect][tunnel]") {
  Bytes p = udp4(kIpB, kIpA, 1, 2, text("deep"));
  for (int i = 0; i < 9; ++i) p = ipv4(kIpA, kIpB, 4, p);
  const auto d = dissect_checked(kLinkRaw, p);
  CHECK(d.depth_exceeded);
  CHECK(find(d, Fid::payload_unparsed) != nullptr);
  CHECK(find(d, Fid::udp_sport) == nullptr);
}
