// SPDX-License-Identifier: GPL-3.0-or-later
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

TEST_CASE("Ethernet / IPv4 / UDP fields and offsets", "[dissect][link]") {
  const Bytes pkt = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 40000, 5060, text("hello")));
  const auto d = dissect_checked(kLinkEthernet, pkt);
  REQUIRE(find(d, Fid::eth_dst) != nullptr);
  CHECK(find(d, Fid::eth_dst)->offset == 0);
  CHECK(find(d, Fid::eth_src)->offset == 6);
  CHECK(find(d, Fid::ipv4_src)->offset == 14 + 12);
  CHECK(find(d, Fid::ipv4_dst)->offset == 14 + 16);
  CHECK(find(d, Fid::udp_sport)->offset == 34);
  CHECK(find(d, Fid::payload_l7)->offset == 42);
  CHECK(find(d, Fid::payload_l7)->length == 5);
  REQUIRE(d.layers.size() == 3);
  CHECK(d.layers[1].kind == LayerKind::ipv4);
  CHECK(d.layers[2].kind == LayerKind::udp);
  CHECK(d.layers[2].parent_ip == 1);
  CHECK_FALSE(d.parse_failure);
}

TEST_CASE("Ethernet padding is a link trailer and the FCS is a field", "[dissect][link]") {
  Bytes pkt = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));  // 42 bytes
  pkt.resize(60, 0xEE);                                               // padding
  pkt = pkt + Bytes{1, 2, 3, 4};                                      // FCS
  DissectOptions o;
  o.fcs_len = 4;
  const auto d = dissect_checked(kLinkEthernet, pkt, o);
  REQUIRE(find(d, Fid::link_trailer) != nullptr);
  CHECK(find(d, Fid::link_trailer)->offset == 42);
  CHECK(find(d, Fid::link_trailer)->length == 18);
  REQUIRE(find(d, Fid::eth_fcs) != nullptr);
  CHECK(find(d, Fid::eth_fcs)->offset == 60);
}

TEST_CASE("802.1ad + 802.1Q stacked tags", "[dissect][link]") {
  const Bytes inner = b16(0x0064) + b16(0x0800) + udp4(kIpA, kIpB, 1, 2, {});
  const Bytes pkt = eth(kMacB, kMacA, 0x88A8, b16(0x2005) + b16(0x8100) + inner);
  const auto d = dissect_checked(kLinkEthernet, pkt);
  CHECK(count(d, Fid::vlan_tci) == 2);
  CHECK(find(d, Fid::vlan_tci, 0)->offset == 14);
  CHECK(find(d, Fid::vlan_tci, 1)->offset == 18);
  CHECK(find(d, Fid::ipv4_src) != nullptr);
}

TEST_CASE("Linux cooked capture v1 and v2", "[dissect][link]") {
  SECTION("SLL with a 6-byte address") {
    const Bytes pkt = b16(0) + b16(1) + b16(6) + raw(kMacA) + Bytes{0, 0} + b16(0x0800) +
                      udp4(kIpA, kIpB, 1, 2, {});
    const auto d = dissect_checked(kLinkSll, pkt);
    CHECK(find(d, Fid::sll_addr)->offset == 6);
    CHECK(find(d, Fid::sll_addr)->length == 6);
    CHECK(find(d, Fid::sll_addr_pad) != nullptr);
    CHECK(find(d, Fid::ipv4_src)->offset == 16 + 12);
  }
  SECTION("SLL with another address length") {
    const Bytes pkt = b16(0) + b16(772) + b16(0) + Bytes(8, 0) + b16(0x0800) +
                      udp4(kIpA, kIpB, 1, 2, {});
    const auto d = dissect_checked(kLinkSll, pkt);
    CHECK(find(d, Fid::sll_addr) == nullptr);
    CHECK(find(d, Fid::sll_addr_other) != nullptr);
  }
  SECTION("SLL2") {
    const Bytes pkt = b16(0x86DD) + b16(0) + b32(3) + b16(1) + Bytes{0, 6} + raw(kMacA) +
                      Bytes{0, 0} + ipv6(kIp6A, kIp6B, 59, {});
    const auto d = dissect_checked(kLinkSll2, pkt);
    CHECK(find(d, Fid::sll2_addr)->offset == 12);
    CHECK(find(d, Fid::ipv6_src)->offset == 20 + 8);
  }
}

TEST_CASE("BSD loopback in either byte order, raw IP link types", "[dissect][link]") {
  const Bytes ip = udp4(kIpA, kIpB, 1, 2, {});
  CHECK(find(dissect_checked(kLinkNull, Bytes{2, 0, 0, 0} + ip), Fid::ipv4_src) != nullptr);
  CHECK(find(dissect_checked(kLinkNull, Bytes{0, 0, 0, 2} + ip), Fid::ipv4_src) != nullptr);
  CHECK(find(dissect_checked(kLinkNull, Bytes{30, 0, 0, 0} + ipv6(kIp6A, kIp6B, 59, {})),
             Fid::ipv6_src) != nullptr);
  CHECK(find(dissect_checked(kLinkRaw, ip), Fid::ipv4_src)->offset == 12);
  CHECK(find(dissect_checked(kLinkIpv6, ipv6(kIp6A, kIp6B, 59, {})), Fid::ipv6_dst)->offset == 24);
  const auto bad = dissect_checked(kLinkIpv6, ip);  // IPv4 bytes on an IPv6 link
  CHECK(bad.parse_failure);
}

TEST_CASE("ARP request over Ethernet", "[dissect][link]") {
  const Bytes arp = b16(1) + b16(0x0800) + Bytes{6, 4} + b16(1) + raw(kMacA) + raw(kIpA) +
                    Bytes(6, 0) + raw(kIpB);
  Bytes pkt = eth({0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, kMacA, 0x0806, arp);
  pkt.resize(60, 0);
  const auto d = dissect_checked(kLinkEthernet, pkt);
  CHECK(find(d, Fid::arp_sha)->offset == 22);
  CHECK(find(d, Fid::arp_spa)->offset == 28);
  CHECK(find(d, Fid::arp_tha)->offset == 32);
  CHECK(find(d, Fid::arp_tpa)->offset == 38);
  CHECK(find(d, Fid::link_trailer)->offset == 42);
}

TEST_CASE("unknown EtherType is zeroed payload and reported", "[dissect][link]") {
  const Bytes pkt = eth(kMacB, kMacA, 0x88B5, text("experimental payload"));
  const auto d = dissect_checked(kLinkEthernet, pkt);
  CHECK(find(d, Fid::payload_unknown)->offset == 14);
  CHECK(has_unknown(d, "ethertype", 0x88B5));
}

TEST_CASE("unsupported link type: the whole packet is unknown payload", "[dissect][link]") {
  const Bytes pkt = text("radiotap header and 802.11 frame");
  const auto d = dissect_checked(127, pkt);
  CHECK(find(d, Fid::payload_unknown)->length == pkt.size());
  CHECK(has_unknown(d, "linktype", 127));
  CHECK_FALSE(is_supported_linktype(127));
  CHECK(is_supported_linktype(kLinkSll2));
}

TEST_CASE("truncated Ethernet header is a parse failure", "[dissect][link]") {
  const auto d = dissect_checked(kLinkEthernet, Bytes(10, 1));
  CHECK(d.parse_failure);
  CHECK(find(d, Fid::payload_unparsed)->length == 10);
  const auto empty = dissect_checked(kLinkEthernet, Bytes{});
  CHECK(empty.fields.empty());
}
