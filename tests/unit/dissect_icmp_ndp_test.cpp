// SPDX-License-Identifier: GPL-3.0-or-later
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

TEST_CASE("ICMP echo", "[dissect][icmp]") {
  const auto d = dissect_checked(kLinkRaw,
                                 ipv4(kIpA, kIpB, 1, Bytes{8, 0, 0, 0} + b32(0x00010002) + text("ping")));
  CHECK(find(d, Fid::icmp_echo)->offset == 24);
  CHECK(find(d, Fid::icmp_data)->length == 4);
}

TEST_CASE("ICMP destination unreachable embeds the invoking IPv4 + UDP header", "[dissect][icmp]") {
  const Bytes invoking = udp4(kIpB, kIpA, 33000, 5060, Bytes(40, 0x55));
  const Bytes icmp = Bytes{3, 3, 0, 0} + b32(0) + Bytes(invoking.begin(), invoking.begin() + 28);
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 1, icmp));
  CHECK(count(d, Fid::ipv4_src) == 2);
  CHECK(find(d, Fid::ipv4_src, 1)->offset == 20 + 8 + 12);
  CHECK(find(d, Fid::udp_sport)->offset == 20 + 8 + 20);
  CHECK(find(d, Fid::icmp_embedded_l4_checksum) != nullptr);
  bool embedded_layer = false;
  for (const auto& l : d.layers) embedded_layer = embedded_layer || l.embedded;
  CHECK(embedded_layer);
}

TEST_CASE("ICMP redirect gateway address", "[dissect][icmp]") {
  const Bytes invoking = udp4(kIpB, kIpA, 1, 2, {});
  const Bytes icmp = Bytes{5, 1, 0, 0} + raw(kIpB) + invoking;
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 1, icmp));
  CHECK(find(d, Fid::icmp_gateway)->offset == 24);
}

TEST_CASE("ICMPv6 error embeds the invoking IPv6 packet", "[dissect][icmp]") {
  const Bytes invoking = ipv6(kIp6B, kIp6A, 17, udp(1, 2, Bytes(8, 0), 0));
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 58, Bytes{1, 4, 0, 0} + b32(0) + invoking));
  CHECK(count(d, Fid::ipv6_src) == 2);
  CHECK(find(d, Fid::icmpv6_rest) != nullptr);
}

TEST_CASE("Neighbor Solicitation with a source link-layer address option", "[dissect][ndp]") {
  const Bytes ns = Bytes{135, 0, 0, 0} + b32(0) + raw(kIp6B) + Bytes{1, 1} + raw(kMacA);
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 58, ns));
  CHECK(find(d, Fid::ndp_target)->offset == 48);
  CHECK(find(d, Fid::ndp_opt_lla)->offset == 66);
}

TEST_CASE("Router Advertisement: prefix, MTU and unknown options", "[dissect][ndp]") {
  const Bytes prefix = Bytes{3, 4, 64, 0xC0} + b32(1) + b32(2) + b32(0) + raw(kIp6A);
  const Bytes mtu = Bytes{5, 1, 0, 0} + b32(1500);
  const Bytes unk = Bytes{250, 1, 1, 2, 3, 4, 5, 6};
  const Bytes ra = Bytes{134, 0, 0, 0} + Bytes(12, 0) + prefix + mtu + unk;
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 58, ra));
  CHECK(find(d, Fid::ndp_opt_prefix_addr) != nullptr);
  CHECK(find(d, Fid::ndp_opt_mtu) != nullptr);
  CHECK(find(d, Fid::ndp_opt_other)->length == 6);
  CHECK(has_unknown(d, "ndp_option", 250));
}

TEST_CASE("NDP option of length zero is a parse failure", "[dissect][ndp]") {
  const Bytes rs = Bytes{133, 0, 0, 0} + b32(0) + Bytes{1, 0, 0, 0, 0, 0, 0, 0};
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 58, rs));
  CHECK(d.parse_failure);
}
