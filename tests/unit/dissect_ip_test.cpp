// SPDX-License-Identifier: GPL-3.0-or-later
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

TEST_CASE("IPv4 options: record route, timestamp with addresses, unknown, EOL", "[dissect][ip]") {
  const Bytes rr = Bytes{7, 11, 4} + raw(kIpA) + raw(kIpB);              // 11 bytes
  const Bytes ts = Bytes{68, 12, 5, 0x01} + raw(kIpB) + b32(0x01020304);  // 12 bytes
  const Bytes other = Bytes{0x94, 4, 0, 0};                               // Router Alert
  const Bytes opts = rr + Bytes{1} + ts + other + Bytes{0, 0, 0, 0};      // 32 bytes
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 59, {}, opts));
  CHECK(find(d, Fid::ipv4_opt_route_hdr) != nullptr);
  CHECK(count(d, Fid::ipv4_opt_route_addr) == 2);
  CHECK(find(d, Fid::ipv4_opt_route_addr, 0)->offset == 23);
  CHECK(find(d, Fid::ipv4_opt_nop)->offset == 31);
  CHECK(find(d, Fid::ipv4_opt_ts_addr)->offset == 36);
  CHECK(find(d, Fid::ipv4_opt_ts_value)->offset == 40);
  CHECK(find(d, Fid::ipv4_opt_other)->offset == 44);
  CHECK(find(d, Fid::ipv4_opt_eol)->offset == 48);
  CHECK(find(d, Fid::ipv4_opt_padding)->length == 3);
  CHECK(has_unknown(d, "ipv4_option", 0x94));
}

TEST_CASE("IPv4 malformed option length pads the rest", "[dissect][ip]") {
  const Bytes opts = Bytes{7, 40, 4, 0};  // claims 40 bytes in a 4-byte option area
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 59, {}, opts));
  CHECK(find(d, Fid::ipv4_opt_malformed)->length == 4);
}

TEST_CASE("IPv4 fragments", "[dissect][ip]") {
  const Bytes data(24, 0x42);
  SECTION("first fragment carries the transport header") {
    const Bytes u = udp(5000, 5060, data, 0);
    const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 17, Bytes(u.begin(), u.begin() + 16),
                                                  {}, 0x2000));
    CHECK(d.layers[0].fragment_first);
    CHECK(find(d, Fid::udp_sport) != nullptr);
  }
  SECTION("later fragments carry only payload") {
    const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 17, data, {}, 0x0003));
    CHECK(d.layers[0].fragment_nonfirst);
    CHECK(find(d, Fid::udp_sport) == nullptr);
    CHECK(find(d, Fid::payload_fragment)->length == data.size());
  }
}

TEST_CASE("IPv4 header errors are parse failures", "[dissect][ip]") {
  Bytes p = ipv4(kIpA, kIpB, 59, {});
  SECTION("IHL below 5") {
    p[0] = 0x44;
    CHECK(dissect_checked(kLinkRaw, p).parse_failure);
  }
  SECTION("total length below the header") {
    p[2] = 0;
    p[3] = 10;
    CHECK(dissect_checked(kLinkRaw, p).parse_failure);
  }
  SECTION("truncated header") {
    p.resize(15);
    CHECK(dissect_checked(kLinkRaw, p).parse_failure);
  }
}

TEST_CASE("IPv4 total length shorter than the frame leaves a trailer", "[dissect][ip]") {
  Bytes p = udp4(kIpA, kIpB, 1, 2, text("x"));
  p.resize(p.size() + 7, 0xAB);
  const auto d = dissect_checked(kLinkRaw, p);
  CHECK(find(d, Fid::link_trailer)->length == 7);
}

TEST_CASE("IPv6 extension headers", "[dissect][ip]") {
  const Bytes hbh = Bytes{60, 0} + Bytes{5, 2, 0, 0} + Bytes{1, 0};  // RA + PadN(0) = 8 bytes
  const Bytes dst = Bytes{43, 2} + Bytes{0xC9, 16} + raw(kIp6B) + Bytes{1, 2, 0, 0};  // 24 bytes
  const Bytes rh2 = Bytes{44, 2, 2, 1} + Bytes(4, 0) + raw(kIp6A);                     // 24 bytes
  const Bytes frag = Bytes{17, 0, 0, 0} + b32(0xABCD);                                 // offset 0
  const Bytes u = udp(1, 2, text("ok"), 0);
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 0, hbh + dst + rh2 + frag + u));
  CHECK(count(d, Fid::ipv6_ext_hdr) == 3);
  CHECK(find(d, Fid::ipv6_opt_ra) != nullptr);
  CHECK(find(d, Fid::ipv6_opt_padn) != nullptr);
  CHECK(find(d, Fid::ipv6_opt_hao_addr)->offset == 40 + 8 + 4);
  CHECK(find(d, Fid::ipv6_rh_addr)->offset == 40 + 8 + 24 + 8);
  CHECK(find(d, Fid::ipv6_frag)->offset == 40 + 8 + 24 + 24);
  CHECK(find(d, Fid::udp_sport) != nullptr);
  CHECK(d.layers[0].upper_offset == 40 + 8 + 24 + 24 + 8);
}

TEST_CASE("IPv6 segment routing header lists segments", "[dissect][ip]") {
  // Last Entry = 2 (three segments): (3*16 + 8) / 8 - 1 = 6.
  const Bytes srh = Bytes{59, 6, 4, 2} + Bytes{2, 0, 0, 0} + raw(kIp6A) + raw(kIp6B) + raw(kIp6A);
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 43, srh));
  CHECK(count(d, Fid::ipv6_srh_seg) == 3);
  CHECK(find(d, Fid::ipv6_srh_fixed)->offset == 44);
}

TEST_CASE("IPv6 unknown routing type data is opaque", "[dissect][ip]") {
  const Bytes rh = Bytes{59, 0, 253, 0} + Bytes{9, 9, 9, 9};
  const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 43, rh));
  CHECK(find(d, Fid::ipv6_rh_data)->length == 4);
}

TEST_CASE("IPv6 non-first fragment, AH, ESP, unknown next header", "[dissect][ip]") {
  SECTION("non-first fragment") {
    const Bytes frag = Bytes{17, 0, 0x01, 0x00} + b32(1);  // offset 32
    const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 44, frag + Bytes(16, 1)));
    CHECK(d.layers[0].fragment_nonfirst);
    CHECK(find(d, Fid::payload_fragment)->length == 16);
  }
  SECTION("AH then UDP") {
    const Bytes ah = Bytes{17, 4, 0, 0} + b32(0x100) + b32(7) + Bytes(12, 0xAA);  // 24 bytes
    const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 51, ah + udp(1, 2, {}, 0)));
    CHECK(find(d, Fid::ah_icv)->length == 12);
    CHECK(find(d, Fid::udp_sport) != nullptr);
  }
  SECTION("ESP payload is opaque") {
    const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 50, b32(1) + b32(2) + Bytes(20, 3)));
    CHECK(find(d, Fid::esp_spi) != nullptr);
    CHECK(find(d, Fid::payload_encrypted)->length == 20);
  }
  SECTION("unknown next header") {
    const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 253, Bytes(10, 3)));
    CHECK(has_unknown(d, "ipv6_nh", 253));
    CHECK(find(d, Fid::payload_unknown)->length == 10);
  }
  SECTION("extension header longer than the packet") {
    const auto d = dissect_checked(kLinkRaw, ipv6(kIp6A, kIp6B, 0, Bytes{59, 5, 1, 0, 0, 0, 0, 0}));
    CHECK(d.parse_failure);
  }
}

TEST_CASE("IPv4 unknown protocol is reported", "[dissect][ip]") {
  const auto d = dissect_checked(kLinkRaw, ipv4(kIpA, kIpB, 253, Bytes(9, 1)));
  CHECK(has_unknown(d, "ip_proto", 253));
}
