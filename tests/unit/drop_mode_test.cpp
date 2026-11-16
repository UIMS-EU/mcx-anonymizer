// SPDX-License-Identifier: GPL-3.0-or-later
#include "rewrite_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;


TEST_CASE("drop: UDP payload removed, lengths and checksums consistent", "[drop]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  Bytes in = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, Bytes(200, 0x41)));
  const auto out = rw.run(kLinkEthernet, in);
  CHECK(out.truncated);
  REQUIRE(out.data.size() == 14 + 20 + 8);
  CHECK(be16(out.data, 16) == 28);
  CHECK(be16(out.data, 38) == 8);
  CHECK(ipv4_header_ok(out.data, 14));
  CHECK(l4_ok_v4(out.data, 14, 17));
}

TEST_CASE("drop: Ethernet padding removed and FCS recomputed", "[drop]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  Bytes frame = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));
  frame.resize(60, 0);
  Bytes in = frame;
  in.resize(64);
  store32(in, 60, crc32_ethernet(frame), Endian::little);
  const auto out = rw.run(kLinkEthernet, in, 4);
  REQUIRE(out.data.size() == 42 + 4);
  const ByteView b(out.data);
  CHECK(load32(b, 42, Endian::little) == crc32_ethernet(b.first(42)));
}

TEST_CASE("drop: TCP stream numbering stays consistent", "[drop][tcp]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  const std::uint32_t isn_c = 1000;
  const std::uint32_t isn_s = 50000;
  auto c2s = [&](std::uint32_t seq, std::uint32_t ack, std::uint8_t flags, std::size_t n) {
    return rw.run(kLinkRaw, tcp4(kIpA, kIpB, 40000, 80, seq, ack, flags, {}, Bytes(n, 0x41))).data;
  };
  auto s2c = [&](std::uint32_t seq, std::uint32_t ack, std::uint8_t flags, std::size_t n) {
    return rw.run(kLinkRaw, tcp4(kIpB, kIpA, 80, 40000, seq, ack, flags, {}, Bytes(n, 0x42))).data;
  };
  const auto syn = c2s(isn_c, 0, 0x02, 0);
  const auto synack = s2c(isn_s, isn_c + 1, 0x12, 0);
  const auto ack = c2s(isn_c + 1, isn_s + 1, 0x10, 0);
  const auto d1 = c2s(isn_c + 1, isn_s + 1, 0x18, 100);
  const auto d2 = c2s(isn_c + 101, isn_s + 1, 0x18, 100);
  const auto r1 = s2c(isn_s + 1, isn_c + 201, 0x18, 500);
  const auto fin = c2s(isn_c + 201, isn_s + 501, 0x11, 0);
  const auto finack = s2c(isn_s + 501, isn_c + 202, 0x11, 0);
  const auto last = c2s(isn_c + 202, isn_s + 502, 0x10, 0);
  CHECK(be32(syn, 24) == isn_c);
  CHECK(be32(synack, 24) == isn_s);
  CHECK(be32(synack, 28) == isn_c + 1);
  CHECK(be32(ack, 24) == isn_c + 1);
  CHECK(be32(d1, 24) == isn_c + 1);
  CHECK(be32(d2, 24) == isn_c + 1);         // no data bytes remain
  CHECK(be32(r1, 28) == isn_c + 1);         // acknowledges the (now empty) data
  CHECK(be32(fin, 24) == isn_c + 1);
  CHECK(be32(finack, 28) == isn_c + 2);     // FIN consumed one sequence number
  CHECK(be32(last, 24) == isn_c + 2);
  CHECK(be32(last, 28) == isn_s + 2);
  CHECK(d1.size() == 40);
  CHECK(l4_ok_v4(d1, 0, 6));
}

TEST_CASE("drop: SACK blocks become padding", "[drop][tcp]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  const Bytes opts = Bytes{1, 1, 5, 10} + b32(1) + b32(2) + Bytes{1, 1};
  const auto out = rw.run(kLinkRaw, tcp4(kIpA, kIpB, 1, 2, 3, 4, 0x10, opts, {}));
  CHECK(Bytes(out.data.begin() + 42, out.data.begin() + 52) == Bytes(10, 1));
}

TEST_CASE("drop: IPv4 fragments", "[drop][fragment]") {
  SECTION("later fragments are dropped") {
    Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
    const auto out = rw.run(kLinkRaw, ipv4(kIpA, kIpB, 17, Bytes(64, 1), {}, 0x0010));
    CHECK(out.drop);
    CHECK(rw.stats.packets_dropped == 1);
  }
  SECTION("the first fragment becomes a complete header-only packet") {
    Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
    const Bytes u = udp(5000, 5060, Bytes(100, 0x42), 0);
    const auto out = rw.run(kLinkRaw, ipv4(kIpA, kIpB, 17, Bytes(u.begin(), u.begin() + 48), {},
                                           0x2000));
    CHECK(be16(out.data, 6) == 0);  // MF cleared, offset 0
    CHECK(be16(out.data, 2) == 28);
    CHECK(be16(out.data, 24) == 8);
    CHECK(l4_ok_v4(out.data, 0, 17));
  }
}

TEST_CASE("drop: IPv6 first fragment becomes atomic", "[drop][fragment]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  const Bytes frag = Bytes{17, 0, 0x00, 0x01} + b32(9);
  const auto out = rw.run(kLinkRaw, ipv6(kIp6A, kIp6B, 44, frag + udp(1, 2, Bytes(40, 3), 0)));
  CHECK((be16(out.data, 42) & 1u) == 0);
  CHECK(be16(out.data, 4) == 16);
}

TEST_CASE("drop: SCTP DATA user data removed with chunk lengths adjusted", "[drop][sctp]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  const Bytes data1 = chunk(0, 3, b32(1) + b16(0) + b16(0) + b32(46) + Bytes(33, 0x44));
  const Bytes sack = chunk(3, 0, b32(1) + b32(65535) + b16(0) + b16(0));
  const Bytes data2 = chunk(0, 3, b32(2) + b16(0) + b16(1) + b32(46) + Bytes(7, 0x45));
  const auto out = rw.run(kLinkRaw, ipv4(kIpA, kIpB, 132, sctp(1, 2, 3, data1 + sack + data2)));
  REQUIRE(out.data.size() == 20 + 12 + 16 + 16 + 16);
  CHECK(be16(out.data, 32 + 2) == 16);
  CHECK(out.data[48] == 3);  // SACK unchanged, now right after the first DATA chunk
  CHECK(be16(out.data, 64 + 2) == 16);
  CHECK(be16(out.data, 2) == out.data.size());
  CHECK(sctp_ok(out.data, 20, out.data.size()));
  CHECK(ipv4_header_ok(out.data));
}

TEST_CASE("drop: GTP-U inner payload removed, every length consistent", "[drop][tunnel]") {
  Rewriter rw;
    rw.options.payload = PayloadPolicy::drop;
  const Bytes inner = udp4(kIpB, kIpA, 6000, 7000, Bytes(80, 0x46));
  const Bytes gtp = Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(7) + inner;
  const auto out = rw.run(kLinkRaw, udp4(kIpA, kIpB, 2152, 2152, gtp));
  const std::size_t total = 20 + 8 + 8 + 20 + 8;
  REQUIRE(out.data.size() == total);
  CHECK(be16(out.data, 2) == total);
  CHECK(be16(out.data, 24) == total - 20);
  CHECK(be16(out.data, 30) == 28);           // GTP-U length: inner IP + UDP
  CHECK(be16(out.data, 36 + 2) == 28);       // inner IPv4 total length
  CHECK(be16(out.data, 56 + 4) == 8);        // inner UDP length
  CHECK(ipv4_header_ok(out.data));
  CHECK(ipv4_header_ok(out.data, 36));
  CHECK(l4_ok_v4(out.data, 36, 17));
  CHECK(l4_ok_v4(out.data, 0, 17));
}
