// SPDX-License-Identifier: GPL-3.0-or-later
#include "rewrite_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
bool contains(const Bytes& hay, const Bytes& needle) {
  return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}
}  // namespace

TEST_CASE("addresses are pseudonymised, payload zeroed, checksums valid", "[rewrite]") {
  Rewriter rw;
  const Bytes in = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 40000, 5060, text("SECRET-PAYLOAD")));
  const auto out = rw.run(kLinkEthernet, in);
  REQUIRE(out.data.size() == in.size());
  CHECK_FALSE(contains(out.data, raw(kMacA)));
  CHECK_FALSE(contains(out.data, raw(kMacB)));
  CHECK_FALSE(contains(out.data, raw(kIpA)));
  CHECK_FALSE(contains(out.data, raw(kIpB)));
  CHECK_FALSE(contains(out.data, text("SECRET")));
  CHECK((out.data[0] & 0x02) == 0x02);  // locally administered
  CHECK(be16(out.data, 34) == 40000);  // ports kept by default
  CHECK(be16(out.data, 36) == 5060);
  CHECK(ipv4_header_ok(out.data, 14));
  CHECK(l4_ok_v4(out.data, 14, 17));
  CHECK(rw.stats.checksums.valid_kept_valid == 2);
  CHECK(rw.stats.counters["ipv4.src"]["pseudonymise"] == 1);
  CHECK(rw.stats.counters["payload.l7"]["zero"] == 1);
}

TEST_CASE("an invalid input checksum stays invalid without copying the original value",
          "[rewrite][checksum]") {
  Rewriter rw;
  Bytes in = udp4(kIpA, kIpB, 1, 2, text("abcd"));
  const std::uint16_t bad = static_cast<std::uint16_t>(be16(in, 26) ^ 0x0F0F);
  store16(in, 26, bad, Endian::big);
  const auto out = rw.run(kLinkRaw, in);
  CHECK(ipv4_header_ok(out.data));
  CHECK_FALSE(l4_ok_v4(out.data, 0, 17));
  CHECK(be16(out.data, 26) != bad);
  CHECK(rw.stats.checksums.invalid_kept_invalid == 1);
}

TEST_CASE("a UDP checksum of zero stays zero", "[rewrite][checksum]") {
  Rewriter rw;
  Bytes in = udp4(kIpA, kIpB, 1, 2, text("abcd"));
  store16(in, 26, 0, Endian::big);
  const auto out = rw.run(kLinkRaw, in);
  CHECK(be16(out.data, 26) == 0);
  CHECK(rw.stats.checksums.udp_zero_kept == 1);
}

TEST_CASE("a packet truncated by the snapshot length gets a recomputed checksum",
          "[rewrite][checksum]") {
  Rewriter rw;
  Bytes in = udp4(kIpA, kIpB, 1, 2, Bytes(100, 0x41));
  in.resize(60);
  const auto out = rw.run(kLinkRaw, in);
  CHECK(rw.stats.checksums.unverifiable_recomputed == 1);
  CHECK(ipv4_header_ok(out.data));
}

TEST_CASE("options not on the allowlist become padding", "[rewrite]") {
  SECTION("IPv4") {
    Rewriter rw;
    const Bytes opts = Bytes{0x94, 4, 0xAB, 0xCD};
    const auto out = rw.run(kLinkRaw, ipv4(kIpA, kIpB, 59, {}, opts));
    CHECK(Bytes(out.data.begin() + 20, out.data.begin() + 24) == Bytes{1, 1, 1, 1});
    CHECK(ipv4_header_ok(out.data));
  }
  SECTION("IPv6 destination option") {
    Rewriter rw;
    const Bytes dst = Bytes{59, 0} + Bytes{0x3E, 4, 9, 9, 9, 9};
    const auto out = rw.run(kLinkRaw, ipv6(kIp6A, kIp6B, 60, dst));
    CHECK(Bytes(out.data.begin() + 42, out.data.begin() + 48) == Bytes{1, 4, 0, 0, 0, 0});
  }
  SECTION("TCP") {
    Rewriter rw;
    const auto out = rw.run(kLinkRaw, tcp4(kIpA, kIpB, 1, 2, 3, 4, 0x10, Bytes{77, 4, 9, 9}, {}));
    CHECK(Bytes(out.data.begin() + 40, out.data.begin() + 44) == Bytes{1, 1, 1, 1});
    CHECK(l4_ok_v4(out.data, 0, 6));
  }
}

TEST_CASE("Ethernet FCS is recomputed and keeps its validity", "[rewrite][checksum]") {
  Bytes frame = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));
  Bytes good = frame;
  good.resize(good.size() + 4);
  store32(good, frame.size(), crc32_ethernet(frame), Endian::little);
  Bytes bad = good;
  bad.back() ^= 0xFF;
  Rewriter rw;
  const auto o1 = rw.run(kLinkEthernet, good, 4);
  const ByteView b1(o1.data);
  CHECK(load32(b1, b1.size() - 4, Endian::little) == crc32_ethernet(b1.first(b1.size() - 4)));
  const auto o2 = rw.run(kLinkEthernet, bad, 4);
  const ByteView b2(o2.data);
  CHECK(load32(b2, b2.size() - 4, Endian::little) != crc32_ethernet(b2.first(b2.size() - 4)));
}

TEST_CASE("multicast MACs follow the pseudonymised group address", "[rewrite]") {
  Rewriter rw;
  const V4 group{239, 1, 2, 3};
  const Bytes in = eth({0x01, 0x00, 0x5e, 0x01, 0x02, 0x03}, kMacA, 0x0800,
                       udp4(kIpA, group, 1, 2, {}));
  const auto out = rw.run(kLinkEthernet, in);
  const std::uint32_t new_group = be32(out.data, 14 + 16);
  CHECK((new_group >> 24) == 233);
  CHECK(out.data[0] == 0x01);
  CHECK(out.data[1] == 0x00);
  CHECK(out.data[2] == 0x5e);
  CHECK(out.data[3] == ((new_group >> 16) & 0x7F));
  CHECK(out.data[5] == (new_group & 0xFF));
}

TEST_CASE("SCTP CRC32c is recomputed", "[rewrite][checksum]") {
  Rewriter rw;
  const Bytes in = ipv4(kIpA, kIpB, 132,
                        sctp(1, 2, 3, chunk(1, 0, b32(1) + b32(1) + b16(1) + b16(1) + b32(1) +
                                                      param(5, raw(kIpA)))));
  const auto out = rw.run(kLinkRaw, in);
  CHECK(sctp_ok(out.data, 20, out.data.size()));
  CHECK_FALSE(contains(out.data, raw(kIpA)));
  CHECK(rw.stats.checksums.valid_kept_valid == 2);
}

TEST_CASE("ICMP error: embedded addresses pseudonymised, ICMP checksum valid", "[rewrite]") {
  Rewriter rw;
  const Bytes invoking = udp4(kIpB, kIpA, 33000, 53, Bytes(4, 0));
  Bytes icmp = Bytes{3, 3, 0, 0} + b32(0) + Bytes(invoking.begin(), invoking.begin() + 28);
  store16(icmp, 2, inet_checksum(icmp), Endian::big);
  const auto out = rw.run(kLinkRaw, ipv4(kIpA, kIpB, 1, icmp));
  CHECK_FALSE(contains(out.data, raw(kIpA)));
  CHECK_FALSE(contains(out.data, raw(kIpB)));
  CHECK(inet_checksum(ByteView(out.data).subspan(20)) == 0);
  CHECK(ipv4_header_ok(out.data, 28));  // the embedded header is consistent too
}

TEST_CASE("strict mode rejects unknown protocols", "[rewrite]") {
  Rewriter rw;
  rw.options.strict = true;
  auto r = rewrite_packet(kLinkRaw, ipv4(kIpA, kIpB, 253, Bytes(4, 0)), 0, *rw.policy, rw.mapper,
                          rw.options, rw.stats);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::input);
}

TEST_CASE("mapper errors (collisions) abort the packet", "[rewrite]") {
  Rewriter rw;
  rw.mapper.fail_with = Error{ErrorCode::collision, "collision"};
  auto r = rewrite_packet(kLinkRaw, udp4(kIpA, kIpB, 1, 2, {}), 0, *rw.policy, rw.mapper,
                          rw.options, rw.stats);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::collision);
}

TEST_CASE("a field without a rule is zeroed and counted as unclassified", "[rewrite]") {
  Rewriter rw(default_rules(Fid::ipv4_ttl));
  const auto out = rw.run(kLinkRaw, udp4(kIpA, kIpB, 1, 2, {}));
  CHECK(out.data[8] == 0);
  CHECK(rw.stats.counters["ipv4.ttl"]["unclassified"] == 1);
  CHECK(rw.stats.counters["ipv4.ttl"]["zero"] == 1);
}

TEST_CASE("VLAN IDs and ephemeral ports change only with the options", "[rewrite]") {
  const Bytes in = eth(kMacB, kMacA, 0x8100, b16(0x6064) + b16(0x0800) +
                                                 udp4(kIpA, kIpB, 50000, 5060, {}));
  Rewriter keep;
  const auto o1 = keep.run(kLinkEthernet, in);
  CHECK(be16(o1.data, 14) == 0x6064);
  CHECK(be16(o1.data, 18 + 20) == 50000);
  Rewriter change;
  change.options.pseudonymise_vlan = true;
  change.options.pseudonymise_ports = true;
  const auto o2 = change.run(kLinkEthernet, in);
  CHECK(be16(o2.data, 14) == 0x6065);  // PCP/DEI kept, VID + 1 by the fake mapper
  CHECK(be16(o2.data, 18 + 20) == 50001);
  CHECK(be16(o2.data, 18 + 22) == 5060);
  CHECK(l4_ok_v4(o2.data, 18, 17));
}

TEST_CASE("AH and ESP SPIs share the SIP SPI mapping; 0-255 are kept (feature 002, R10)", "[rewrite][spi]") {
  auto rules = load_embedded_ruleset();
  REQUIRE(rules.has_value());
  CHECK(rules->find("esp.spi")->action == Action::pseudonymise);
  CHECK(rules->find("esp.spi")->category == "spi");
  CHECK(rules->find("ah.spi")->category == "spi");
  Rewriter rw(*rules);
  const Bytes esp = eth(kMacB, kMacA, 0x0800, ipv4(kIpA, kIpB, 50, b32(0x12345678) + b32(1) + Bytes(16, 0xAB)));
  auto o = rw.run(kLinkEthernet, esp);
  CHECK(be32(o.data, 34) == (0x12345678u ^ 0x5A5A5A5Au));  // FakeMapper::spi
  const Bytes reserved = eth(kMacB, kMacA, 0x0800, ipv4(kIpA, kIpB, 50, b32(200) + b32(1) + Bytes(16, 0xAB)));
  CHECK(be32(rw.run(kLinkEthernet, reserved).data, 34) == 200u);  // RFC 4303 §2.1 reserved range
  const Bytes ah = eth(kMacB, kMacA, 0x0800,
                       ipv4(kIpA, kIpB, 51, Bytes{59, 4, 0, 0} + b32(0x0BADCAFE) + b32(1) + Bytes(12, 0)));
  CHECK(be32(rw.run(kLinkEthernet, ah).data, 34 + 4) == (0x0BADCAFEu ^ 0x5A5A5A5Au));
  CHECK(rw.stats.counters["esp.spi"]["pseudonymise"] == 2);
}
