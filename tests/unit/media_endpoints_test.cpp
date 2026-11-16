// SPDX-License-Identifier: GPL-3.0-or-later
//
// Media endpoint table.
#include "media/endpoints.hpp"

#include <catch2/catch_test_macros.hpp>

#include <variant>

using namespace mcxanon;
using namespace mcxanon::media;

namespace {
Address v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return Address::v4({a, b, c, d});
}
EndpointKey udp(const Address& a, std::uint16_t port) { return {a, port, Transport::udp}; }
EndpointKey tcp(const Address& a, std::uint16_t port) { return {a, port, Transport::tcp}; }

Announcement rtp(const Address& a, std::uint16_t port) {
  Announcement x;
  x.address = a;
  x.port = port;
  x.transport = Transport::udp;
  x.role = Role::rtp;
  return x;
}

const Address A = v4(10, 0, 0, 1);
const Address B = v4(10, 0, 0, 2);
const Address C = v4(10, 0, 0, 3);
}  // namespace

TEST_CASE("an RTP announcement registers RTP and RTCP on port + 1", "[media][endpoints]") {
  EndpointTable t;
  t.announce(rtp(A, 40000), 1);
  auto r = t.lookup(udp(A, 40000), udp(B, 50000), 2);
  REQUIRE(r.has_value());
  CHECK(r->kind == Kind::rtp);
  CHECK(r->matched == Match::dst);
  CHECK_FALSE(r->secure);
  auto c = t.lookup(udp(A, 40001), udp(B, 50001), 3);
  REQUIRE(c.has_value());
  CHECK(c->kind == Kind::rtcp);
  CHECK_FALSE(t.lookup(udp(A, 40002), udp(B, 9), 4).has_value());
  CHECK(t.registered().at(Kind::rtp) == 1);
  CHECK(t.registered().at(Kind::rtcp) == 1);
}

TEST_CASE("a=rtcp and a=rtcp-mux change the RTCP endpoint", "[media][endpoints]") {
  EndpointTable t;
  auto x = rtp(A, 40000);
  x.rtcp_port = 40100;
  x.rtcp_address = C;
  t.announce(x, 1);
  auto c = t.lookup(udp(C, 40100), udp(B, 1), 2);
  REQUIRE(c.has_value());
  CHECK(c->kind == Kind::rtcp);
  CHECK_FALSE(t.lookup(udp(A, 40001), udp(B, 1), 2).has_value());

  EndpointTable m;
  auto y = rtp(A, 40000);
  y.rtcp_mux = true;
  y.secure = true;
  m.announce(y, 1);
  auto r = m.lookup(udp(A, 40000), udp(B, 1), 2);
  REQUIRE(r.has_value());
  CHECK(r->kind == Kind::mux);
  CHECK(r->secure);
  CHECK_FALSE(m.lookup(udp(A, 40001), udp(B, 1), 2).has_value());
}

TEST_CASE("floor, transmission control and MSRP endpoints", "[media][endpoints]") {
  EndpointTable t;
  Announcement fc;
  fc.address = A;
  fc.port = 40002;
  fc.role = Role::fc;
  t.announce(fc, 1);
  Announcement tc = fc;
  tc.port = 40004;
  tc.role = Role::tc;
  t.announce(tc, 1);
  Announcement ms = fc;
  ms.port = 7000;
  ms.transport = Transport::tcp;
  ms.role = Role::msrp;
  t.announce(ms, 1);
  CHECK(t.lookup(udp(A, 40002), udp(B, 1), 2)->kind == Kind::fc);
  CHECK(t.lookup(udp(A, 40004), udp(B, 1), 2)->kind == Kind::tc);
  CHECK(t.lookup(tcp(A, 7000), tcp(B, 1), 2)->kind == Kind::msrp);
  // The transport is part of the key: UDP to the MSRP port is not MSRP.
  CHECK_FALSE(t.lookup(udp(A, 7000), udp(B, 1), 2).has_value());
  // No RTCP endpoint for a floor control channel: its port is already an RTCP port.
  CHECK_FALSE(t.lookup(udp(A, 40003), udp(B, 1), 2).has_value());
}

TEST_CASE("lookup by destination first, then by source (P1)", "[media][endpoints]") {
  EndpointTable t;
  t.announce(rtp(A, 40000), 1);
  Announcement fc;
  fc.address = B;
  fc.port = 50002;
  fc.role = Role::fc;
  t.announce(fc, 1);
  // A packet from the announced RTP endpoint to an unannounced port belongs to it by source.
  auto s = t.lookup(udp(C, 9999), udp(A, 40000), 2);
  REQUIRE(s.has_value());
  CHECK(s->kind == Kind::rtp);
  CHECK(s->matched == Match::src);
  // Both ends announced: the destination decides.
  auto d = t.lookup(udp(B, 50002), udp(A, 40000), 3);
  REQUIRE(d.has_value());
  CHECK(d->kind == Kind::fc);
  CHECK(d->matched == Match::dst);
}

TEST_CASE("a re-announcement replaces the entry; port 0 is not registered", "[media][endpoints]") {
  EndpointTable t;
  t.announce(rtp(A, 40000), 1);
  Announcement fc;
  fc.address = A;
  fc.port = 40000;
  fc.role = Role::fc;
  t.announce(fc, 2);
  CHECK(t.lookup(udp(A, 40000), udp(B, 1), 3)->kind == Kind::fc);
  t.announce(rtp(B, 0), 4);
  CHECK(t.skipped().at(SkipReason::rejected) == 1);
  CHECK_FALSE(t.lookup(udp(B, 0), udp(C, 1), 5).has_value());
}

TEST_CASE("the table is bounded; the least recently used endpoint is evicted", "[media][endpoints]") {
  EndpointTable t(4);
  Announcement fc;
  fc.role = Role::fc;
  fc.address = A;
  for (std::uint16_t p = 1; p <= 4; ++p) {
    fc.port = p;
    t.announce(fc, p);
  }
  // Port 1 is used again, so port 2 is now the least recently used.
  REQUIRE(t.lookup(udp(A, 1), udp(B, 9), 10).has_value());
  fc.port = 5;
  t.announce(fc, 11);
  CHECK(t.size() == 4);
  CHECK(t.evicted() == 1);
  CHECK_FALSE(t.lookup(udp(A, 2), udp(B, 9), 12).has_value());
  CHECK(t.lookup(udp(A, 1), udp(B, 9), 12).has_value());
  CHECK(t.lookup(udp(A, 5), udp(B, 9), 12).has_value());
  // Equal timestamps: the earlier insertion goes first (deterministic).
  EndpointTable u(2);
  fc.port = 1;
  u.announce(fc, 7);
  fc.port = 2;
  u.announce(fc, 7);
  fc.port = 3;
  u.announce(fc, 7);
  CHECK_FALSE(u.lookup(udp(A, 1), udp(B, 9), 8).has_value());
  CHECK(u.lookup(udp(A, 2), udp(B, 9), 8).has_value());
}

TEST_CASE("connection addresses: IPv4, IPv6 and the skipped forms", "[media][endpoints]") {
  auto a = connection_address("IP4", "10.0.0.1");
  REQUIRE(std::holds_alternative<Address>(a));
  CHECK(std::get<Address>(a) == A);
  auto b = connection_address("IP6", "2001:db8::1");
  REQUIRE(std::holds_alternative<Address>(b));
  CHECK(std::get<Address>(b).bytes[0] == 0x20);
  CHECK(std::get<SkipReason>(connection_address("IP4", "media.example.net")) == SkipReason::fqdn);
  CHECK(std::get<SkipReason>(connection_address("IP4", "0.0.0.0")) == SkipReason::unspecified);
  CHECK(std::get<SkipReason>(connection_address("IP6", "::")) == SkipReason::unspecified);
  CHECK(std::get<SkipReason>(connection_address("IP4", "224.2.1.1/127")) == SkipReason::multicast);
  CHECK(std::get<SkipReason>(connection_address("IP6", "ff0e::1")) == SkipReason::multicast);
  CHECK(std::get<SkipReason>(connection_address("IP4", "10.0.0.256")) == SkipReason::malformed);
  CHECK(std::get<SkipReason>(connection_address("XY", "10.0.0.1")) == SkipReason::malformed);
}

TEST_CASE("an RTP announcement on port 65535 has no RTCP endpoint", "[media][endpoints]") {
  EndpointTable t;
  t.announce(rtp(A, 65535), 1);
  CHECK(t.lookup(udp(A, 65535), udp(B, 1), 2)->kind == Kind::rtp);
  CHECK(t.registered().count(Kind::rtcp) == 0);
}
