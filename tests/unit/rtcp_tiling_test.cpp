// SPDX-License-Identifier: GPL-3.0-or-later
//
// RTCP tiling, the SRTCP view and unknown packet types (FR-013, FR-024,
// FR-025, FR-030).
#include "media_env.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
std::optional<Bytes> run(MediaEnv& e, const Bytes& in, bool secure = false) {
  auto r = media::rewrite_rtcp(in, secure, e.env);
  REQUIRE(r.has_value());
  return *r;
}
bool zero_from(const Bytes& b, std::size_t off) {
  return std::all_of(b.begin() + static_cast<std::ptrdiff_t>(off), b.end(), [](std::uint8_t x) { return x == 0; });
}
}  // namespace

TEST_CASE("one APP packet and a reduced-size pair tile their datagram", "[media][rtcp]") {
  MediaEnv e;
  const Bytes a = app("MCPT", 0, 0x10203040, {field(0, {0x04, 0x00})});
  auto out = run(e, a);
  REQUIRE(out.has_value());
  CHECK(out->size() == a.size());
  CHECK(get32(*out, 4) == e.ssrc(0x10203040));
  // Two APP packets in one datagram (TS 24.380 §8.1.1: more than one message per IP packet).
  Bytes two = a;
  const Bytes b = app("MCPT", 5, 0x10203041, {field(8, {0x00, 0x07})});
  two.insert(two.end(), b.begin(), b.end());
  auto out2 = run(e, two);
  REQUIRE(out2.has_value());
  CHECK(out2->size() == two.size());
  CHECK(e.counters.srtcp_view.empty());
  CHECK(e.counters.rtcp_by_packet_type.at("204") == 3);
}

TEST_CASE("RTCP that does not tile is reduced to its first 8 octets (P3)", "[media][rtcp]") {
  MediaEnv e;
  Bytes a = app("MCPT", 0, 0x10203040, {field(0, {0x04, 0x00})});
  // An appended secure part: E flag + SRTCP index and a 10-octet tag (RFC 3711 §3.4).
  for (int i = 0; i < 14; ++i) a.push_back(static_cast<std::uint8_t>(0xA0 + i));
  auto out = run(e, a);
  REQUIRE(out.has_value());
  CHECK(out->size() == a.size());
  CHECK(std::equal(a.begin(), a.begin() + 4, out->begin()));
  CHECK(get32(*out, 4) == e.ssrc(0x10203040));
  // A known APP name is public vocabulary and stays; everything after it is zeroed.
  CHECK(Bytes(out->begin() + 8, out->begin() + 12) == str("MCPT"));
  CHECK(zero_from(*out, 12));
  CHECK(e.counters.srtcp_view.at("undecodable") == 1);
}

TEST_CASE("bad version or an overrunning length gives the SRTCP view", "[media][rtcp]") {
  MediaEnv e;
  Bytes v = app("MCPT", 0, 1, {field(0, {0x04, 0x00})});
  v[0] = 0x40 | (v[0] & 0x3F);
  auto o1 = run(e, v);
  REQUIRE(o1.has_value());
  CHECK(zero_from(*o1, 12));
  Bytes over = app("MCPT", 0, 1, {field(0, {0x04, 0x00})});
  over[3] = 0x20;  // length beyond the datagram
  auto o2 = run(e, over);
  REQUIRE(o2.has_value());
  CHECK(zero_from(*o2, 12));
  CHECK(e.counters.srtcp_view.at("undecodable") == 2);
  // Shorter than 8 octets: nothing can be kept.
  CHECK_FALSE(run(e, Bytes{0x80, 0xCC, 0x00}).has_value());
}

TEST_CASE("on a secure endpoint every datagram gets the SRTCP view", "[media][rtcp][srtp]") {
  MediaEnv e;
  const Bytes a = app("MCPT", 0, 0x0BADF00D, {field(6, str("sip:alice@example.net"))});
  auto out = run(e, a, true);
  REQUIRE(out.has_value());
  CHECK(get32(*out, 4) == e.ssrc(0x0BADF00D));
  CHECK(zero_from(*out, 12));
  CHECK(e.counters.srtcp_view.at("secure") == 1);
}

TEST_CASE("an unknown RTCP packet type keeps its 4-octet header, the body is zeroed (P4)", "[media][rtcp]") {
  MediaEnv e;
  Bytes body;
  put32(body, 0x11111111);
  put32(body, 0x22222222);
  const Bytes x = rtcp(209, 3, body);
  auto out = run(e, x);
  REQUIRE(out.has_value());
  CHECK(std::equal(x.begin(), x.begin() + 4, out->begin()));
  CHECK(zero_from(*out, 4));
  CHECK(e.counters.rtcp_by_packet_type.at("other") == 1);
}
