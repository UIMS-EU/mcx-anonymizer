// SPDX-License-Identifier: GPL-3.0-or-later
//
// RTCP report packets (FR-009 to FR-013): SR, RR,
// SDES, BYE, RTPFB/PSFB and XR.
#include "media_env.hpp"
#include "sip/sdp.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
Bytes run(MediaEnv& e, const Bytes& in) {
  auto r = media::rewrite_rtcp(in, false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  return **r;
}
Bytes block(std::uint32_t ssrc) {
  Bytes b;
  put32(b, ssrc);
  put32(b, 0x05000010);  // fraction lost, cumulative lost
  put32(b, 0x00011234);  // extended highest sequence number
  put32(b, 0x00000040);  // jitter
  put32(b, 0xABCD1234);  // LSR
  put32(b, 0x00000200);  // DLSR
  return b;
}
Bytes sr(std::uint32_t ssrc, std::initializer_list<std::uint32_t> blocks) {
  Bytes body;
  put32(body, ssrc);
  put32(body, 0xE1234567);
  put32(body, 0x89ABCDEF);
  put32(body, 160000);
  put32(body, 500);
  put32(body, 16000);
  for (auto b : blocks) {
    const auto x = block(b);
    body.insert(body.end(), x.begin(), x.end());
  }
  return rtcp(200, static_cast<std::uint8_t>(blocks.size()), body);
}
Bytes sdes(std::uint32_t ssrc, std::initializer_list<std::pair<std::uint8_t, std::string>> items) {
  Bytes body;
  put32(body, ssrc);
  for (const auto& [t, v] : items) {
    body.push_back(t);
    body.push_back(static_cast<std::uint8_t>(v.size()));
    body.insert(body.end(), v.begin(), v.end());
  }
  body.push_back(0);
  while (body.size() % 4) body.push_back(0);
  return rtcp(202, 1, body);
}
bool lengths_ok(const Bytes& d) {
  std::size_t o = 0;
  while (o + 4 <= d.size()) o += 4 * (1 + ((std::size_t{d[o + 2]} << 8) | d[o + 3]));
  return o == d.size();
}
bool contains(const Bytes& hay, const std::string& needle) {
  return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}
}  // namespace

TEST_CASE("SR and RR keep their statistics; every SSRC is mapped (FR-009)", "[media][rtcp]") {
  MediaEnv e;
  Bytes in = sr(0x11110001, {0x22220001, 0x22220002});
  const Bytes rr_body = [] {
    Bytes b;
    put32(b, 0x33330001);
    const auto x = block(0x22220001);
    b.insert(b.end(), x.begin(), x.end());
    return b;
  }();
  const Bytes rr = rtcp(201, 1, rr_body);
  in.insert(in.end(), rr.begin(), rr.end());
  const auto out = run(e, in);
  REQUIRE(out.size() == in.size());
  CHECK(get32(out, 4) == e.ssrc(0x11110001));
  CHECK(std::equal(in.begin() + 8, in.begin() + 28, out.begin() + 8));  // sender info
  CHECK(get32(out, 28) == e.ssrc(0x22220001));
  CHECK(std::equal(in.begin() + 32, in.begin() + 52, out.begin() + 32));  // block statistics
  CHECK(get32(out, 52) == e.ssrc(0x22220002));
  const std::size_t r = in.size() - rr.size();
  CHECK(get32(out, r + 4) == e.ssrc(0x33330001));
  CHECK(get32(out, r + 8) == e.ssrc(0x22220001));
  CHECK(e.counters.rtcp_by_packet_type.at("200") == 1);
  CHECK(e.counters.rtcp_by_packet_type.at("201") == 1);
}

TEST_CASE("SDES keeps a pseudonymised CNAME and removes every other item (FR-010)", "[media][rtcp]") {
  MediaEnv e;
  const std::string cname = "alice@ue1.example.net";
  const auto in = sdes(0x44440001, {{1, cname}, {2, "CANARY-NAME"}, {3, "CANARY-EMAIL"}, {4, "CANARY-PHONE"},
                                    {5, "CANARY-LOC"}, {6, "CANARY-TOOL"}, {7, "CANARY-NOTE"},
                                    {8, "\x05" "CANARY-PRIV"}, {42, "CANARY-UNKNOWN"}});
  const auto out = run(e, in);
  CHECK(lengths_ok(out));
  CHECK(out[0] == in[0]);  // SC = 1
  CHECK(get32(out, 4) == e.ssrc(0x44440001));
  CHECK(out[8] == 1);
  const auto expect = *sip::map_cname(cname, e.sip);
  REQUIRE(expect.has_value());
  CHECK(out[9] == expect->size());
  CHECK(std::string(out.begin() + 10, out.begin() + 10 + static_cast<std::ptrdiff_t>(expect->size())) == *expect);
  // The terminating null item and 32-bit padding (RFC 3550 §6.5).
  CHECK(out[10 + expect->size()] == 0);
  CHECK(out.size() % 4 == 0);
  CHECK_FALSE(contains(out, "CANARY"));
  CHECK(e.counters.sdes_removed.at("NAME") == 1);
  CHECK(e.counters.sdes_removed.at("PRIV") == 1);
  CHECK(e.counters.sdes_removed.at("unknown") == 1);
  CHECK(std::any_of(e.counters.removed_values.begin(), e.counters.removed_values.end(),
                    [](const auto& x) { return x.second == "CANARY-EMAIL"; }));
}

TEST_CASE("SDES with several chunks keeps the chunk count; a malformed chunk zeroes the body", "[media][rtcp]") {
  MediaEnv e;
  Bytes body;
  for (std::uint32_t s : {0x1u << 24, 0x2u << 24}) {
    put32(body, s);
    body.insert(body.end(), {1, 4, 'a', 'b', 'c', 'd', 0, 0});
  }
  const auto out = run(e, rtcp(202, 2, body));
  CHECK((out[0] & 0x1F) == 2);
  CHECK(lengths_ok(out));
  Bytes bad;
  put32(bad, 7);
  bad.insert(bad.end(), {1, 40, 'a', 'b', 'c', 'd'});  // the item overruns
  while (bad.size() % 4) bad.push_back(0);
  const Bytes x = rtcp(202, 1, bad);
  const auto o2 = run(e, x);
  CHECK(o2.size() == x.size());
  CHECK(std::all_of(o2.begin() + 4, o2.end(), [](std::uint8_t b) { return b == 0; }));
  CHECK(e.counters.rtcp_zeroed.at("malformed") == 1);  // counted by reason (FR-032)
}

TEST_CASE("an SR whose report count overruns its length keeps its header and is counted", "[media][rtcp]") {
  MediaEnv e;
  Bytes in = sr(0x11110001, {0x22220001});
  in[0] = static_cast<std::uint8_t>((in[0] & 0xE0) | 2);  // claims two report blocks, carries one
  const auto out = run(e, in);
  REQUIRE(out.size() == in.size());
  CHECK(std::equal(in.begin(), in.begin() + 4, out.begin()));
  CHECK(std::all_of(out.begin() + 4, out.end(), [](std::uint8_t b) { return b == 0; }));
  CHECK(e.counters.rtcp_zeroed.at("malformed") == 1);
  CHECK(e.counters.rtcp_by_packet_type.at("200") == 1);
}

TEST_CASE("BYE keeps its SSRCs mapped and removes the reason (FR-011)", "[media][rtcp]") {
  MediaEnv e;
  Bytes body;
  put32(body, 0x55550001);
  put32(body, 0x55550002);
  const std::string reason = "CANARY-BYE-REASON";
  body.push_back(static_cast<std::uint8_t>(reason.size()));
  body.insert(body.end(), reason.begin(), reason.end());
  while (body.size() % 4) body.push_back(0);
  const auto out = run(e, rtcp(203, 2, body));
  REQUIRE(out.size() == 12);
  CHECK(lengths_ok(out));
  CHECK(get32(out, 4) == e.ssrc(0x55550001));
  CHECK(get32(out, 8) == e.ssrc(0x55550002));
  CHECK(std::any_of(e.counters.removed_values.begin(), e.counters.removed_values.end(),
                    [&](const auto& x) { return x.second == reason; }));
}

TEST_CASE("feedback: NACK, PLI and SLI kept; RPSI bit string zeroed; AFB zeroed (FR-012)", "[media][rtcp]") {
  MediaEnv e;
  const auto fb = [](std::uint8_t pt, std::uint8_t fmt, const Bytes& fci) {
    Bytes b;
    put32(b, 0x66660001);
    put32(b, 0x66660002);
    b.insert(b.end(), fci.begin(), fci.end());
    return rtcp(pt, fmt, b);
  };
  const Bytes nack = fb(205, 1, {0x12, 0x34, 0x00, 0x05});
  const Bytes pli = fb(206, 1, {});
  const Bytes sli = fb(206, 2, {0x01, 0x23, 0x45, 0x67});
  const Bytes rpsi = fb(206, 3, {0x08, 0x60, 0xDE, 0xAD, 0xBE, 0xEF, 0x77, 0x00});
  const Bytes afb = fb(206, 15, {'C', 'A', 'N', 'A', 'R', 'Y', '-', 'A'});
  const Bytes other = fb(205, 9, {0xAA, 0xBB, 0xCC, 0xDD});
  for (const auto& [in, keep_fci] : {std::pair{nack, true}, std::pair{pli, true}, std::pair{sli, true}}) {
    const auto out = run(e, in);
    REQUIRE(out.size() == in.size());
    CHECK(get32(out, 4) == e.ssrc(0x66660001));
    CHECK(get32(out, 8) == e.ssrc(0x66660002));
    CHECK(std::equal(in.begin() + 12, in.end(), out.begin() + 12) == keep_fci);
  }
  const auto r = run(e, rpsi);
  CHECK(r[12] == 0x08);  // PB
  CHECK(r[13] == 0x60);  // payload type
  CHECK(std::all_of(r.begin() + 14, r.end(), [](std::uint8_t b) { return b == 0; }));
  for (const Bytes& z : {afb, other}) {
    const auto out = run(e, z);
    CHECK(get32(out, 8) == e.ssrc(0x66660002));
    CHECK(std::all_of(out.begin() + 12, out.end(), [](std::uint8_t b) { return b == 0; }));
  }
  CHECK(e.counters.rtcp_feedback.at("206/15").at("zero") == 1);
  CHECK(e.counters.rtcp_feedback.at("205/9").at("zero") == 1);
  CHECK(e.counters.rtcp_feedback.at("205/1").at("keep") == 1);
}

TEST_CASE("XR blocks 1 to 7 are kept with SSRCs mapped; unknown blocks zeroed (FR-012, P4)", "[media][rtcp]") {
  MediaEnv e;
  Bytes body;
  put32(body, 0x77770001);  // XR sender
  // BT 1 Loss RLE: SSRC of source, begin/end seq, one chunk.
  body.insert(body.end(), {1, 0, 0, 3});
  put32(body, 0x77770002);
  put32(body, 0x00010010);
  put32(body, 0x40050000);
  // BT 4 Receiver Reference Time: NTP timestamp.
  body.insert(body.end(), {4, 0, 0, 2});
  put32(body, 0xE1111111);
  put32(body, 0x22222222);
  // BT 5 DLRR: one sub-block.
  body.insert(body.end(), {5, 0, 0, 3});
  put32(body, 0x77770003);
  put32(body, 0x11112222);
  put32(body, 0x00000300);
  // BT 7 VoIP Metrics: SSRC + 32 octets of metrics.
  body.insert(body.end(), {7, 0, 0, 8});
  put32(body, 0x77770004);
  for (int i = 0; i < 28; ++i) body.push_back(static_cast<std::uint8_t>(i + 1));
  // BT 99: unknown.
  body.insert(body.end(), {99, 0, 0, 1});
  put32(body, 0xCAFEBABE);
  const Bytes in = rtcp(207, 0, body);
  const auto out = run(e, in);
  REQUIRE(out.size() == in.size());
  CHECK(get32(out, 4) == e.ssrc(0x77770001));
  CHECK(get32(out, 12) == e.ssrc(0x77770002));
  CHECK(std::equal(in.begin() + 16, in.begin() + 24, out.begin() + 16));
  CHECK(std::equal(in.begin() + 24, in.begin() + 36, out.begin() + 24));  // RRT kept as is
  CHECK(get32(out, 40) == e.ssrc(0x77770003));
  CHECK(std::equal(in.begin() + 44, in.begin() + 52, out.begin() + 44));
  CHECK(get32(out, 56) == e.ssrc(0x77770004));
  CHECK(std::equal(in.begin() + 60, in.begin() + 88, out.begin() + 60));
  CHECK(std::equal(in.begin() + 88, in.begin() + 92, out.begin() + 88));  // unknown block header
  CHECK(get32(out, 92) == 0);
  CHECK(e.counters.rtcp_xr.at("other").at("zero") == 1);
  CHECK(e.counters.rtcp_xr.at("7").at("keep") == 1);
}
