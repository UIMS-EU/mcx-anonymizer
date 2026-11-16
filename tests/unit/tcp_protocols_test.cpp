// SPDX-License-Identifier: GPL-3.0-or-later
//
// The TCP stream layer with two protocols (feature 004): a direction whose key
// the predicate marks as MSRP uses the MSRP callbacks; every other direction keeps the SIP
// behaviour of feature 002. The protocols are stand-ins here; the real MSRP layer is exercised by
// msrp_test.cpp and test_media_msrp.py.
#include "stream/tcp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::stream;

namespace {

const Bytes kMsrpC2S{10, 0, 0, 1, 10, 0, 0, 2, 0x1b, 0x58, 0x1b, 0x59, 0};  // 7000 -> 7001
const Bytes kMsrpS2C{10, 0, 0, 2, 10, 0, 0, 1, 0x1b, 0x59, 0x1b, 0x58, 0};
const Bytes kSipC2S{10, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40, 0x13, 0xc4, 0};

std::optional<bool> starts(std::string_view d, std::string_view prefix) {
  if (d.size() < prefix.size()) return prefix.starts_with(d) ? std::nullopt : std::optional<bool>(false);
  return d.starts_with(prefix);
}

// Stand-ins: a message runs to "<EOM>\r\n"; SIP rewrites "secret" in place, MSRP replaces its
// first line with a longer one and keeps the rest linear.
Framed frame(std::string_view d) {
  const auto e = d.find("<EOM>\r\n");
  if (e == std::string_view::npos) return {FrameKind::more, 0};
  return {FrameKind::message, e + 7};
}

Result<RewrittenMessage> sip_rewrite(std::string_view m) {
  RewrittenMessage r;
  r.bytes.assign(m);
  r.spans.push_back(Piece{0, m.size(), 0, m.size(), true});
  return r;
}

std::vector<std::string> msrp_seen;

Result<RewrittenMessage> msrp_rewrite(std::string_view m) {
  msrp_seen.emplace_back(m);
  const auto eol = m.find("\r\n") + 2;
  RewrittenMessage r;
  r.bytes = "MSRP PSEUDONYM-TID SEND\r\n";
  r.spans.push_back(Piece{0, eol, 0, r.bytes.size(), false});
  r.bytes.append(m.substr(eol));
  r.spans.push_back(Piece{eol, m.size() - eol, r.spans[0].out_len, m.size() - eol, true});
  return r;
}

SipFns sip() {
  return SipFns{[](std::string_view d) { return starts(d, "INVITE "); }, frame, sip_rewrite};
}
SipFns msrp() {
  return SipFns{[](std::string_view d) { return starts(d, "MSRP "); }, frame, msrp_rewrite};
}

bool is_msrp(const Bytes& key) { return key == kMsrpC2S || key == kMsrpS2C; }

TcpSegment segment(const Bytes& dir, const Bytes& rev, std::uint32_t seq, std::uint32_t ack, const std::string& p,
                   bool syn = false) {
  TcpSegment s;
  s.direction = dir;
  s.reverse = rev;
  s.seq = seq;
  s.ack = ack;
  s.syn = syn;
  s.has_ack = !syn;
  s.payload = ByteView(reinterpret_cast<const std::uint8_t*>(p.data()), p.size());
  s.data_len = p.size();
  return s;
}

std::string text(const Bytes& b) { return std::string(b.begin(), b.end()); }

}  // namespace

TEST_CASE("an MSRP direction uses the MSRP callbacks and its offset map", "[stream][msrp]") {
  msrp_seen.clear();
  TcpStreams t(sip(), false, msrp(), is_msrp);
  std::vector<TcpStreams::Ticket> rdy;
  const std::string syn;
  REQUIRE(t.segment(segment(kMsrpC2S, kMsrpS2C, 100, 0, syn, true), rdy)->ready);
  REQUIRE(t.segment(segment(kMsrpS2C, kMsrpC2S, 900, 101, syn, true), rdy)->ready);
  const std::string part1 = "MSRP abcd SEND\r\nTo-Path: x\r\n";
  const std::string part2 = "content\r\n-------abcd<EOM>\r\n";
  auto a = t.segment(segment(kMsrpC2S, kMsrpS2C, 101, 901, part1), rdy);
  REQUIRE(a.has_value());
  CHECK_FALSE(a->ready);  // the message is incomplete
  auto b = t.segment(segment(kMsrpC2S, kMsrpS2C, 101 + static_cast<std::uint32_t>(part1.size()), 901, part2), rdy);
  REQUIRE(b.has_value());
  REQUIRE(msrp_seen.size() == 1);
  CHECK(msrp_seen[0] == part1 + part2);
  auto o1 = t.take(a->ticket, false, rdy);
  auto o2 = t.take(b->ticket, false, rdy);
  REQUIRE((o1 && o2));
  // The replaced first line goes to the first segment; the rest maps byte by byte.
  CHECK(text(o1->payload).starts_with("MSRP PSEUDONYM-TID SEND\r\n"));
  CHECK(text(o1->payload) + text(o2->payload) == "MSRP PSEUDONYM-TID SEND\r\nTo-Path: x\r\n" + part2);
  CHECK(o2->seq == 101 + static_cast<std::uint32_t>(o1->payload.size()));
  CHECK(t.stats().streams_msrp == 1);
  CHECK(t.stats().streams_sip == 0);
}

TEST_CASE("a SIP direction is unchanged; MSRP bytes on a non-MSRP direction are not MSRP", "[stream][msrp]") {
  msrp_seen.clear();
  TcpStreams t(sip(), false, msrp(), is_msrp);
  std::vector<TcpStreams::Ticket> rdy;
  const std::string syn;
  REQUIRE(t.segment(segment(kSipC2S, kMsrpS2C, 100, 0, syn, true), rdy)->ready);
  const std::string m = "MSRP abcd SEND\r\n<EOM>\r\n";
  auto a = t.segment(segment(kSipC2S, kMsrpS2C, 101, 0, m), rdy);
  REQUIRE(a.has_value());
  auto o = t.take(a->ticket, false, rdy);
  REQUIRE(o.has_value());
  CHECK(msrp_seen.empty());
  CHECK(o->payload == Bytes(m.size(), 0));  // not SIP, not MSRP: zeroed as in 001
}

TEST_CASE("an MSRP direction whose first payload is not MSRP falls back to zeroing", "[stream][msrp]") {
  msrp_seen.clear();
  TcpStreams t(sip(), false, msrp(), is_msrp);
  std::vector<TcpStreams::Ticket> rdy;
  const std::string syn;
  REQUIRE(t.segment(segment(kMsrpC2S, kMsrpS2C, 100, 0, syn, true), rdy)->ready);
  const std::string m = "HELLO there <EOM>\r\n";
  auto a = t.segment(segment(kMsrpC2S, kMsrpS2C, 101, 0, m), rdy);
  auto o = t.take(a->ticket, false, rdy);
  REQUIRE(o.has_value());
  CHECK(msrp_seen.empty());
  CHECK(o->payload == Bytes(m.size(), 0));
}
