// SPDX-License-Identifier: GPL-3.0-or-later
//
// TCP stream state: classification, framing, the offset map that drives
// sequence and acknowledgement numbers, retransmission replay, resynchronisation, bounds and
// the drop-mode deltas that replace the feature-001 renumbering.
//
// The SIP layer is a stand-in here: a "message" is a start line up to an empty line, and the
// rewriter replaces every "secret" by the longer "PSEUDONYM-1234". The real SIP layer is
// exercised end to end by test_sip_tcp.py.
#include "stream/limits.hpp"
#include "stream/tcp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::stream;

namespace {

constexpr std::string_view kSecret = "secret";
constexpr std::string_view kPseudonym = "PSEUDONYM-1234";  // 14 bytes for 6: delta +8

bool start_line(std::string_view line) {
  return line.starts_with("SIP/2.0 ") ||
         ((line.starts_with("INVITE ") || line.starts_with("MESSAGE ")) && line.ends_with(" SIP/2.0"));
}

std::optional<bool> fake_is_start(std::string_view d) {
  const auto eol = d.find("\r\n");
  if (eol == std::string_view::npos) {
    for (const char c : d) {
      if (c < 0x20 || c > 0x7E) return false;
    }
    return d.size() < 256 ? std::nullopt : std::optional<bool>(false);
  }
  return start_line(d.substr(0, eol));
}

Framed fake_frame(std::string_view d) {
  if (d.starts_with("\r")) {
    std::size_t n = 0;
    while (d.substr(n, 2) == "\r\n") n += 2;
    if (n == 0) return {FrameKind::more, 0};
    return {FrameKind::verbatim, n};
  }
  const auto s = fake_is_start(d);
  if (s && !*s) return {FrameKind::invalid, 0};
  const auto end = d.find("\r\n\r\n");
  if (end == std::string_view::npos) return {FrameKind::more, 0};
  return {FrameKind::message, end + 4};
}

Result<RewrittenMessage> fake_rewrite(std::string_view m) {
  RewrittenMessage r;
  if (m.find("BROKEN") != std::string_view::npos) {
    r.zeroed = true;
    return r;
  }
  std::size_t i = 0;
  while (i < m.size()) {
    const auto at = m.find(kSecret, i);
    const std::size_t plain = (at == std::string_view::npos ? m.size() : at) - i;
    if (plain > 0) {
      r.spans.push_back(Piece{i, plain, r.bytes.size(), plain, true});
      r.bytes.append(m.substr(i, plain));
      i += plain;
    }
    if (at == std::string_view::npos) break;
    r.spans.push_back(Piece{i, kSecret.size(), r.bytes.size(), kPseudonym.size(), false});
    r.bytes.append(kPseudonym);
    i += kSecret.size();
  }
  return r;
}

SipFns fake_sip() { return SipFns{fake_is_start, fake_frame, fake_rewrite}; }

std::string rewritten(std::string_view m) { return fake_rewrite(m)->bytes; }

const Bytes kC2S{10, 0, 0, 1, 10, 0, 0, 2, 0x9c, 0x40, 0x13, 0xc4, 0};
const Bytes kS2C{10, 0, 0, 2, 10, 0, 0, 1, 0x13, 0xc4, 0x9c, 0x40, 0};

struct Conn {
  TcpStreams streams;
  std::vector<TcpStreams::Ticket> ready;
  std::uint64_t ts = 1'000'000;
  std::vector<std::string> payloads;  // keep the bytes alive

  explicit Conn(bool drop = false, SipFns fns = fake_sip()) : streams(std::move(fns), drop) {}

  TcpStreams::Arrival seg(const Bytes& dir, std::uint32_t seq, std::uint32_t ack, std::string data,
                          bool syn = false, bool fin = false, bool has_ack = true,
                          std::vector<std::uint32_t> sack = {}) {
    payloads.push_back(std::move(data));
    const std::string& p = payloads.back();
    TcpSegment s;
    s.direction = dir;
    s.reverse = dir == kC2S ? kS2C : kC2S;
    s.seq = seq;
    s.ack = ack;
    s.syn = syn;
    s.fin = fin;
    s.has_ack = has_ack;
    s.sack = std::move(sack);
    s.payload = ByteView(reinterpret_cast<const std::uint8_t*>(p.data()), p.size());
    s.data_len = p.size();
    s.ts_us = ts += 1000;
    auto r = streams.segment(s, ready);
    if (!r) FAIL(r.error().message);
    return *r;
  }
  TcpOutput take(TcpStreams::Ticket t, bool force = false) {
    auto r = streams.take(t, force, ready);
    if (!r) FAIL(r.error().message << " ticket " << t);
    return *r;
  }
  bool became_ready(TcpStreams::Ticket t) const {
    return std::find(ready.begin(), ready.end(), t) != ready.end();
  }
};

std::string text(const Bytes& b) { return std::string(b.begin(), b.end()); }

constexpr std::uint32_t kIsnC = 1000;
constexpr std::uint32_t kIsnS = 50000;

// SYN, SYN/ACK, ACK: data offsets start at ISN + 1 in both directions.
void handshake(Conn& c) {
  REQUIRE(c.seg(kC2S, kIsnC, 0, "", true, false, false).ready);
  REQUIRE(c.seg(kS2C, kIsnS, kIsnC + 1, "", true).ready);
  REQUIRE(c.seg(kC2S, kIsnC + 1, kIsnS + 1, "").ready);
}

const std::string kMsg1 = "INVITE sip:bob SIP/2.0\r\nFrom: secret\r\n\r\n";
const std::string kMsg2 = "SIP/2.0 200 OK\r\nTo: secret and secret\r\n\r\n";

}  // namespace

TEST_CASE("a direction whose first payload is SIP is rewritten, message by message", "[tcp][classify]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1 + kMsg1 + kMsg1);  // 3 messages
  REQUIRE(a.ready);
  const auto o = c.take(a.ticket);
  CHECK(text(o.payload) == rewritten(kMsg1) + rewritten(kMsg1) + rewritten(kMsg1));
  CHECK(o.seq == kIsnC + 1);
  CHECK(o.sip);
  CHECK(c.streams.stats().streams_sip == 1);
}

TEST_CASE("a direction with SYN and a non-SIP first payload is non-SIP at once", "[tcp][classify]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, std::string("\x16\x03\x01\x02\x00secret", 10));
  REQUIRE(a.ready);
  const auto o = c.take(a.ticket);
  CHECK(o.payload == Bytes(10, 0));  // zero mode: zeros of the same length
  CHECK(o.seq == kIsnC + 1);
  CHECK_FALSE(o.sip);
  // Later SIP-looking bytes do not change the classification.
  const auto b = c.seg(kC2S, kIsnC + 11, kIsnS + 1, kMsg1);
  REQUIRE(b.ready);
  CHECK(c.take(b.ticket).payload == Bytes(kMsg1.size(), 0));
  CHECK(c.streams.stats().streams_sip == 0);
  CHECK(c.streams.breakpoints(kC2S) == 1);  // zero mode non-SIP: one identity span
}

TEST_CASE("a message split over three segments is released when complete", "[tcp][framing]") {
  Conn c;
  handshake(c);
  // The first "secret" straddles the first boundary: its pseudonym goes to the first segment.
  const std::size_t cut1 = kMsg1.find("secret") + 3;
  const std::size_t cut2 = kMsg1.size() - 5;
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1.substr(0, cut1));
  const auto b = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(cut1), kIsnS + 1, kMsg1.substr(cut1, cut2 - cut1));
  CHECK_FALSE(a.ready);
  CHECK_FALSE(b.ready);
  const auto e = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(cut2), kIsnS + 1, kMsg1.substr(cut2));
  CHECK(e.ready);
  CHECK(c.became_ready(a.ticket));
  CHECK(c.became_ready(b.ticket));
  const auto oa = c.take(a.ticket);
  const auto ob = c.take(b.ticket);
  const auto oe = c.take(e.ticket);
  const std::string out = rewritten(kMsg1);
  CHECK(text(oa.payload) + text(ob.payload) + text(oe.payload) == out);
  CHECK(text(oa.payload).ends_with(std::string(kPseudonym)));
  CHECK(oa.seq == kIsnC + 1);
  CHECK(ob.seq == kIsnC + 1 + oa.payload.size());
  CHECK(oe.seq == ob.seq + ob.payload.size());
}

TEST_CASE("sequence numbers shift by the delta; ACKs and SACK edges map back", "[tcp][offsets]") {
  Conn c;
  handshake(c);
  const auto m1 = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  const std::uint32_t after1 = kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size());
  const auto m2 = c.seg(kC2S, after1, kIsnS + 1, kMsg1);
  const std::uint32_t delta = static_cast<std::uint32_t>(rewritten(kMsg1).size() - kMsg1.size());
  REQUIRE(m1.ready);
  REQUIRE(m2.ready);
  (void)c.take(m1.ticket);
  CHECK(c.take(m2.ticket).seq == after1 + delta);

  // The server acknowledges the first message, then both.
  const auto a1 = c.seg(kS2C, kIsnS + 1, after1, "");
  REQUIRE(a1.ready);
  CHECK(*c.take(a1.ticket).ack == after1 + delta);
  const std::uint32_t after2 = after1 + static_cast<std::uint32_t>(kMsg1.size());
  const auto a2 = c.seg(kS2C, kIsnS + 1, after2, "");
  CHECK(*c.take(a2.ticket).ack == after2 + 2 * delta);

  // An ACK inside a replaced token maps to the end of its replacement.
  const std::uint32_t in_token = after1 + static_cast<std::uint32_t>(kMsg1.find("secret") + 2);
  const auto a3 = c.seg(kS2C, kIsnS + 1, in_token, "");
  const std::uint32_t token_end_out =
      after1 + delta + static_cast<std::uint32_t>(kMsg1.find("secret") + kPseudonym.size());
  CHECK(*c.take(a3.ticket).ack == token_end_out);

  // SACK edges are mapped the same way.
  const auto a4 = c.seg(kS2C, kIsnS + 1, after1, "", false, false, true, {after1, after2});
  const auto o4 = c.take(a4.ticket);
  REQUIRE(o4.sack_known);
  CHECK(o4.sack == std::vector<std::uint32_t>{after1 + delta, after2 + 2 * delta});
}

TEST_CASE("an ACK of bytes still being framed waits for the message", "[tcp][offsets]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1.substr(0, 20));
  const auto ack = c.seg(kS2C, kIsnS + 1, kIsnC + 21, "");
  CHECK_FALSE(a.ready);
  CHECK_FALSE(ack.ready);
  const auto b = c.seg(kC2S, kIsnC + 21, kIsnS + 1, kMsg1.substr(20));
  CHECK(b.ready);
  CHECK(c.became_ready(ack.ticket));
  const auto oa = c.take(a.ticket);
  CHECK(*c.take(ack.ticket).ack == kIsnC + 1 + oa.payload.size());
}

TEST_CASE("keep-alive CRLFs between messages are kept verbatim", "[tcp][framing]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, "\r\n\r\n" + kMsg1 + "\r\n");
  REQUIRE(a.ready);
  CHECK(text(c.take(a.ticket).payload) == "\r\n\r\n" + rewritten(kMsg1) + "\r\n");
}

TEST_CASE("retransmissions replay the cached output byte for byte", "[tcp][retransmission]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  const auto first = c.take(a.ticket);
  const auto r = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);  // full retransmission
  REQUIRE(r.ready);
  const auto again = c.take(r.ticket);
  CHECK(again.payload == first.payload);
  CHECK(again.seq == first.seq);
  // An overlapping retransmission: old bytes plus a new message.
  const std::size_t half = kMsg1.size() / 2;
  const auto ov = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(half), kIsnS + 1,
                        kMsg1.substr(half) + kMsg2);
  REQUIRE(ov.ready);
  const auto o = c.take(ov.ticket);
  CHECK(text(o.payload).ends_with(rewritten(kMsg2)));
  CHECK(c.streams.stats().retransmissions_replayed == 2);
}

TEST_CASE("a retransmission of evicted output is zero-filled, its numbers still mapped", "[tcp][retransmission]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  const auto first = c.take(a.ticket);
  std::uint32_t seq = kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size());
  std::string bulk;
  while (bulk.size() < kRetransCacheBytes + 4096) bulk += kMsg2;
  for (std::size_t off = 0; off < bulk.size(); off += 1400) {
    const auto chunk = bulk.substr(off, 1400);
    const auto t = c.seg(kC2S, seq, kIsnS + 1, chunk);
    seq += static_cast<std::uint32_t>(chunk.size());
    if (t.ready) (void)c.take(t.ticket);
  }
  for (const auto t : c.ready) {
    if (c.streams.ready(t)) (void)c.take(t);
  }
  const auto r = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  REQUIRE(r.ready);
  const auto again = c.take(r.ticket);
  CHECK(again.payload == Bytes(first.payload.size(), 0));
  CHECK(again.seq == first.seq);
  CHECK(c.streams.stats().retransmissions_zeroed == 1);
}

TEST_CASE("reordered segments are rewritten once the gap is filled", "[tcp][reorder]") {
  Conn c;
  handshake(c);
  const std::string two = kMsg1 + kMsg2;
  const std::size_t cut = 30;
  const auto late = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(cut), kIsnS + 1, two.substr(cut));
  CHECK_FALSE(late.ready);
  const auto early = c.seg(kC2S, kIsnC + 1, kIsnS + 1, two.substr(0, cut));
  CHECK(early.ready);
  CHECK(c.became_ready(late.ticket));
  CHECK(text(c.take(early.ticket).payload) + text(c.take(late.ticket).payload) ==
        rewritten(kMsg1) + rewritten(kMsg2));
}

TEST_CASE("unframable bytes are zeroed with their length and the stream resynchronises", "[tcp][unframable]") {
  Conn c;
  handshake(c);
  const std::string junk = "garbage line\r\nmore garbage\r\n";
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1 + junk + kMsg2);
  REQUIRE(a.ready);
  // The line end before the resynchronisation point is kept (a decoder resynchronises too).
  CHECK(text(c.take(a.ticket).payload) ==
        rewritten(kMsg1) + std::string(junk.size() - 2, '\0') + "\r\n" + rewritten(kMsg2));
  CHECK(c.streams.stats().bytes_unframable == junk.size() - 2);
}

TEST_CASE("a forced incomplete message is zeroed and later bytes are searched", "[tcp][unframable]") {
  Conn c;
  handshake(c);
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1.substr(0, 25));
  REQUIRE_FALSE(a.ready);
  const auto o = c.take(a.ticket, true);
  CHECK(o.payload == Bytes(25, 0));
  CHECK(c.streams.stats().forced == 1);
  // The rest of the abandoned message is zeroed; the next message is found again.
  const auto b = c.seg(kC2S, kIsnC + 26, kIsnS + 1, kMsg1.substr(25) + kMsg2);
  REQUIRE(b.ready);
  CHECK(text(c.take(b.ticket).payload) == std::string(kMsg1.size() - 27, '\0') + "\r\n" + rewritten(kMsg2));
}

TEST_CASE("a malformed message is zeroed in zero mode", "[tcp][unframable]") {
  Conn c;
  handshake(c);
  const std::string bad = "INVITE sip:x SIP/2.0\r\nX: BROKEN secret\r\n\r\n";
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, bad + kMsg1);
  REQUIRE(a.ready);
  CHECK(text(c.take(a.ticket).payload) == std::string(bad.size(), '\0') + rewritten(kMsg1));
}

TEST_CASE("an oversized message is zeroed as unframable", "[tcp][bounds]") {
  Conn c;
  handshake(c);
  std::string big = "INVITE sip:big SIP/2.0\r\nX: ";
  big += std::string(kMaxStreamMessageBytes, 'x');
  std::uint32_t seq = kIsnC + 1;
  std::vector<TcpStreams::Ticket> tickets;
  for (std::size_t off = 0; off < big.size(); off += 60000) {
    const auto chunk = big.substr(off, 60000);
    tickets.push_back(c.seg(kC2S, seq, kIsnS + 1, chunk).ticket);
    seq += static_cast<std::uint32_t>(chunk.size());
  }
  for (const auto t : tickets) CHECK(c.streams.ready(t));
  CHECK(c.streams.stats().bytes_unframable >= kMaxStreamMessageBytes);
}

TEST_CASE("a mid-stream start searches for a start line", "[tcp][midstream]") {
  Conn c;
  // No SYN: the first payload is the 3 KiB tail of a message.
  std::string tail;
  while (tail.size() < 3072) tail += "a=secret-attribute-line\r\n";
  tail += "\r\n";
  const auto a = c.seg(kC2S, 777777, 5555, tail);
  REQUIRE(a.ready);
  CHECK(text(c.take(a.ticket).payload) == std::string(tail.size() - 2, '\0') + "\r\n");
  const auto b = c.seg(kC2S, 777777 + static_cast<std::uint32_t>(tail.size()), 5555, kMsg1);
  REQUIRE(b.ready);
  const auto ob = c.take(b.ticket);
  CHECK(text(ob.payload) == rewritten(kMsg1));
  CHECK(ob.seq == 777777 + tail.size());
  CHECK(c.streams.stats().streams_sip == 1);
  CHECK(c.streams.stats().bytes_unframable == tail.size() - 2);
}

TEST_CASE("after 1 MiB without a start line a direction is non-SIP", "[tcp][midstream]") {
  Conn c;
  std::uint32_t seq = 1;
  std::size_t total = 0;
  const std::string line = "some text that is not a start line\r\n";
  std::string chunk;
  while (chunk.size() < 60000) chunk += line;
  while (total < kMaxSearchBytes + chunk.size()) {
    const auto t = c.seg(kC2S, seq, 1, chunk);
    CHECK(t.ready);
    seq += static_cast<std::uint32_t>(chunk.size());
    total += chunk.size();
  }
  const auto m = c.seg(kC2S, seq, 1, kMsg1);
  REQUIRE(m.ready);
  CHECK(c.take(m.ticket).payload == Bytes(kMsg1.size(), 0));
  CHECK(c.streams.stats().streams_sip == 0);
  CHECK(c.streams.stats().bytes_unframable == 0);  // never proved to be SIP: not counted
}

TEST_CASE("SYN and FIN consume one sequence number each", "[tcp][synfin]") {
  Conn c;
  handshake(c);
  const auto m = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  const std::uint32_t delta = static_cast<std::uint32_t>(rewritten(kMsg1).size() - kMsg1.size());
  const std::uint32_t end = kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size());
  (void)c.take(m.ticket);
  const auto fin = c.seg(kC2S, end, kIsnS + 1, "", false, true);
  CHECK(c.take(fin.ticket).seq == end + delta);
  const auto finack = c.seg(kS2C, kIsnS + 1, end + 1, "", false, true);
  CHECK(*c.take(finack.ticket).ack == end + delta + 1);
  const auto last = c.seg(kC2S, end + 1, kIsnS + 2, "");
  const auto ol = c.take(last.ticket);
  CHECK(ol.seq == end + delta + 1);
  CHECK(*ol.ack == kIsnS + 2);
}

TEST_CASE("drop mode reproduces the feature-001 numbering for non-SIP flows", "[tcp][drop]") {
  Conn c(true, SipFns{});
  const auto syn = c.take(c.seg(kC2S, kIsnC, 0, "", true, false, false).ticket);
  const auto synack = c.take(c.seg(kS2C, kIsnS, kIsnC + 1, "", true).ticket);
  const auto ack = c.take(c.seg(kC2S, kIsnC + 1, kIsnS + 1, "").ticket);
  const auto d1 = c.take(c.seg(kC2S, kIsnC + 1, kIsnS + 1, std::string(100, 'A')).ticket);
  const auto d2 = c.take(c.seg(kC2S, kIsnC + 101, kIsnS + 1, std::string(100, 'A')).ticket);
  const auto r1 = c.take(c.seg(kS2C, kIsnS + 1, kIsnC + 201, std::string(500, 'B')).ticket);
  const auto fin = c.take(c.seg(kC2S, kIsnC + 201, kIsnS + 501, "", false, true).ticket);
  const auto finack = c.take(c.seg(kS2C, kIsnS + 501, kIsnC + 202, "", false, true).ticket);
  const auto last = c.take(c.seg(kC2S, kIsnC + 202, kIsnS + 502, "").ticket);
  CHECK(syn.seq == kIsnC);
  CHECK(synack.seq == kIsnS);
  CHECK(*synack.ack == kIsnC + 1);
  CHECK(ack.seq == kIsnC + 1);
  CHECK(d1.seq == kIsnC + 1);
  CHECK(d1.payload.empty());
  CHECK(d2.seq == kIsnC + 1);
  CHECK(*r1.ack == kIsnC + 1);
  CHECK(fin.seq == kIsnC + 1);
  CHECK(*finack.ack == kIsnC + 2);
  CHECK(last.seq == kIsnC + 2);
  CHECK(*last.ack == kIsnS + 2);
  // Without the reverse direction, the first ACK value stays (001/R8).
  Conn one(true, SipFns{});
  const auto x = one.take(one.seg(kC2S, 7, 900, "abc").ticket);
  const auto y = one.take(one.seg(kC2S, 10, 1400, "def").ticket);
  CHECK(*x.ack == 900);
  CHECK(*y.ack == 900);
  CHECK_FALSE(y.sack_known);
}

TEST_CASE("drop mode keeps SIP and removes non-SIP bytes of a mixed connection", "[tcp][drop]") {
  Conn c(true);
  handshake(c);
  const auto m = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1);
  REQUIRE(m.ready);
  CHECK(text(c.take(m.ticket).payload) == rewritten(kMsg1));
  // The server answers with binary data: removed, delta minus its length.
  const auto bin = c.seg(kS2C, kIsnS + 1, kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size()),
                         std::string(300, '\x01'));
  REQUIRE(bin.ready);
  const auto ob = c.take(bin.ticket);
  CHECK(ob.payload.empty());
  CHECK(*ob.ack == kIsnC + 1 + rewritten(kMsg1).size());
  const auto ack = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size()), kIsnS + 301, "");
  CHECK(*c.take(ack.ticket).ack == kIsnS + 1);
}

TEST_CASE("breakpoints below the peer's ACK are pruned", "[tcp][offsets]") {
  Conn c;
  handshake(c);
  std::string msg = "MESSAGE sip:x SIP/2.0\r\nX:";
  for (int i = 0; i < 200; ++i) msg += " secret";
  msg += "\r\n\r\n";
  const auto m = c.seg(kC2S, kIsnC + 1, kIsnS + 1, msg);
  REQUIRE(m.ready);
  const auto om = c.take(m.ticket);
  CHECK(c.streams.breakpoints(kC2S) > 200);
  const std::uint32_t end = kIsnC + 1 + static_cast<std::uint32_t>(msg.size());
  const auto a = c.seg(kS2C, kIsnS + 1, end, "");
  CHECK(*c.take(a.ticket).ack == kIsnC + 1 + om.payload.size());
  CHECK(c.streams.breakpoints(kC2S) <= 2);
  // Numbers after the pruned range are still exact.
  const auto n = c.seg(kC2S, end, kIsnS + 1, kMsg1);
  CHECK(c.take(n.ticket).seq == kIsnC + 1 + om.payload.size());
}

TEST_CASE("the direction table evicts the least recently active direction", "[tcp][bounds]") {
  Conn c;
  // The oldest direction holds an incomplete message.
  REQUIRE(c.seg(kC2S, kIsnC, 0, "", true, false, false).ready);
  const auto pending = c.seg(kC2S, kIsnC + 1, 0, kMsg1.substr(0, 20), false, false, false);
  REQUIRE_FALSE(pending.ready);
  for (std::uint32_t i = 0; i < kMaxTcpDirections; ++i) {
    Bytes key{192, 168, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 10, 0, 0, 9, 0, 1, 0, 2, 0};
    const auto t = c.seg(key, 1, 0, "", true, false, false);
    (void)c.take(t.ticket);
  }
  CHECK(c.streams.directions() == kMaxTcpDirections);
  CHECK(c.streams.stats().directions_evicted == 1);
  CHECK(c.became_ready(pending.ticket));
  CHECK(c.take(pending.ticket).payload == Bytes(20, 0));
}

TEST_CASE("truncated segments are a gap: zeroed, counted, resynchronised", "[tcp][unframable]") {
  Conn c;
  handshake(c);
  TcpSegment s;
  s.direction = kC2S;
  s.reverse = kS2C;
  s.seq = kIsnC + 1;
  s.ack = kIsnS + 1;
  s.has_ack = true;
  const std::string head = kMsg1.substr(0, 10);
  s.payload = ByteView(reinterpret_cast<const std::uint8_t*>(head.data()), head.size());
  s.data_len = kMsg1.size();
  auto a = c.streams.segment(s, c.ready);
  REQUIRE(a.has_value());
  REQUIRE(a->ready);
  CHECK(c.take(a->ticket).payload == Bytes(10, 0));
  const auto b = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(kMsg1.size()), kIsnS + 1, kMsg2);
  REQUIRE(b.ready);
  CHECK(text(c.take(b.ticket).payload) == rewritten(kMsg2));
}

TEST_CASE("the stream state is deterministic", "[tcp]") {
  const auto run = [] {
    Conn c;
    handshake(c);
    std::string all;
    const std::string two = kMsg1 + "junk\r\n" + kMsg2;
    std::uint32_t seq = kIsnC + 1;
    for (std::size_t off = 0; off < two.size(); off += 7) {
      const auto t = c.seg(kC2S, seq, kIsnS + 1, two.substr(off, 7));
      seq += static_cast<std::uint32_t>(std::min<std::size_t>(7, two.size() - off));
      (void)t;
    }
    for (TcpStreams::Ticket t = 1; t < 100; ++t) {
      auto r = c.streams.take(t, true, c.ready);
      if (r) all += std::to_string(r->seq) + ":" + text(r->payload) + "|";
    }
    return all;
  };
  CHECK(run() == run());
}

TEST_CASE("the segment with a message's last byte carries its last output byte", "[tcp][framing]") {
  // A rewriter that replaces the last 10 bytes of every message by one byte (an emptied body).
  SipFns fns = fake_sip();
  fns.rewrite = [](std::string_view m) -> Result<RewrittenMessage> {
    RewrittenMessage r;
    const std::size_t keep = m.size() - 10;
    r.bytes = std::string(m.substr(0, keep)) + "!";
    r.spans = {Piece{0, keep, 0, keep, true}, Piece{keep, 10, keep, 1, false}};
    return r;
  };
  Conn c(false, fns);
  handshake(c);
  const std::size_t cut = kMsg1.size() - 3;
  const auto a = c.seg(kC2S, kIsnC + 1, kIsnS + 1, kMsg1.substr(0, cut));
  const auto b = c.seg(kC2S, kIsnC + 1 + static_cast<std::uint32_t>(cut), kIsnS + 1, kMsg1.substr(cut));
  REQUIRE(b.ready);
  const auto oa = c.take(a.ticket);
  const auto ob = c.take(b.ticket);
  CHECK(text(oa.payload) + text(ob.payload) == kMsg1.substr(0, kMsg1.size() - 10) + "!");
  CHECK(text(ob.payload) == "!");  // the message still completes in the second segment
}

TEST_CASE("an oversized message with a declared length is skipped exactly", "[tcp][bounds]") {
  constexpr std::size_t kBig = kMaxStreamMessageBytes + 5000;
  const std::string head = "MESSAGE sip:big SIP/2.0\r\n";
  SipFns fns = fake_sip();
  fns.frame = [&](std::string_view d) -> Framed {
    if (d.starts_with(head)) return {FrameKind::oversized, kBig};
    return fake_frame(d);
  };
  Conn c(false, fns);
  handshake(c);
  std::string big = head + std::string(kBig - head.size(), 's');
  big += kMsg1;  // the next message follows the body directly, not at a line start
  std::uint32_t seq = kIsnC + 1;
  std::string out;
  for (std::size_t off = 0; off < big.size(); off += 50000) {
    const auto chunk = big.substr(off, 50000);
    const auto t = c.seg(kC2S, seq, kIsnS + 1, chunk);
    REQUIRE(t.ready);
    out += text(c.take(t.ticket).payload);
    seq += static_cast<std::uint32_t>(chunk.size());
  }
  CHECK(out == std::string(kBig - 2, '\0') + "\r\n" + rewritten(kMsg1));
  CHECK(c.streams.stats().bytes_unframable == kBig - 2);
}
