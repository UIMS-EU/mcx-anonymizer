// SPDX-License-Identifier: GPL-3.0-or-later
//
// IP fragment reassembly: which datagrams are tracked, when one is complete or
// ambiguous, bounds, and the rewriter's halves of refragmentation (the reassembled packet, and
// an output fragment built on an original fragment's headers).
#include "rewrite_test_util.hpp"
#include "stream/fragments.hpp"
#include "stream/limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;
using namespace mcxanon::stream;

namespace {

bool looks_sip(ByteView p) {
  const std::string_view s(reinterpret_cast<const char*>(p.data()), p.size());
  return s.starts_with("MESSAGE ") || s.starts_with("SIP/2.0 ");
}

const std::string kBody = "MESSAGE sip:alice@example.net SIP/2.0\r\nContent-Length: 200\r\n\r\n" + std::string(200, 'x');

Bytes datagram() { return udp(5060, 5060, text(kBody), pseudo_sum_v4(kIpA, kIpB, 17, 8 + kBody.size())); }

// IPv4 fragment `[off, off + len)` of `dg` with identification `id`.
Bytes frag4(const Bytes& dg, std::size_t off, std::size_t len, std::uint16_t id = 0x1234) {
  const bool more = off + len < dg.size();
  Bytes p = ipv4(kIpA, kIpB, 17, Bytes(dg.begin() + static_cast<std::ptrdiff_t>(off),
                                       dg.begin() + static_cast<std::ptrdiff_t>(off + len)),
                 {}, static_cast<std::uint16_t>((more ? 0x2000u : 0u) | (off / 8)));
  store16(p, 4, id, Endian::big);
  store16(p, 10, 0, Endian::big);
  store16(p, 10, inet_checksum(ByteView(p).first(20)), Endian::big);
  return p;
}

// IPv6 fragment with a Fragment header (RFC 8200 §4.5).
Bytes frag6(const Bytes& dg, std::size_t off, std::size_t len, std::uint32_t id = 77) {
  const bool more = off + len < dg.size();
  Bytes fh{17, 0};
  fh = fh + b16(static_cast<std::uint16_t>((off / 8) << 3 | (more ? 1u : 0u))) + b32(id);
  return ipv6(kIp6A, kIp6B, 44, fh + Bytes(dg.begin() + static_cast<std::ptrdiff_t>(off),
                                         dg.begin() + static_cast<std::ptrdiff_t>(off + len)));
}

FragmentInfo info(const Bytes& pkt, std::uint16_t lt = kLinkRaw) {
  auto f = fragment_of(dissect(lt, pkt), pkt, &looks_sip);
  REQUIRE(f.has_value());
  return *f;
}

Bytes gtpu(const Bytes& inner) {
  return udp4(kIpA, kIpB, 2152, 2152, Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(7) + inner);
}

}  // namespace

TEST_CASE("fragments are keyed per address pair, protocol, identification and tunnel depth", "[fragment][key]") {
  const Bytes dg = datagram();
  const auto a = info(frag4(dg, 0, 96));
  const auto b = info(frag4(dg, 96, dg.size() - 96));
  CHECK(a.key == b.key);
  CHECK(a.offset == 0);
  CHECK(a.more);
  CHECK(b.offset == 96);
  CHECK_FALSE(b.more);
  CHECK(a.sip == std::optional<bool>(true));
  CHECK_FALSE(b.sip.has_value());
  CHECK(info(frag4(dg, 0, 96, 0x9999)).key != a.key);
  const auto v6 = info(frag6(dg, 0, 96));
  CHECK(v6.key != a.key);
  CHECK(v6.key == info(frag6(dg, 96, dg.size() - 96)).key);
  CHECK(v6.key != info(frag6(dg, 0, 96, 78)).key);
  // The same fragment inside a GTP-U tunnel is another datagram.
  const auto inner = info(gtpu(frag4(dg, 0, 96)));
  CHECK(inner.key != a.key);
  CHECK(inner.sip == std::optional<bool>(true));
  // Not a fragment, or embedded in an ICMP error: none.
  const Bytes whole = ipv4(kIpA, kIpB, 17, dg);
  CHECK_FALSE(fragment_of(dissect(kLinkRaw, whole), whole, &looks_sip).has_value());
}

TEST_CASE("a datagram completes in order, out of order and with identical duplicates", "[fragment][table]") {
  const Bytes dg = datagram();
  for (const std::vector<std::size_t>& order :
       {std::vector<std::size_t>{0, 1, 2}, {2, 0, 1}, {1, 2, 1, 0}, {0, 0, 2, 1}}) {
    FragmentTable t;
    std::vector<FragmentTable::Ticket> ready;
    const std::size_t cuts[] = {0, 96, 192, dg.size()};
    std::vector<FragmentTable::Arrival> got;
    for (std::size_t i = 0; i < order.size(); ++i) {
      const std::size_t k = order[i];
      got.push_back(t.add(info(frag4(dg, cuts[k], cuts[k + 1] - cuts[k])), ready));
      REQUIRE(got.back().tracked);
    }
    CHECK(got.back().ready);
    const auto dgid = got.back().datagram;
    REQUIRE(t.verdict(dgid) == FragmentTable::Verdict::complete);
    CHECK(t.reassembled(dgid) == dg);
    CHECK(t.chunk_size(dgid) == 96);
    CHECK(t.ranks(dgid) == 3);
    for (std::size_t i = 0; i + 1 < got.size(); ++i) CHECK(std::find(ready.begin(), ready.end(), got[i].ticket) != ready.end());
    CHECK(t.rank(got[0].ticket) == order[0]);
    CHECK(t.stats().datagrams_reassembled == 1);
  }
}

TEST_CASE("an empty middle fragment does not break reassembly", "[fragment][table]") {
  // Found by fuzz_ip_reassembly: a fragment with no payload bytes reached memcpy with a null
  // source (undefined even for length 0).
  const Bytes dg = datagram();
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  t.add(info(frag4(dg, 0, 96)), ready);
  t.add(info(frag4(dg, 96, 0)), ready);
  const auto last = t.add(info(frag4(dg, 96, dg.size() - 96)), ready);
  REQUIRE(last.ready);
  CHECK(t.reassembled(last.datagram) == dg);
}

TEST_CASE("conflicting overlaps, differing duplicates and length conflicts are ambiguous", "[fragment][table]") {
  const Bytes dg = datagram();
  SECTION("conflicting overlap") {
    FragmentTable t;
    std::vector<FragmentTable::Ticket> ready;
    Bytes other = dg;
    other[100] ^= 0xFF;
    const auto a = t.add(info(frag4(dg, 0, 104)), ready);
    const auto b = t.add(info(frag4(other, 96, dg.size() - 96)), ready);
    CHECK(b.ready);
    CHECK(t.verdict(a.datagram) == FragmentTable::Verdict::zero);
    CHECK(std::find(ready.begin(), ready.end(), a.ticket) != ready.end());
    CHECK(t.stats().datagrams_ambiguous == 1);
  }
  SECTION("identical overlap is accepted") {
    FragmentTable t;
    std::vector<FragmentTable::Ticket> ready;
    (void)t.add(info(frag4(dg, 0, 104)), ready);
    const auto b = t.add(info(frag4(dg, 96, dg.size() - 96)), ready);
    CHECK(t.verdict(b.datagram) == FragmentTable::Verdict::complete);
    CHECK(t.reassembled(b.datagram) == dg);
  }
  SECTION("an earlier fragment that ends beyond the last fragment's end") {
    FragmentTable t;
    std::vector<FragmentTable::Ticket> ready;
    (void)t.add(info(frag4(dg, 0, 192)), ready);
    Bytes last = frag4(dg, 96, 48);
    store16(last, 6, 96 / 8, Endian::big);  // MF cleared: the datagram would end at 144
    store16(last, 10, 0, Endian::big);
    store16(last, 10, inet_checksum(ByteView(last).first(20)), Endian::big);
    const auto b = t.add(info(last), ready);
    CHECK(t.verdict(b.datagram) == FragmentTable::Verdict::zero);
  }
  SECTION("two last fragments that disagree on the length") {
    FragmentTable t;
    std::vector<FragmentTable::Ticket> ready;
    (void)t.add(info(frag4(dg, 96, dg.size() - 96)), ready);
    const auto b = t.add(info(frag4(dg, 96, dg.size() - 104)), ready);
    CHECK(t.verdict(b.datagram) == FragmentTable::Verdict::zero);
  }
}

TEST_CASE("a missing fragment keeps the datagram pending until it is given up", "[fragment][table]") {
  const Bytes dg = datagram();
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  const auto a = t.add(info(frag4(dg, 0, 96)), ready);
  const auto c = t.add(info(frag4(dg, 192, dg.size() - 192)), ready);
  CHECK_FALSE(a.ready);
  CHECK_FALSE(c.ready);
  CHECK(t.verdict(a.datagram) == FragmentTable::Verdict::pending);
  t.abandon(a.datagram, FragmentTable::Abandon::missing, ready);
  CHECK(t.verdict(a.datagram) == FragmentTable::Verdict::zero);
  CHECK(t.ready(a.ticket));
  CHECK(t.ready(c.ticket));
  CHECK(t.stats().datagrams_incomplete == 1);
  // A late fragment of the given-up datagram is not tracked (feature 001 behaviour).
  CHECK_FALSE(t.add(info(frag4(dg, 96, 96)), ready).tracked);
}

TEST_CASE("a given-up datagram is counted by the reason it was given up", "[fragment][table]") {
  const Bytes dg = datagram();
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  const auto a = t.add(info(frag4(dg, 0, 96, 0x101)), ready);
  const auto b = t.add(info(frag4(dg, 0, 96, 0x102)), ready);
  const auto c = t.add(info(frag4(dg, 0, 96, 0x103)), ready);
  t.abandon(a.datagram, FragmentTable::Abandon::missing, ready);
  t.abandon(b.datagram, FragmentTable::Abandon::timeout, ready);
  t.abandon(c.datagram, FragmentTable::Abandon::bound, ready);
  t.abandon(c.datagram, FragmentTable::Abandon::missing, ready);  // already decided: not counted
  CHECK(t.stats().datagrams_incomplete == 1);
  CHECK(t.stats().datagrams_timed_out == 1);
  CHECK(t.stats().datagrams_held_bound == 1);
}

TEST_CASE("datagrams that are not SIP and transports other than UDP are not tracked", "[fragment][table]") {
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  const Bytes other = udp(1000, 2000, Bytes(300, 0x41));
  // A later fragment first: tracked until the first fragment shows the datagram is not SIP.
  const auto late = t.add(info(frag4(other, 104, other.size() - 104)), ready);
  CHECK(late.tracked);
  CHECK_FALSE(late.ready);
  CHECK_FALSE(t.add(info(frag4(other, 0, 104)), ready).tracked);
  CHECK(std::find(ready.begin(), ready.end(), late.ticket) != ready.end());
  CHECK(t.verdict(late.datagram) == FragmentTable::Verdict::zero);
  // TCP over fragments keeps the feature-001 behaviour.
  Bytes tcpfrag = ipv4(kIpA, kIpB, 6, Bytes(64, 1), {}, 0x2000);
  CHECK_FALSE(t.add(info(tcpfrag), ready).tracked);
}

TEST_CASE("a truncated fragment makes the datagram ambiguous", "[fragment][table]") {
  const Bytes dg = datagram();
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  Bytes p = frag4(dg, 0, 96);
  p.resize(p.size() - 10);  // snaplen cut
  const auto a = t.add(info(p), ready);
  CHECK(a.ready);
  CHECK(t.verdict(a.datagram) == FragmentTable::Verdict::zero);
}

TEST_CASE("more than 4096 pending datagrams evict the oldest", "[fragment][bounds]") {
  const Bytes dg = datagram();
  FragmentTable t;
  std::vector<FragmentTable::Ticket> ready;
  const auto first = t.add(info(frag4(dg, 0, 96, 0)), ready);
  for (std::uint16_t id = 1; id <= kMaxPendingDatagrams; ++id) (void)t.add(info(frag4(dg, 0, 96, id)), ready);
  CHECK(t.pending() == kMaxPendingDatagrams);
  CHECK(t.stats().datagrams_evicted == 1);
  CHECK(t.verdict(first.datagram) == FragmentTable::Verdict::zero);
  CHECK(std::find(ready.begin(), ready.end(), first.ticket) != ready.end());
}

TEST_CASE("the reassembled packet is a valid unfragmented packet", "[fragment][rewrite]") {
  const Bytes dg = datagram();
  for (const bool v6 : {false, true}) {
    INFO((v6 ? "IPv6" : "IPv4"));
    const Bytes first = v6 ? frag6(dg, 0, 96) : frag4(dg, 0, 96);
    const auto f = info(first);
    auto pkt = reassembled_packet(kLinkRaw, first, 0, f.layer, dg);
    REQUIRE(pkt.has_value());
    const Dissection d = dissect(kLinkRaw, *pkt);
    CHECK_FALSE(d.layers[0].fragment_first);
    CHECK_FALSE(d.layers[0].fragment_nonfirst);
    if (v6) {
      CHECK(be16(*pkt, 4) == 8 + dg.size());
    } else {
      CHECK(be16(*pkt, 2) == 20 + dg.size());
      CHECK(ipv4_header_ok(*pkt));
      CHECK(l4_ok_v4(*pkt, 0, 17));
    }
    const auto reg = fragmentable_region(kLinkRaw, *pkt, 0, f.layer);
    REQUIRE(reg.has_value());
    CHECK(Bytes(pkt->begin() + static_cast<std::ptrdiff_t>(reg->first),
                pkt->begin() + static_cast<std::ptrdiff_t>(reg->second)) == dg);
  }
}

TEST_CASE("an output fragment carries its part on the original fragment's headers", "[fragment][rewrite]") {
  const Bytes dg = datagram();
  const Bytes orig = frag4(dg, 96, 96);
  Rewriter rw;
  const FragmentOverride fo{Bytes(120, 0x5A), 120, true};
  auto r = rewrite_packet(kLinkRaw, orig, 0, *rw.policy, rw.mapper, rw.options, rw.stats, nullptr, nullptr, &fo);
  REQUIRE(r.has_value());
  CHECK(r->data.size() == 20 + 120);
  CHECK(be16(r->data, 2) == 140);
  CHECK(be16(r->data, 6) == (0x2000 | 15));
  CHECK(ipv4_header_ok(r->data));
  CHECK(Bytes(r->data.begin() + 20, r->data.end()) == Bytes(120, 0x5A));
  // The last fragment: MF cleared. In drop mode the fragment is kept, not dropped.
  rw.options.payload = PayloadPolicy::drop;
  const FragmentOverride last{Bytes(16, 0x5B), 240, false};
  auto z = rewrite_packet(kLinkRaw, orig, 0, *rw.policy, rw.mapper, rw.options, rw.stats, nullptr, nullptr, &last);
  REQUIRE(z.has_value());
  CHECK_FALSE(z->drop);
  CHECK(be16(z->data, 6) == 30);
  CHECK(be16(z->data, 2) == 36);
  // IPv6: offset and M flag in the Fragment header, payload length follows.
  const Bytes o6 = frag6(dg, 0, 96);
  Rewriter rw6;
  const FragmentOverride f6{Bytes(48, 0x11), 0, true};
  auto s = rewrite_packet(kLinkRaw, o6, 0, *rw6.policy, rw6.mapper, rw6.options, rw6.stats, nullptr, nullptr, &f6);
  REQUIRE(s.has_value());
  CHECK(be16(s->data, 4) == 8 + 48);
  CHECK(be16(s->data, 42) == 1);
  CHECK(Bytes(s->data.begin() + 48, s->data.end()) == Bytes(48, 0x11));
}

TEST_CASE("an output fragment inside GTP-U adjusts every enclosing length", "[fragment][rewrite][tunnel]") {
  const Bytes dg = datagram();
  const Bytes orig = gtpu(frag4(dg, 0, 96));
  const auto f = info(orig);
  Rewriter rw;
  const FragmentOverride fo{Bytes(dg.begin(), dg.begin() + 144), 0, true};
  auto r = rewrite_packet(kLinkRaw, orig, 0, *rw.policy, rw.mapper, rw.options, rw.stats, nullptr, nullptr, &fo);
  REQUIRE(r.has_value());
  const std::size_t inner = 20 + 8 + 8;
  CHECK(be16(r->data, 2) == r->data.size());                 // outer IPv4
  CHECK(be16(r->data, 24) == r->data.size() - 20);           // outer UDP
  CHECK(be16(r->data, 30) == r->data.size() - inner);        // GTP-U
  CHECK(be16(r->data, inner + 2) == 20 + 144);               // inner IPv4
  CHECK(ipv4_header_ok(r->data));
  CHECK(ipv4_header_ok(r->data, inner));
  CHECK(l4_ok_v4(r->data, 0, 17));
  // The datagram's own UDP header came with the chunk, checksum included.
  CHECK(Bytes(r->data.begin() + inner + 20, r->data.begin() + inner + 28) == Bytes(dg.begin(), dg.begin() + 8));
  (void)f;
}
