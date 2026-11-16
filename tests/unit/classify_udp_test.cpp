// SPDX-License-Identifier: GPL-3.0-or-later
//
// The context-aware UDP media classifier of the dissector: the callback sees the
// innermost addresses and ports; a non-zero tag makes the payload payload.media.
#include "dissect/packet.hpp"
#include "packet_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {

struct Seen {
  Bytes src, dst;
  std::uint16_t sport = 0, dport = 0;
  int depth = -1;
  std::size_t payload = 0;
};

struct Ctx {
  std::vector<Seen> calls;
  std::uint16_t media_port = 40000;
  int tag = 7;
};

int classify(const UdpFlowView& f, ByteView payload, void* p) {
  auto& c = *static_cast<Ctx*>(p);
  c.calls.push_back({Bytes(f.src.begin(), f.src.end()), Bytes(f.dst.begin(), f.dst.end()), f.sport,
                     f.dport, f.depth, payload.size()});
  return f.dport == c.media_port || f.sport == c.media_port ? c.tag : 0;
}

bool is_sip(ByteView p) { return p.size() >= 3 && p[0] == 'I' && p[1] == 'N' && p[2] == 'V'; }

DissectOptions options(Ctx& c) {
  DissectOptions o;
  o.recognise_sip = &is_sip;
  o.classify_media = &classify;
  o.classify_media_ctx = &c;
  return o;
}

const FieldInstance* field(const Dissection& d, Fid id) {
  for (const auto& f : d.fields) {
    if (f.id == id) return &f;
  }
  return nullptr;
}

const Bytes kRtp = Bytes{0x80, 0x60, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4} + Bytes(20, 0x55);

}  // namespace

TEST_CASE("an announced UDP flow becomes payload.media with its tag", "[dissect][media]") {
  Ctx c;
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 50000, 40000, kRtp)), options(c));
  REQUIRE(c.calls.size() == 1);
  CHECK(c.calls[0].src == raw(kIpA));
  CHECK(c.calls[0].dst == raw(kIpB));
  CHECK(c.calls[0].sport == 50000);
  CHECK(c.calls[0].dport == 40000);
  CHECK(c.calls[0].depth == 0);
  CHECK(c.calls[0].payload == kRtp.size());
  const auto* f = field(d, Fid::payload_media);
  REQUIRE(f != nullptr);
  CHECK(f->length == kRtp.size());
  CHECK(d.media_tag == 7);
  CHECK(field(d, Fid::payload_l7) == nullptr);
}

TEST_CASE("an unannounced flow stays payload.l7 and IPv6 addresses reach the callback", "[dissect][media]") {
  Ctx c;
  const Bytes u = udp(50000, 41000, kRtp, pseudo_sum_v6(kIp6A, kIp6B, 17, 8 + kRtp.size()));
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x86DD, ipv6(kIp6A, kIp6B, 17, u)), options(c));
  REQUIRE(c.calls.size() == 1);
  CHECK(c.calls[0].src == raw(kIp6A));
  CHECK(c.calls[0].dst == raw(kIp6B));
  CHECK(field(d, Fid::payload_l7) != nullptr);
  CHECK(field(d, Fid::payload_media) == nullptr);
  CHECK(d.media_tag == 0);
}

TEST_CASE("SIP is recognised before media", "[dissect][media]") {
  Ctx c;
  const Bytes sip = text("INVITE sip:a@example.net SIP/2.0\r\n\r\n");
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 50000, 40000, sip)), options(c));
  CHECK(field(d, Fid::payload_sip) != nullptr);
  CHECK(c.calls.empty());
}

TEST_CASE("tunnelled flows reach the callback with the inner addresses", "[dissect][media]") {
  Ctx c;
  const Bytes inner = udp4(kIpA, kIpB, 50000, 40000, kRtp);
  // GTP-U G-PDU (TS 29.281 §5.1): flags 0x30, type 255, length, TEID.
  const Bytes gtpu = Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(0x1001) + inner;
  const V4 t1{192, 0, 2, 1}, t2{198, 51, 100, 1};
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, udp4(t1, t2, 2152, 2152, gtpu)), options(c));
  REQUIRE(c.calls.size() == 1);
  CHECK(c.calls[0].src == raw(kIpA));
  CHECK(c.calls[0].dport == 40000);
  CHECK(c.calls[0].depth == 1);
  CHECK(field(d, Fid::payload_media) != nullptr);
}

TEST_CASE("fragments and ICMP-embedded datagrams are not classified", "[dissect][media]") {
  Ctx c;
  // A first fragment (MF set) of an IPv4 UDP datagram.
  const Bytes u = udp(50000, 40000, kRtp, pseudo_sum_v4(kIpA, kIpB, 17, 8 + kRtp.size()));
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, ipv4(kIpA, kIpB, 17, u, {}, 0x2000)), options(c));
  CHECK(c.calls.empty());
  CHECK(field(d, Fid::payload_media) == nullptr);
  // ICMP destination unreachable quoting the datagram.
  const Bytes quoted = ipv4(kIpA, kIpB, 17, u);
  const Bytes icmp = Bytes{3, 3, 0, 0, 0, 0, 0, 0} + quoted;
  const auto e = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, ipv4(kIpB, kIpA, 1, icmp)), options(c));
  CHECK(c.calls.empty());
  CHECK(field(e, Fid::payload_media) == nullptr);
}

TEST_CASE("without a classifier nothing changes", "[dissect][media]") {
  DissectOptions o;
  const auto d = dissect(kLinkEthernet, eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 50000, 40000, kRtp)), o);
  CHECK(field(d, Fid::payload_l7) != nullptr);
  CHECK(field(d, Fid::payload_media) == nullptr);
}
