// SPDX-License-Identifier: GPL-3.0-or-later
//
// The L7 splice of the packet rewriter: a payload.sip field is replaced by the
// SIP layer's bytes, every enclosing length grows or shrinks by the delta, and checksums keep
// their input validity state (001/R7).
#include "rewrite_test_util.hpp"

#include "policy/ruleset.hpp"
#include "rewrite/checksum.hpp"
#include "sip/message.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {

const std::string kSip = "OPTIONS sip:a@example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n";

bool recognise(ByteView p) {
  return sip::is_start_line(std::string_view(reinterpret_cast<const char*>(p.data()), p.size()));
}

struct Splice {
  RuleSet rules = *load_embedded_ruleset();
  std::optional<Policy> policy;
  FakeMapper mapper;
  RewriteOptions options;
  RewriteStats stats;
  Bytes replacement;
  bool give_up = false;
  L7Hook hook;
  Splice() {
    policy.emplace(rules);
    hook.recognise = &recognise;
    hook.rewrite = [this](ByteView, const L7Context&) -> Result<std::optional<Bytes>> {
      if (give_up) return std::optional<Bytes>{};
      return std::optional<Bytes>(replacement);
    };
  }
  PacketOutput run(const Bytes& in) {
    auto r = rewrite_packet(kLinkEthernet, in, 0, *policy, mapper, options, stats, &hook);
    REQUIRE(r.has_value());
    return *r;
  }
};

std::string tail(const Bytes& p, std::size_t n) {
  return std::string(p.end() - static_cast<std::ptrdiff_t>(n), p.end());
}

bool udp6_ok(const Bytes& p, std::size_t ip) {
  const std::size_t len = be16(p, ip + 4);
  std::uint32_t acc = inet_accumulate(ByteView(p).subspan(ip + 8, 32));
  acc = inet_accumulate(Bytes{0, 0, static_cast<std::uint8_t>(len >> 8), static_cast<std::uint8_t>(len), 0, 0, 0, 17}, acc);
  acc = inet_accumulate(ByteView(p).subspan(ip + 40, len), acc);
  return inet_fold_sum(acc) == 0xFFFF;
}

}  // namespace

TEST_CASE("a grown SIP payload over IPv4/UDP fixes IP and UDP lengths and checksums", "[rewrite][splice]") {
  Splice s;
  s.replacement = text(kSip + std::string(40, '\0') + "GROWN");
  const Bytes in = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  const auto out = s.run(in);
  const std::size_t delta = s.replacement.size() - kSip.size();
  REQUIRE(out.data.size() == in.size() + delta);
  CHECK(tail(out.data, 5) == "GROWN");
  CHECK(be16(out.data, 14 + 2) == 20 + 8 + s.replacement.size());  // IPv4 total length
  CHECK(be16(out.data, 34 + 4) == 8 + s.replacement.size());       // UDP length
  CHECK(ipv4_header_ok(out.data, 14));
  CHECK(l4_ok_v4(out.data, 14, 17));
  CHECK(s.stats.counters["payload.sip"]["l7"] == 1);
}

TEST_CASE("a shrunk SIP payload over IPv6/UDP", "[rewrite][splice]") {
  Splice s;
  s.replacement = text("SIP");
  const Bytes in = eth(kMacB, kMacA, 0x86DD, ipv6(kIp6A, kIp6B, 17, udp(5060, 5060, text(kSip),
                                                                          pseudo_sum_v6(kIp6A, kIp6B, 17, 8 + kSip.size()))));
  const auto out = s.run(in);
  REQUIRE(out.data.size() == in.size() - (kSip.size() - 3));
  CHECK(be16(out.data, 14 + 4) == 8 + 3);  // IPv6 payload length
  CHECK(be16(out.data, 54 + 4) == 8 + 3);  // UDP length
  CHECK(udp6_ok(out.data, 14));
}

TEST_CASE("GTP-U and outer tunnel headers follow the delta", "[rewrite][splice]") {
  Splice s;
  s.replacement = text(kSip + "0123456789");
  const Bytes inner = udp4(kIpA, kIpB, 5060, 5060, text(kSip));
  const Bytes gtp = Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(0x1001) + inner;
  const Bytes in = eth(kMacB, kMacA, 0x0800, udp4(V4{192, 0, 2, 1}, V4{198, 51, 100, 1}, 2152, 2152, gtp));
  const auto out = s.run(in);
  const std::size_t delta = 10;
  REQUIRE(out.data.size() == in.size() + delta);
  CHECK(be16(out.data, 14 + 2) == in.size() - 14 + delta);  // outer IPv4
  CHECK(be16(out.data, 34 + 4) == 8 + gtp.size() + delta);  // outer UDP
  CHECK(be16(out.data, 42 + 2) == inner.size() + delta);    // GTP-U length
  CHECK(be16(out.data, 50 + 2) == inner.size() + delta);    // inner IPv4
  CHECK(be16(out.data, 70 + 4) == 8 + kSip.size() + delta); // inner UDP
  CHECK(ipv4_header_ok(out.data, 14));
  CHECK(ipv4_header_ok(out.data, 50));
  CHECK(l4_ok_v4(out.data, 14, 17));
  CHECK(l4_ok_v4(out.data, 50, 17));
}

TEST_CASE("checksums keep their input validity state", "[rewrite][splice]") {
  Splice s;
  s.replacement = text(kSip + "X");
  Bytes bad = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  bad[34 + 6] ^= 0x55;  // invalid UDP checksum in the input
  const auto o1 = s.run(bad);
  CHECK_FALSE(l4_ok_v4(o1.data, 14, 17));
  Bytes zero = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  zero[34 + 6] = 0;
  zero[34 + 7] = 0;  // no UDP checksum (RFC 768)
  const auto o2 = s.run(zero);
  CHECK(be16(o2.data, 34 + 6) == 0);
}

TEST_CASE("without a replacement, or with an unrepresentable length, the payload is zeroed", "[rewrite][splice]") {
  Splice s;
  s.give_up = true;
  const Bytes in = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  auto o = s.run(in);
  REQUIRE(o.data.size() == in.size());
  CHECK(std::all_of(o.data.end() - static_cast<std::ptrdiff_t>(kSip.size()), o.data.end(), [](auto b) { return b == 0; }));
  s.give_up = false;
  s.replacement = Bytes(70000, 'x');  // IPv4 total length cannot hold it
  o = s.run(in);
  REQUIRE(o.data.size() == in.size());
  CHECK(std::all_of(o.data.end() - static_cast<std::ptrdiff_t>(kSip.size()), o.data.end(), [](auto b) { return b == 0; }));
}

TEST_CASE("drop mode keeps a rewritten SIP payload (FR-003)", "[rewrite][splice]") {
  Splice s;
  s.options.payload = PayloadPolicy::drop;
  s.replacement = text(kSip + "Y");
  const Bytes in = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  auto o = s.run(in);
  REQUIRE(o.data.size() == in.size() + 1);
  CHECK(tail(o.data, 1) == "Y");
  // Not SIP: dropped as in feature 001.
  const Bytes other = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text("GET / HTTP/1.1\r\n\r\n")));
  o = s.run(other);
  CHECK(o.data.size() == 14 + 20 + 8);
  // A first IP fragment is never SIP in this layer (the fragment table handles it).
  Bytes frag = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 5060, 5060, text(kSip)));
  frag[14 + 6] = 0x20;  // MF set
  frag[14 + 10] = frag[14 + 11] = 0;
  s.options.payload = PayloadPolicy::zero;
  o = s.run(frag);
  CHECK(s.stats.counters["payload.sip"]["l7"] == 1);  // the earlier SIP packet only
}
