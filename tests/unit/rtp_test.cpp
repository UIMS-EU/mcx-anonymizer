// SPDX-License-Identifier: GPL-3.0-or-later
//
// RTP rewrite (FR-004 to FR-008, FR-025 for SRTP).
#include "media/rtp.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/media_rules.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <initializer_list>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::media;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 17 + 9);
  return s;
}

void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}

// V=2, P, X, CC from the arguments; M=1, PT=96, seq 0x1234, ts 0xA0B0C0D0.
Bytes header(std::uint32_t ssrc, std::initializer_list<std::uint32_t> csrcs = {}, bool x = false, bool p = false) {
  Bytes b{static_cast<std::uint8_t>(0x80 | (p ? 0x20 : 0) | (x ? 0x10 : 0) | csrcs.size()), 0xE0, 0x12, 0x34,
          0xA0, 0xB0, 0xC0, 0xD0};
  put32(b, ssrc);
  for (auto c : csrcs) put32(b, c);
  return b;
}

Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

std::uint32_t at32(const Bytes& b, std::size_t off) {
  return (std::uint32_t{b[off]} << 24) | (std::uint32_t{b[off + 1]} << 16) | (std::uint32_t{b[off + 2]} << 8) |
         b[off + 3];
}

struct Fixture {
  MediaRuleSet rules = *load_embedded_media_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  MediaCounters counters;

  std::optional<Bytes> run(const Bytes& in, bool secure = false) {
    auto r = rewrite_rtp(in, secure, rules, mapper, counters);
    REQUIRE(r.has_value());
    return *r;
  }
  std::uint32_t ssrc(std::uint32_t v) { return *mapper.ssrc(v); }
};

const Bytes kPayload(40, 0x5A);
}  // namespace

TEST_CASE("the fixed header is kept, SSRC and CSRCs are mapped, the payload is zeroed", "[media][rtp]") {
  Fixture f;
  const Bytes in = cat({header(0x11223344, {0x55667788, 0x99AABBCC}), kPayload});
  const auto out = f.run(in);
  REQUIRE(out.has_value());
  REQUIRE(out->size() == in.size());
  CHECK(std::equal(in.begin(), in.begin() + 8, out->begin()));  // V P X CC M PT seq ts
  CHECK(at32(*out, 8) == f.ssrc(0x11223344));
  CHECK(at32(*out, 12) == f.ssrc(0x55667788));
  CHECK(at32(*out, 16) == f.ssrc(0x99AABBCC));
  CHECK(std::all_of(out->begin() + 20, out->end(), [](std::uint8_t b) { return b == 0; }));
  CHECK(f.counters.rtp_packets == 1);
  CHECK(f.counters.rtp_by_payload_type.at("96") == 1);
  CHECK(f.counters.rtp_by_stream.size() == 1);
}

TEST_CASE("one-byte header extension keeps IDs, lengths and padding; data is zeroed", "[media][rtp]") {
  Fixture f;
  // 0xBEDE, length 2 words: element id 1 len 2 (AA BB CC? no: len field 1 = 2 octets), id 2 len 1, pad.
  const Bytes ext{0xBE, 0xDE, 0x00, 0x02, 0x11, 0xAA, 0xBB, 0x20, 0xCC, 0x00, 0x00, 0x00};
  const Bytes in = cat({header(1, {}, true), ext, kPayload});
  const auto out = f.run(in);
  REQUIRE(out.has_value());
  const Bytes want{0xBE, 0xDE, 0x00, 0x02, 0x11, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00};
  CHECK(Bytes(out->begin() + 12, out->begin() + 24) == want);
}

TEST_CASE("ID 15 stops the one-byte walk; the rest of the extension is zeroed", "[media][rtp]") {
  Fixture f;
  const Bytes ext{0xBE, 0xDE, 0x00, 0x02, 0x10, 0xAA, 0xF3, 0x41, 0x42, 0x43, 0x44, 0x45};
  const auto out = f.run(cat({header(1, {}, true), ext, kPayload}));
  REQUIRE(out.has_value());
  const Bytes want{0xBE, 0xDE, 0x00, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  CHECK(Bytes(out->begin() + 12, out->begin() + 24) == want);
}

TEST_CASE("two-byte header extension keeps IDs and lengths; data is zeroed", "[media][rtp]") {
  Fixture f;
  // 0x1000 (appbits 0), length 2 words: id 7 len 3, id 9 len 0, padding.
  const Bytes ext{0x10, 0x00, 0x00, 0x02, 0x07, 0x03, 0xAA, 0xBB, 0xCC, 0x09, 0x00, 0x00};
  const auto out = f.run(cat({header(1, {}, true), ext, kPayload}));
  REQUIRE(out.has_value());
  const Bytes want{0x10, 0x00, 0x00, 0x02, 0x07, 0x03, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00};
  CHECK(Bytes(out->begin() + 12, out->begin() + 24) == want);
}

TEST_CASE("another extension profile keeps profile and length; its body is zeroed", "[media][rtp]") {
  Fixture f;
  const Bytes ext{0xAB, 0xCD, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44};
  const auto out = f.run(cat({header(1, {}, true), ext, kPayload}));
  REQUIRE(out.has_value());
  CHECK(Bytes(out->begin() + 12, out->begin() + 20) == Bytes{0xAB, 0xCD, 0x00, 0x01, 0, 0, 0, 0});
}

TEST_CASE("an extension element that overruns zeroes the extension body", "[media][rtp]") {
  Fixture f;
  const Bytes ext{0xBE, 0xDE, 0x00, 0x01, 0x1F, 0xAA, 0xBB, 0xCC};  // id 1, 16 octets: overrun
  const auto out = f.run(cat({header(1, {}, true), ext, kPayload}));
  REQUIRE(out.has_value());
  CHECK(Bytes(out->begin() + 12, out->begin() + 20) == Bytes{0xBE, 0xDE, 0x00, 0x01, 0, 0, 0, 0});
  CHECK(f.counters.rtp_zeroed.at("extension") == 1);
}

TEST_CASE("RTP padding keeps its count octet; the other padding octets are zeroed (P2)", "[media][rtp]") {
  Fixture f;
  Bytes in = cat({header(1, {}, false, true), Bytes(20, 0x77), Bytes{0xAA, 0xAA, 0xAA, 0x04}});
  const auto out = f.run(in);
  REQUIRE(out.has_value());
  CHECK(out->back() == 0x04);
  CHECK(std::all_of(out->begin() + 12, out->end() - 1, [](std::uint8_t b) { return b == 0; }));
}

TEST_CASE("every payload type is zeroed, telephone-event included", "[media][rtp]") {
  Fixture f;
  for (int pt : {0, 8, 18, 96, 101, 127}) {
    Bytes in = cat({header(7), kPayload});
    in[1] = static_cast<std::uint8_t>(pt);
    const auto out = f.run(in);
    REQUIRE(out.has_value());
    CHECK((*out)[1] == pt);
    CHECK(std::all_of(out->begin() + 12, out->end(), [](std::uint8_t b) { return b == 0; }));
  }
}

TEST_CASE("SRTP: the header is kept and mapped; every octet after it is zeroed", "[media][rtp][srtp]") {
  Fixture f;
  // With P set, the padding is inside the encrypted portion (RFC 3711 §3.1): nothing after the
  // header is interpreted, so a "padding count" of 0 is not malformed.
  Bytes in = cat({header(0xCAFEBABE, {}, false, true), Bytes(30, 0x66), Bytes{0x00}});
  const auto out = f.run(in, true);
  REQUIRE(out.has_value());
  CHECK((*out)[0] == in[0]);  // P kept
  CHECK(at32(*out, 8) == f.ssrc(0xCAFEBABE));
  CHECK(std::all_of(out->begin() + 12, out->end(), [](std::uint8_t b) { return b == 0; }));
}

TEST_CASE("malformed RTP is not passed through", "[media][rtp][malformed]") {
  Fixture f;
  // Wrong version.
  Bytes v1 = cat({header(1), kPayload});
  v1[0] = 0x40;
  // Shorter than the fixed header.
  const Bytes shorty{0x80, 0x60, 0x00};
  // CSRC count larger than the packet.
  Bytes cc = header(1);
  cc[0] = 0x8F;
  // Padding count 0, and padding count larger than the packet.
  Bytes pad0 = cat({header(1, {}, false, true), Bytes(10, 1), Bytes{0}});
  Bytes padbig = cat({header(1, {}, false, true), Bytes(3, 1), Bytes{200}});
  // Extension header beyond the packet.
  Bytes ext = cat({header(1, {}, true), Bytes{0xBE, 0xDE, 0x00, 0x09}});
  for (const auto& in : {v1, shorty, cc, pad0, padbig, ext}) {
    CHECK_FALSE(f.run(in).has_value());
  }
  CHECK(f.counters.rtp_zeroed.at("malformed") == 6);
}

TEST_CASE("an SSRC that no SDP announced is mapped with the same project mapping", "[media][rtp]") {
  Fixture f;
  // The SSRC mapping is project-wide: the same original gives the same pseudonym however it
  // was first seen; a new SSRC in mid-stream simply gets its own pseudonym and stream.
  const auto a = f.run(cat({header(0xABCD0001), kPayload}));
  const auto b = f.run(cat({header(0xABCD0002), kPayload}));
  const auto c = f.run(cat({header(0xABCD0001), kPayload}));
  REQUIRE((a && b && c));
  CHECK(at32(*a, 8) == at32(*c, 8));
  CHECK(at32(*a, 8) != at32(*b, 8));
  CHECK(f.counters.rtp_by_stream.size() == 2);
}

TEST_CASE("an original SSRC equal to an issued pseudonym takes the collision path", "[media][rtp]") {
  Fixture f;
  const auto first = f.run(cat({header(0x01020304), kPayload}));
  REQUIRE(first.has_value());
  const auto issued = at32(*first, 8);
  auto r = rewrite_rtp(cat({header(issued), kPayload}), false, f.rules, f.mapper, f.counters);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::collision);
}
