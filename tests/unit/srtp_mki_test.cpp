// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SRTP and SRTCP MKI (spec FR-012a, SC-008). On a secure
// endpoint the 004 trailer stays zeroed except for an MKI whose words are key identifiers known
// from the endpoint's key context or from the project mapping, at a unique (length, offset).
#include "media/rtcp.hpp"
#include "media/rtp.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/media_rules.hpp"
#include "policy/sip_rules.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <initializer_list>

using namespace mcxanon;
using namespace mcxanon::media;

namespace {

constexpr std::uint32_t kGmk = 0x0AAA1111u;  // purpose tag 0
constexpr std::uint32_t kGuk = 0x0BBB2222u;  // purpose tag 0
constexpr std::uint32_t kPck = 0x1CCC3333u;  // purpose tag 1
constexpr std::uint32_t kCsk = 0x2DDD4444u;  // purpose tag 2

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 13 + 1);
  return s;
}

void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}

std::uint32_t at32(const Bytes& b, std::size_t off) {
  return (std::uint32_t{b[off]} << 24) | (std::uint32_t{b[off + 1]} << 16) | (std::uint32_t{b[off + 2]} << 8) |
         b[off + 3];
}

// An SRTP packet: 12-octet header, `enc` encrypted octets, the MKI words, `tag` tag octets.
Bytes srtp(std::initializer_list<std::uint32_t> mki, std::size_t enc = 40, std::size_t tag = 0) {
  Bytes b{0x80, 0x60, 0x12, 0x34, 0xA0, 0xB0, 0xC0, 0xD0};
  put32(b, 0x51525354u);
  b.insert(b.end(), enc, 0xE5);
  for (auto w : mki) put32(b, w);
  b.insert(b.end(), tag, 0x7A);
  return b;
}

// An SRTCP packet (RFC 3711 §3.4): an SR header with the SSRC, `enc` encrypted octets, E+index,
// the MKI words, `tag` tag octets.
Bytes srtcp(std::initializer_list<std::uint32_t> mki, std::size_t enc = 20, std::size_t tag = 0) {
  Bytes b{0x80, 200, 0x00, 0x06};
  put32(b, 0x61626364u);
  b.insert(b.end(), enc, 0xC3);
  put32(b, 0x80000007u);  // E flag and SRTCP index
  for (auto w : mki) put32(b, w);
  b.insert(b.end(), tag, 0x7A);
  return b;
}

struct Fixture {
  MediaRuleSet rules = *load_embedded_media_ruleset();
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  MediaCounters counters;
  sip::SipCounters sip_counters;
  sip::Context sctx{sip_rules, mapper, {}, sip_counters};

  Bytes rtp(const Bytes& in, const sip::KeyContext* keys) {
    auto r = rewrite_rtp(in, true, rules, mapper, counters, keys);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
  Bytes rtcp(const Bytes& in, const sip::KeyContext* keys) {
    RtcpEnv env{rules, mapper, sctx, counters, keys};
    auto r = rewrite_rtcp(in, true, env);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
  std::uint32_t pseudo(std::uint32_t k) { return *mapper.key_id(k); }
};

bool zero_range(const Bytes& b, std::size_t from, std::size_t to) {
  return std::all_of(b.begin() + static_cast<std::ptrdiff_t>(from), b.begin() + static_cast<std::ptrdiff_t>(to),
                     [](std::uint8_t x) { return x == 0; });
}

}  // namespace

TEST_CASE("mki: GMK-ID || GUK-ID before a 4-octet tag (TS 33.180 §E.2.2)", "[mki]") {
  Fixture f;
  sip::KeyContext keys{{kGuk, kGmk}, 4, std::nullopt};
  const auto in = srtp({kGmk, kGuk}, 40, 4);
  const auto out = f.rtp(in, &keys);
  REQUIRE(out.size() == in.size());
  const std::size_t mki = in.size() - 4 - 8;
  CHECK(at32(out, mki) == f.pseudo(kGmk));
  CHECK(at32(out, mki + 4) == f.pseudo(kGuk));
  CHECK(zero_range(out, 12, mki));                    // encrypted portion
  CHECK(zero_range(out, mki + 8, out.size()));        // tag
  CHECK(f.counters.mki.pseudonymised == 1);
  CHECK(f.counters.mki.unmatched == 0);
}

TEST_CASE("mki: a PCK-ID with the AEAD tag inside the ciphertext (TS 33.180 §E.3.2)", "[mki]") {
  Fixture f;
  sip::KeyContext keys{{kPck}, 0, std::nullopt};
  const auto in = srtp({kPck});
  const auto out = f.rtp(in, &keys);
  CHECK(at32(out, in.size() - 4) == f.pseudo(kPck));
  CHECK(zero_range(out, 12, in.size() - 4));
  CHECK(f.counters.mki.pseudonymised == 1);
}

TEST_CASE("mki: SRTCP MKI after E+index; E+index and the rest stay zeroed", "[mki]") {
  Fixture f;
  sip::KeyContext keys{{kCsk}, std::nullopt, 0};
  const auto in = srtcp({kCsk});
  const auto out = f.rtcp(in, &keys);
  REQUIRE(out.size() == in.size());
  CHECK(at32(out, in.size() - 4) == f.pseudo(kCsk));
  CHECK(zero_range(out, 8, in.size() - 4));
  CHECK(f.counters.mki.pseudonymised == 1);
}

TEST_CASE("mki: a key identifier known only from the project mapping", "[mki]") {
  Fixture f;
  const auto expected = f.pseudo(kPck);  // a previous capture put it in the mapping
  const auto in = srtp({kPck});
  const auto out = f.rtp(in, nullptr);   // no key context: tag lengths 0 and 4 are tried
  CHECK(at32(out, in.size() - 4) == expected);
  CHECK(f.counters.mki.pseudonymised == 1);
}

TEST_CASE("mki: two fitting positions are ambiguous and stay zeroed", "[mki]") {
  Fixture f;
  const auto p1 = f.pseudo(kPck);
  const auto p2 = f.pseudo(0x1EEE5555u);
  (void)p1;
  (void)p2;
  // No tag length known: (4 octets, tag 4) and (4 octets, tag 0) both read a PCK-ID.
  const auto in = srtp({kPck, 0x1EEE5555u});
  const auto out = f.rtp(in, nullptr);
  CHECK(zero_range(out, 12, out.size()));
  CHECK(f.counters.mki.ambiguous == 1);
  CHECK(f.counters.mki.pseudonymised == 0);
}

TEST_CASE("mki: an unknown MKI keeps the 004 zeroed trailer and is counted", "[mki]") {
  Fixture f;
  sip::KeyContext keys{{kPck}, 0, std::nullopt};
  const auto in = srtp({0x1F00F00Du});
  const auto out = f.rtp(in, &keys);
  CHECK(zero_range(out, 12, out.size()));
  CHECK(f.counters.mki.unmatched == 1);
  // Without a key context an SRTP packet without a known MKI is not counted.
  Fixture g;
  (void)g.rtp(srtp({0x1F00F00Du}), nullptr);
  CHECK(g.counters.mki.unmatched == 0);
}

TEST_CASE("mki: a purpose tag that does not fit the position is not matched", "[mki]") {
  Fixture f;
  // A CSK-ID (tag 2) is not an SRTP MKI word; a PCK-ID is not half of a GMK-ID || GUK-ID pair.
  sip::KeyContext keys{{kCsk, kPck}, 0, std::nullopt};
  auto out = f.rtp(srtp({kCsk}), &keys);
  CHECK(zero_range(out, 12, out.size()));
  out = f.rtp(srtp({kPck, kPck}), &keys);
  CHECK(at32(out, out.size() - 4) == f.pseudo(kPck));  // the single PCK-ID at the end matches
  CHECK(at32(out, out.size() - 8) == 0u);
}
