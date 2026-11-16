// SPDX-License-Identifier: GPL-3.0-or-later
//
// The '3GPP key parameters' extension (type 7; TS 33.180 §E.6.1, Table 8.5.4.1-1; research
// R9) and the GENERIC-ID crypto session blocks (RFC 6043 §6.1.1).
#include "mikey/decode.hpp"
#include "mikey/keyparams.hpp"
#include "mikey/rewrite.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/mikey_rules.hpp"
#include "pseudo/pseudonymiser.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <variant>

using namespace mcxanon;
using namespace mikey_test;

namespace {

constexpr std::uint32_t kGmk = 0x0ABCDEF1u;  // purpose tag 0 (GMK)
constexpr std::uint32_t kGuk = 0x01234567u;

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 7 + 3);
  return s;
}

// The protected payload of TS 33.180 Table 8.5.4.1-1 carrying the Key Parameters payload.
Bytes key_parameters(std::uint32_t dppk, const Bytes& iv, const Bytes& ciphertext, std::optional<std::uint8_t> sig_alg,
                     std::uint64_t date = 0x0065A1B2C3ull, const Bytes& nested_i_message = {}) {
  Bytes b{0x01};  // Message Type
  for (int s = 32; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(date >> s));
  put32(b, 0);  // Payload ID
  b.push_back(0);  // Payload sequence number
  b.push_back(1);  // Payload algorithm
  if (sig_alg) b.push_back(*sig_alg);
  b.insert(b.end(), iv.begin(), iv.end());
  put32(b, dppk);
  b.push_back(0x78);  // Payload IEI
  put16(b, static_cast<unsigned>(ciphertext.size()));
  b.insert(b.end(), ciphertext.begin(), ciphertext.end());
  if (!nested_i_message.empty()) {
    b.push_back(0x79);
    put16(b, static_cast<unsigned>(nested_i_message.size()));
    b.insert(b.end(), nested_i_message.begin(), nested_i_message.end());
  }
  return b;
}

Bytes gmk_message(const Bytes& kp, std::vector<Bytes> blocks = {}) {
  Header h;
  h.csb_id = kGuk;
  h.blocks = std::move(blocks);
  return message(h, {t(0xE9A1B2C380000000ull), rand(Bytes(16, 0x52)), idr(1, 1, text("sip:gms@example.org")),
                     idr(2, 1, text("sip:alice@example.org")), idr(6, 1, text("kms.example.org")),
                     idr(7, 1, text("kms.example.org")), ext(7, kp), sakke(Bytes(273, 0x53)),
                     sign(Bytes(129, 0x47))});
}

struct Fixture {
  MikeyRuleSet rules = *load_embedded_mikey_ruleset();
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters sip_counters;
  sip::Context ctx{sip_rules, mapper, {}, sip_counters};
  mikey::Counters counters;
  mikey::RewriterOptions options;
  std::set<std::uint32_t> seen;

  mikey::Message rewrite(const Bytes& in) {
    auto d = mikey::decode(in, rules);
    REQUIRE(d.verdict == mikey::Verdict::sakke);
    mikey::RewriteEnv env{rules, options, ctx, counters, &seen};
    REQUIRE(mikey::rewrite_message(*d.message, env).has_value());
    return *d.message;
  }
  std::uint32_t key_id(std::uint32_t v) { return *mapper.key_id(v); }
  Bytes nonce(const Bytes& v) { return *mapper.bytes(Category::nonce, v); }
};

const Bytes& ext_data(const mikey::Message& m) {
  for (const auto& p : m.payloads) {
    if (const auto* e = std::get_if<mikey::Ext>(&p.v)) return e->data;
  }
  FAIL("no extension");
  static const Bytes none;
  return none;
}

std::uint32_t be32(const Bytes& b, std::size_t at) {
  return (std::uint32_t{b[at]} << 24) | (std::uint32_t{b[at + 1]} << 16) | (std::uint32_t{b[at + 2]} << 8) | b[at + 3];
}

}  // namespace

TEST_CASE("keyparams: both layouts delimit when the DPPK-ID equals the CSB ID", "[mikey][keyparams]") {
  const Bytes iv(16, 0x49);
  const Bytes ct(40, 0x43);
  for (const std::optional<std::uint8_t> sig : {std::optional<std::uint8_t>{}, std::optional<std::uint8_t>{2}}) {
    const auto kp = key_parameters(kGuk, iv, ct, sig);
    const auto d = mikey::delimit_key_parameters(kp, kGuk);
    REQUIRE(d.has_value());
    CHECK(d->signalling == sig.has_value());
    CHECK(d->iv_off == (sig ? 13u : 12u));
    CHECK(d->dppk_off == d->iv_off + 16);
    CHECK(d->payload_off == d->dppk_off + 4 + 3);
    CHECK(d->payload_len == ct.size());
    CHECK_FALSE(d->i_message.has_value());
  }
}

TEST_CASE("keyparams: a DPPK-ID other than the CSB ID, a 32-octet IV or trailing bytes do not delimit",
          "[mikey][keyparams]") {
  const Bytes ct(40, 0x43);
  CHECK_FALSE(mikey::delimit_key_parameters(key_parameters(kGmk, Bytes(16, 0x49), ct, std::nullopt), kGuk));
  // Plan review P5: the IV is 16 octets (Table 8.5.4.1-1); a 32-octet IV fails both layouts.
  CHECK_FALSE(mikey::delimit_key_parameters(key_parameters(kGuk, Bytes(32, 0x49), ct, std::nullopt), kGuk));
  auto trailing = key_parameters(kGuk, Bytes(16, 0x49), ct, std::nullopt);
  trailing.push_back(0);
  CHECK_FALSE(mikey::delimit_key_parameters(trailing, kGuk));
  CHECK_FALSE(mikey::delimit_key_parameters(Bytes(10, 0), kGuk));
  CHECK_FALSE(mikey::delimit_key_parameters(Bytes{}, kGuk));
}

TEST_CASE("keyparams: a layout that fits both ways is not delimited", "[mikey][keyparams]") {
  // CSB ID 0x01010101: without the Signalling algorithm octet the DPPK-ID is at 28..31 and the
  // payload TLV-E at 32 (IEI 01, length 0x0101 = 257, ends at 292); with it, the DPPK-ID is at
  // 29..32 and the TLV-E at 33 (IEI 01, length 0x0100 = 256, ends at 292). Both fit.
  constexpr std::uint32_t csb = 0x01010101u;
  Bytes kp(292, 0x2A);
  for (std::size_t i = 28; i < 35; ++i) kp[i] = 0x01;
  kp[35] = 0x00;
  CHECK_FALSE(mikey::delimit_key_parameters(kp, csb));
  // The unique layout of the same header with another length is accepted.
  const auto ok = key_parameters(kGuk, Bytes(16, 0), Bytes(4, 0x43), std::nullopt);
  const auto d = mikey::delimit_key_parameters(ok, kGuk);
  REQUIRE(d.has_value());
  CHECK_FALSE(d->signalling);
}

TEST_CASE("keyparams: a nested off-network I-MESSAGE TLV-E is delimited", "[mikey][keyparams]") {
  const auto kp = key_parameters(kGuk, Bytes(16, 0x49), Bytes(24, 0x43), std::nullopt, 0x0065A1B2C3ull, Bytes(30, 0x4D));
  const auto d = mikey::delimit_key_parameters(kp, kGuk);
  REQUIRE(d.has_value());
  REQUIRE(d->i_message.has_value());
  CHECK(d->i_message->second == 30u);
  CHECK(d->i_message->first + 30 == kp.size());
}

TEST_CASE("keyparams: rewrite shifts the date, maps the IV and DPPK-ID, keeps the ciphertext", "[mikey][keyparams]") {
  Fixture f;
  f.options.time_shift_ns = std::int64_t{3600} * 1'000'000'000;
  const Bytes iv(16, 0x49);
  const Bytes ct(40, 0x43);
  const auto kp = key_parameters(kGuk, iv, ct, std::uint8_t{2});
  const auto m = f.rewrite(gmk_message(kp));
  const auto& out = ext_data(m);
  REQUIRE(out.size() == kp.size());
  CHECK(out[0] == kp[0]);  // Message Type
  std::uint64_t date = 0;
  for (std::size_t i = 1; i < 6; ++i) date = (date << 8) | out[i];
  CHECK(date == 0x0065A1B2C3ull + 3600);
  CHECK(Bytes(out.begin() + 6, out.begin() + 13) == Bytes(kp.begin() + 6, kp.begin() + 13));  // IDs, algorithms
  CHECK(Bytes(out.begin() + 13, out.begin() + 29) == f.nonce(iv));
  CHECK(be32(out, 29) == f.key_id(kGuk));
  CHECK(be32(out, 29) == m.hdr.csb_id);  // still equal to the (pseudonymised) CSB ID
  CHECK(Bytes(out.begin() + 33, out.end()) == Bytes(kp.begin() + 33, kp.end()));  // TLV-E kept
  CHECK(f.counters.payloads["key-parameters"]["rewritten"] == 1);
  CHECK(f.counters.payloads["key-parameters"]["undelimited"] == 0);
}

TEST_CASE("keyparams: without --time-shift the date is kept; a shift out of range zeroes it", "[mikey][keyparams]") {
  {
    Fixture f;
    const auto kp = key_parameters(kGuk, Bytes(16, 0x49), Bytes(8, 0x43), std::nullopt);
    const auto m = f.rewrite(gmk_message(kp));
    const auto& out = ext_data(m);
    CHECK(Bytes(out.begin() + 1, out.begin() + 6) == Bytes(kp.begin() + 1, kp.begin() + 6));
  }
  {
    Fixture f;
    f.options.time_shift_ns = -std::int64_t{1'000'000'000} * 0x0100000000ll;
    const auto kp = key_parameters(kGuk, Bytes(16, 0x49), Bytes(8, 0x43), std::nullopt);
    const auto m = f.rewrite(gmk_message(kp));
    const auto& out = ext_data(m);
    CHECK(Bytes(out.begin() + 1, out.begin() + 6) == Bytes(5, 0));
  }
}

TEST_CASE("keyparams: the nested I-MESSAGE value is zeroed, IEI and length kept", "[mikey][keyparams]") {
  Fixture f;
  const auto kp = key_parameters(kGuk, Bytes(16, 0x49), Bytes(24, 0x43), std::nullopt, 0x0065A1B2C3ull, Bytes(30, 0x4D));
  const auto m = f.rewrite(gmk_message(kp));
    const auto& out = ext_data(m);
  REQUIRE(out.size() == kp.size());
  CHECK(Bytes(out.end() - 33, out.end() - 30) == Bytes(kp.end() - 33, kp.end() - 30));
  CHECK(Bytes(out.end() - 30, out.end()) == Bytes(30, 0));
  CHECK(f.counters.payloads["key-parameters"]["rewritten"] == 1);
}

TEST_CASE("keyparams: an undelimited header is zeroed and counted", "[mikey][keyparams]") {
  Fixture f;
  const auto kp = key_parameters(kGmk, Bytes(16, 0x49), Bytes(24, 0x43), std::nullopt);  // DPPK != CSB
  const auto m = f.rewrite(gmk_message(kp));
    const auto& out = ext_data(m);
  CHECK(out == Bytes(kp.size(), 0));
  CHECK(f.counters.payloads["key-parameters"]["undelimited"] == 1);
  CHECK(f.counters.payloads["key-parameters"]["rewritten"] == 0);
}

TEST_CASE("keyparams: GENERIC-ID session data and SPIs of 4 and 8 octets", "[mikey][keyparams]") {
  Fixture f;
  Bytes spi8;
  put32(spi8, kGmk);
  put32(spi8, kGuk);
  Bytes spi4;
  put32(spi4, kGmk);
  const auto in = gmk_message(key_parameters(kGuk, Bytes(16, 0x49), Bytes(8, 0x43), std::nullopt),
                              {block(4, 0, {0}, {{0x11223344u, 7}}, spi8), block(5, 0, {0}, {}, spi4),
                               block(6, 0, {0}, {}, Bytes{1, 2, 3})});
  const auto m = f.rewrite(in);
  REQUIRE(m.hdr.blocks.size() == 3);
  const auto& b0 = m.hdr.blocks[0];
  CHECK(be32(b0.session_data, 0) == *f.mapper.ssrc(0x11223344u));
  CHECK(be32(b0.session_data, 4) == 7u);  // ROC kept
  CHECK(be32(b0.spi, 0) == f.key_id(kGmk));
  CHECK(be32(b0.spi, 4) == f.key_id(kGuk));
  CHECK(be32(m.hdr.blocks[1].spi, 0) == f.key_id(kGmk));
  CHECK(m.hdr.blocks[2].spi == Bytes(3, 0));  // other SPI lengths are zeroed
  CHECK(b0.cs_id == 4);
  CHECK(b0.policies == std::vector<std::uint8_t>{0});
}
