// SPDX-License-Identifier: GPL-3.0-or-later
//
// The payload handlers of the MIKEY rewriter in ciphertext mode (spec FR-006 to FR-015).
#include "mikey/decode.hpp"
#include "mikey/encode.hpp"
#include "mikey/rewrite.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/mikey_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"
#include "xml/categories.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <variant>

using namespace mcxanon;
using namespace mikey_test;

namespace {

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 11 + 5);
  return s;
}

struct Fixture {
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  MikeyRuleSet rules = *load_embedded_mikey_ruleset();
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
  std::string uri(std::string_view u) { return **sip::rewrite_uri_text(u, ctx); }
};

template <typename P>
const P& at(const mikey::Message& m, std::size_t i) {
  return std::get<P>(m.payloads.at(i).v);
}
std::string str(const Bytes& b) { return std::string(b.begin(), b.end()); }

}  // namespace

TEST_CASE("mikey rewrite: identities take the SIP pseudonyms, KMS the 003 kms-uri ones", "[mikey][rewrite]") {
  Fixture f;
  const auto m = f.rewrite(private_call());
  CHECK(str(at<mikey::Idr>(m, 2).data) == f.uri("sip:alice@example.org"));
  CHECK(str(at<mikey::Idr>(m, 3).data) == f.uri("sip:bob@example.org"));
  const auto kms = xml::map_category(XmlCategory::kms_uri, "kms.example.org", f.ctx);
  REQUIRE(kms.has_value());
  CHECK(str(at<mikey::Idr>(m, 4).data) == **kms);
  CHECK(str(at<mikey::Idr>(m, 5).data) == **kms);
  CHECK(at<mikey::Idr>(m, 2).role == 1);
  CHECK(at<mikey::Idr>(m, 2).id_type == 1);
  CHECK(f.counters.payloads["IDR"]["identity"] == 2);
  CHECK(f.counters.payloads["IDR"]["kms"] == 2);
}

TEST_CASE("mikey rewrite: CSB ID keeps the purpose tag, RAND same length, SAKKE kept, SIGN zeroed",
          "[mikey][rewrite]") {
  Fixture f;
  const auto m = f.rewrite(private_call(0x1ABCDEF0u));
  CHECK((m.hdr.csb_id >> 28) == 1u);
  CHECK(m.hdr.csb_id != 0x1ABCDEF0u);
  CHECK(m.hdr.csb_id == *f.p.find_key_id(0x1ABCDEF0u));
  const auto& r = at<mikey::Rand>(m, 1).rand;
  CHECK(r.size() == 16);
  CHECK(r != Bytes(16, 0x52));
  CHECK(at<mikey::Sakke>(m, 6).data == Bytes(273, 0x53));
  const auto& s = at<mikey::Sign>(m, 7);
  CHECK(s.s_type == 2);
  CHECK(s.signature == Bytes(129, 0));
  CHECK(f.counters.payloads["SIGN"]["invalidated"] == 1);
  CHECK(f.counters.payloads["RAND"]["pseudonymised"] == 1);
  CHECK(f.counters.payloads["SAKKE"]["kept"] == 1);
  CHECK(f.counters.key_ids["PCK"] == 1);
  // The same RAND and the same key identifier always give the same pseudonyms.
  const auto again = f.rewrite(private_call(0x1ABCDEF0u));
  CHECK(at<mikey::Rand>(again, 1).rand == r);
  CHECK(again.hdr.csb_id == m.hdr.csb_id);
  CHECK(f.counters.key_ids["PCK"] == 1);  // distinct identifiers
}

TEST_CASE("mikey rewrite: the timestamp follows --time-shift, COUNTER is kept", "[mikey][rewrite]") {
  Fixture f;
  f.options.time_shift_ns = 3LL * 86400 * 1000000000;
  const auto m = f.rewrite(private_call());
  const auto& tv = at<mikey::T>(m, 0).value;
  std::uint64_t v = 0;
  for (auto b : tv) v = (v << 8) | b;
  CHECK(v == 0xE9A1B2C380000000ull + (std::uint64_t{259200} << 32));
  CHECK(f.counters.payloads["T"]["shifted"] == 1);
  Fixture g;
  const auto c = g.rewrite(message(Header{}, {t(77, 2), rand(Bytes(16, 1)), sakke(Bytes(4, 1)), sign(Bytes(129, 1))}));
  CHECK(at<mikey::T>(c, 0).value == Bytes{0, 0, 0, 77});
  CHECK(g.counters.payloads["T"]["kept"] == 1);
}

TEST_CASE("mikey rewrite: SP keeps allowed parameters, zeroes the others; unknown extensions zeroed",
          "[mikey][rewrite]") {
  Fixture f;
  const Bytes in = message(Header{}, {t(1), rand(Bytes(16, 1)), sp(0, 0, {{0, Bytes{6}}, {20, Bytes{16}}, {14, Bytes{9, 9}}}),
                                      ext(6, sakke_payload(0, Bytes(8, 0x54))), ext(0, text("vendor-canary")),
                                      sakke(Bytes(4, 1)), sign(Bytes(129, 1))});
  const auto m = f.rewrite(in);
  const auto& s = at<mikey::Sp>(m, 2);
  REQUIRE(s.params.size() == 3);
  CHECK(s.params[0].second == Bytes{6});
  CHECK(s.params[1].second == Bytes{16});
  CHECK(s.params[2].second == Bytes(2, 0));
  CHECK(at<mikey::Ext>(m, 3).data == sakke_payload(0, Bytes(8, 0x54)));  // SAKKE-to-self kept
  CHECK(at<mikey::Ext>(m, 4).data == Bytes(13, 0));
  CHECK(f.counters.payloads["SP"]["kept"] == 2);
  CHECK(f.counters.payloads["SP"]["zeroed"] == 1);
  CHECK(f.counters.payloads["unknown-extension"]["zeroed"] == 1);
  CHECK(f.counters.payloads["SAKKE-to-self"]["kept"] == 1);
}

TEST_CASE("mikey rewrite: an undefined role/type pair has its data zeroed; incomplete counted", "[mikey][rewrite]") {
  Fixture f;
  const auto m = f.rewrite(message(Header{}, {t(1), idr(1, 2, text("raw-canary")), sign(Bytes(129, 1))}));
  CHECK(at<mikey::Idr>(m, 1).data == Bytes(10, 0));
  CHECK(f.counters.payloads["IDR"]["unknown-identity"] == 1);
  CHECK(f.counters.incomplete == 1);  // no RAND, no SAKKE
}

TEST_CASE("mikey rewrite: GENERIC-ID SSRCs take the 002 mapping, SPIs the key-identifier mapping",
          "[mikey][rewrite]") {
  Fixture f;
  Header h;
  h.blocks = {block(4, 0, {0}, {{0x11223344u, 7}}, Bytes{0x0A, 0xAA, 0xAA, 0xAA, 0x0B, 0xBB, 0xBB, 0xBB}),
              block(12, 0, {0}, {}, Bytes{1, 2})};
  const auto m = f.rewrite(message(h, {t(1), rand(Bytes(16, 1)), sakke(Bytes(4, 1)), sign(Bytes(129, 1))}));
  const auto& b = m.hdr.blocks.at(0);
  const std::uint32_t ssrc = (std::uint32_t{b.session_data[0]} << 24) | (std::uint32_t{b.session_data[1]} << 16) |
                             (std::uint32_t{b.session_data[2]} << 8) | b.session_data[3];
  CHECK(ssrc == *f.mapper.ssrc(0x11223344u));
  CHECK(Bytes(b.session_data.begin() + 4, b.session_data.end()) == Bytes{0, 0, 0, 7});  // ROC kept
  const std::uint32_t gmk = (std::uint32_t{b.spi[0]} << 24) | (std::uint32_t{b.spi[1]} << 16) |
                            (std::uint32_t{b.spi[2]} << 8) | b.spi[3];
  CHECK(gmk == *f.p.find_key_id(0x0AAAAAAAu));
  CHECK((gmk >> 28) == 0u);
  CHECK(m.hdr.blocks.at(1).spi == Bytes(2, 0));                 // other SPI lengths zeroed
  CHECK(f.counters.cs_ids["undefined-cs-id"] == 1);             // CS ID 12
}
