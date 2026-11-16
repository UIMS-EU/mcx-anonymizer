// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY-SAKKE UID (TS 33.180 §F.2.1.1) and the resolution of hidden identities (spec
// FR-010, FR-011).
#include "bytes/base64.hpp"
#include "mikey/decode.hpp"
#include "mikey/ledger.hpp"
#include "mikey/rewrite.hpp"
#include "mikey/uid.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/mikey_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"
#include "xml/categories.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>
#include <vector>

using namespace mcxanon;
using namespace mikey_test;

TEST_CASE("uid: the worked example of TS 33.180 §F.2.1.2", "[mikey][uid]") {
  CHECK(mikey::period_number(3599719634u, 2592000u, 0u) == 1388u);
  const Bytes u = mikey::uid("sip:user@example.org", "kms.example.org", 2592000u, 0u, 1388u);
  CHECK(base64::encode(u) == "OoH7FMOx0P5DycV3EE1VptgXiL/S8JdDxFV3RqWgNTs=");
}

namespace {

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 3 + 9);
  return s;
}

constexpr std::uint64_t kNtp = 0xE9A1B2C380000000ull;  // seconds 0xE9A1B2C3
constexpr std::uint64_t kPeriod = 2592000;

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
  mikey::Ledger ledger;
  std::vector<std::string> message_uris;

  mikey::Message rewrite(const Bytes& in) {
    ctx.message_uris = &message_uris;
    auto d = mikey::decode(in, rules);
    REQUIRE(d.verdict == mikey::Verdict::sakke);
    mikey::RewriteEnv env{rules, options, ctx, counters, nullptr, &ledger};
    REQUIRE(mikey::rewrite_message(*d.message, env).has_value());
    return *d.message;
  }
};

Bytes hidden_call(const Bytes& uidi, const Bytes& uidr_text_or_raw, std::uint8_t r_type) {
  return message(Header{}, {t(kNtp), rand(Bytes(16, 1)), idr(8, 2, uidi), idr(9, r_type, uidr_text_or_raw),
                            idr(6, 1, text("kms.example.org")), idr(7, 1, text("kms.example.org")),
                            sakke(Bytes(8, 0x53)), sign(Bytes(129, 1))});
}

}  // namespace

TEST_CASE("uid: resolved from the message's own identities with the KMS key period", "[mikey][uid]") {
  Fixture f;
  f.options.kms_periods = {{"kms.example.org", kPeriod, 0}};
  f.options.time_shift_ns = 40LL * 86400 * 1000000000;  // crosses into another key period
  const std::uint64_t p5 = mikey::period_number(0xE9A1B2C3u, kPeriod, 0);
  const Bytes uidi = mikey::uid("sip:alice@example.org", "kms.example.org", kPeriod, 0, p5);
  const Bytes uidr = mikey::uid("sip:bob@example.org", "kms.example.org", kPeriod, 0, p5);
  f.message_uris = {"sip:alice@example.org"};       // the caller is in this message's headers
  f.ledger.add("sip:bob@example.org");               // the callee was seen earlier in the run
  const auto m = f.rewrite(hidden_call(uidi, text(base64::encode(uidr)), 1));
  const std::string pa = **sip::rewrite_uri_text("sip:alice@example.org", f.ctx);
  const std::string pb = **sip::rewrite_uri_text("sip:bob@example.org", f.ctx);
  const std::string pk = **xml::map_category(XmlCategory::kms_uri, "kms.example.org", f.ctx);
  const std::uint64_t p5_out = mikey::period_number(0xE9A1B2C3u + 40u * 86400u, kPeriod, 0);
  CHECK(p5_out != p5);
  CHECK(std::get<mikey::Idr>(m.payloads[2].v).data == mikey::uid(pa, pk, kPeriod, 0, p5_out));
  const auto& r = std::get<mikey::Idr>(m.payloads[3].v);
  CHECK(std::string(r.data.begin(), r.data.end()) == base64::encode(mikey::uid(pb, pk, kPeriod, 0, p5_out)));
  CHECK(f.counters.uids_resolved == 2);
  CHECK(f.counters.uids_unresolved == 0);
}

TEST_CASE("uid: without a key period, or without a matching identity, an opaque pseudonym", "[mikey][uid]") {
  const std::uint64_t p5 = mikey::period_number(0xE9A1B2C3u, kPeriod, 0);
  const Bytes uidi = mikey::uid("sip:alice@example.org", "kms.example.org", kPeriod, 0, p5);
  const Bytes uidr = mikey::uid("sip:nobody@example.org", "kms.example.org", kPeriod, 0, p5);
  Fixture f;  // no --kms-key-period
  f.message_uris = {"sip:alice@example.org"};
  const auto m = f.rewrite(hidden_call(uidi, uidr, 2));
  const auto& a = std::get<mikey::Idr>(m.payloads[2].v).data;
  CHECK(a.size() == 32);
  CHECK(a != uidi);
  CHECK(f.counters.uids_unresolved == 2);
  // The same original UID always gets the same opaque pseudonym.
  const auto again = f.rewrite(hidden_call(uidi, uidr, 2));
  CHECK(std::get<mikey::Idr>(again.payloads[2].v).data == a);
  Fixture g;
  g.options.kms_periods = {{"kms.example.org", kPeriod, 0}};
  g.message_uris = {"sip:alice@example.org"};
  const auto n = g.rewrite(hidden_call(uidi, uidr, 2));
  CHECK(g.counters.uids_resolved == 1);    // alice
  CHECK(g.counters.uids_unresolved == 1);  // nobody: not seen in the run
  CHECK(std::get<mikey::Idr>(n.payloads[3].v).data != uidr);
}
