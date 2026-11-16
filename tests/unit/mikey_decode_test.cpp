// SPDX-License-Identifier: GPL-3.0-or-later
//
// The bounded MIKEY parser and encoder.
#include "mikey/decode.hpp"
#include "mikey/encode.hpp"
#include "policy/mikey_rules.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <variant>

using namespace mcxanon;
using namespace mikey_test;

namespace {
const MikeyRuleSet& rules() {
  static const MikeyRuleSet rs = *load_embedded_mikey_ruleset();
  return rs;
}
mikey::Decoded parse(const Bytes& b) { return mikey::decode(b, rules()); }
}  // namespace

TEST_CASE("mikey decode: a private call I_MESSAGE parses into its payloads", "[mikey][decode]") {
  const Bytes m = private_call();
  const auto d = parse(m);
  REQUIRE(d.verdict == mikey::Verdict::sakke);
  REQUIRE(d.message.has_value());
  const auto& msg = *d.message;
  CHECK(msg.hdr.csb_id == 0x1ABCDEF0u);
  CHECK(msg.hdr.cs_count == 0);
  CHECK(msg.hdr.map_type == 1);
  REQUIRE(msg.payloads.size() == 8);
  CHECK(std::get<mikey::T>(msg.payloads[0].v).ts_type == 0);
  CHECK(std::get<mikey::Rand>(msg.payloads[1].v).rand == Bytes(16, 0x52));
  const auto& i = std::get<mikey::Idr>(msg.payloads[2].v);
  CHECK(i.role == 1);
  CHECK(i.id_type == 1);
  CHECK(i.data == text("sip:alice@example.org"));
  CHECK(std::get<mikey::Sakke>(msg.payloads[6].v).data.size() == 273);
  const auto& s = std::get<mikey::Sign>(msg.payloads[7].v);
  CHECK(s.s_type == 2);
  CHECK(s.signature.size() == 129);
  // Unmodified, the encoder gives back the same bytes.
  CHECK(mikey::encode(msg) == m);
}

TEST_CASE("mikey decode: GENERIC-ID blocks and every allowed payload kind", "[mikey][decode]") {
  Header h;
  h.blocks = {block(4, 0, {0}, {{0x11223344u, 7}}, Bytes{0x0A, 0xAA, 0xAA, 0xAA, 0x0B, 0xBB, 0xBB, 0xBB})};
  const Bytes m = message(h, {t(5, 2), rand(Bytes(20, 1)), idr(8, 2, Bytes(32, 0x55)),
                              sp(0, 0, {{0, Bytes{6}}, {20, Bytes{16}}}), ext(6, sakke_payload(0, Bytes(9, 0x54))),
                              ext(7, Bytes(40, 0x43)), sakke(Bytes(10, 0x53)), sign(Bytes(129, 0x47))});
  const auto d = parse(m);
  REQUIRE(d.verdict == mikey::Verdict::sakke);
  const auto& hdr = d.message->hdr;
  CHECK(hdr.cs_count == 1);
  CHECK(hdr.map_type == 2);
  REQUIRE(hdr.blocks.size() == 1);
  CHECK(hdr.blocks[0].cs_id == 4);
  CHECK(hdr.blocks[0].policies == std::vector<std::uint8_t>{0});
  CHECK(hdr.blocks[0].session_data.size() == 8);
  CHECK(hdr.blocks[0].spi.size() == 8);
  CHECK(std::get<mikey::T>(d.message->payloads[0].v).value.size() == 4);  // COUNTER
  CHECK(std::get<mikey::Sp>(d.message->payloads[3].v).params.size() == 2);
  CHECK(std::get<mikey::Ext>(d.message->payloads[4].v).type == 6);
  CHECK(mikey::encode(*d.message) == m);
}

TEST_CASE("mikey decode: not MIKEY-SAKKE", "[mikey][decode]") {
  const auto with = [](auto change) {
    Header h;
    change(h);
    return message(h, {t(1), rand(Bytes(16, 1)), sakke(Bytes(4, 1)), sign(Bytes(129, 1))});
  };
  for (int dt : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 27}) {
    CHECK(parse(with([dt](Header& h) { h.data_type = static_cast<std::uint8_t>(dt); })).verdict ==
          mikey::Verdict::not_sakke);
  }
  CHECK(parse(with([](Header& h) { h.v = true; })).verdict == mikey::Verdict::not_sakke);
  CHECK(parse(with([](Header& h) { h.version = 2; })).verdict == mikey::Verdict::not_sakke);
  // A payload outside the allowlist (KEMAC = 1, CERT = 7, Key data = 20), and RSA SIGN.
  for (int ty : {1, 7, 20}) {
    const Bytes m = message(Header{}, {t(1), Part{static_cast<std::uint8_t>(ty), Bytes{0, 0, 0, 0}}, sign(Bytes(129, 1))});
    const auto d = parse(m);
    CHECK(d.verdict == mikey::Verdict::not_sakke);
    CHECK(d.reason == "unknown-payload");
  }
  CHECK(parse(message(Header{}, {t(1), sakke(Bytes(4, 1)), sign(Bytes(128, 1), 0)})).verdict ==
        mikey::Verdict::not_sakke);
  // An IDRpsk role makes it a pre-shared-key exchange.
  CHECK(parse(message(Header{}, {t(1), idr(4, 2, Bytes(4, 1)), sign(Bytes(129, 1))})).verdict ==
        mikey::Verdict::not_sakke);
}

TEST_CASE("mikey decode: malformed at every payload boundary", "[mikey][decode]") {
  const Bytes m = private_call();
  for (std::size_t cut = 1; cut < m.size(); ++cut) {
    const Bytes part(m.begin(), m.begin() + static_cast<std::ptrdiff_t>(cut));
    const auto d = parse(part);
    CHECK(d.verdict != mikey::Verdict::sakke);
    CHECK_FALSE(d.message.has_value());
  }
  Bytes trailing = m;
  trailing.push_back(0);
  CHECK(parse(trailing).verdict == mikey::Verdict::malformed);
  // A SIGN that is not last: the chain continues after it.
  Bytes sign_first = message(Header{}, {sign(Bytes(4, 1)), t(1)});
  CHECK(parse(sign_first).verdict == mikey::Verdict::malformed);
  // Another map type with #CS > 0.
  Bytes other_map = m;
  other_map[8] = 1;   // #CS
  other_map[9] = 0;   // SRTP-ID
  CHECK(parse(other_map).verdict == mikey::Verdict::malformed);
  // A chain that ends without SIGN.
  CHECK(parse(message(Header{}, {t(1), rand(Bytes(16, 1))})).verdict == mikey::Verdict::malformed);
  // An unknown TS type.
  Bytes bad_ts = m;
  bad_ts[11] = 9;
  CHECK(parse(bad_ts).verdict == mikey::Verdict::malformed);
  // A SAKKE-to-self that is not one SAKKE payload.
  CHECK(parse(message(Header{}, {t(1), ext(6, Bytes(3, 1)), sakke(Bytes(4, 1)), sign(Bytes(129, 1))})).verdict ==
        mikey::Verdict::malformed);
}

TEST_CASE("mikey decode: limits", "[mikey][decode]") {
  CHECK(parse(Bytes(65536, 0)).verdict == mikey::Verdict::limit);
  std::vector<Part> many;
  for (int i = 0; i < 70; ++i) many.push_back(rand(Bytes(16, 1)));
  many.push_back(sign(Bytes(129, 1)));
  CHECK(parse(message(Header{}, many)).verdict == mikey::Verdict::limit);
  CHECK(parse(message(Header{}, {t(1), idr(1, 1, Bytes(1025, 'a')), sign(Bytes(129, 1))})).verdict ==
        mikey::Verdict::limit);
  CHECK(parse(Bytes{}).verdict == mikey::Verdict::malformed);
}
