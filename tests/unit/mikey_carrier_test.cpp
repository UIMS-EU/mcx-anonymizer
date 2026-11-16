// SPDX-License-Identifier: GPL-3.0-or-later
//
// Carrier encodings: binary or base64 application/mikey bodies and MCPC field
// 192, with and without Content-Transfer-Encoding; the base64 line layout; <GKTP> hexBinary letter
// case and surrounding XML whitespace.
#include "mikey/carrier.hpp"
#include "mikey/decode.hpp"
#include "policy/mikey_rules.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using namespace mikey_test;
using Kind = sip::MikeyCarrierKind;
using Enc = mikey::CarrierValue::Encoding;

namespace {

const MikeyRuleSet& rules() {
  static const MikeyRuleSet r = *load_embedded_mikey_ruleset();
  return r;
}

std::string as_string(const Bytes& b) { return std::string(b.begin(), b.end()); }

std::string b64_lines(std::string_view b64, std::size_t width, std::string_view brk = "\r\n", bool final_break = true) {
  std::string out;
  for (std::size_t i = 0; i < b64.size(); i += width) {
    out += b64.substr(i, width);
    if (i + width < b64.size() || final_break) out += brk;
  }
  return out;
}

std::string hex(const Bytes& b, bool upper) {
  const char* d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string s;
  for (auto x : b) {
    s += d[x >> 4];
    s += d[x & 15];
  }
  return s;
}

}  // namespace

TEST_CASE("carrier: a binary application/mikey body, with and without a binary CTE", "[mikey][carrier]") {
  const Bytes msg = private_call();
  for (std::string_view cte : {"", "binary", " Binary ", "8bit"}) {
    const auto c = mikey::decode_carrier(Kind::body, as_string(msg), cte, rules());
    REQUIRE(c.has_value());
    CHECK(c->encoding == Enc::binary);
    CHECK(c->bytes == msg);
    CHECK(mikey::encode_carrier(*c, msg) == as_string(msg));
  }
}

TEST_CASE("carrier: a base64 body is recognised with and without Content-Transfer-Encoding", "[mikey][carrier]") {
  const Bytes msg = private_call();
  const std::string one_line = base64::encode(msg);
  for (std::string_view cte : {"base64", "BASE64", ""}) {
    const auto c = mikey::decode_carrier(Kind::body, one_line, cte, rules());
    REQUIRE(c.has_value());
    CHECK(c->encoding == Enc::base64);
    CHECK(c->bytes == msg);
  }
  // Declared base64 but not base64: the carrier is not in its encoding.
  CHECK_FALSE(mikey::decode_carrier(Kind::body, as_string(msg), "base64", rules()).has_value());
  // An unknown transfer encoding is not understood.
  CHECK_FALSE(mikey::decode_carrier(Kind::body, one_line, "quoted-printable", rules()).has_value());
}

TEST_CASE("carrier: base64 text that is not MIKEY-SAKKE stays binary without a CTE", "[mikey][carrier]") {
  // "QUJD" is valid base64, but its 3 octets are no I_MESSAGE: read as 4 binary octets.
  const auto c = mikey::decode_carrier(Kind::body, "QUJD", "", rules());
  REQUIRE(c.has_value());
  CHECK(c->encoding == Enc::binary);
  CHECK(c->bytes == text("QUJD"));
}

TEST_CASE("carrier: the base64 line layout is kept (76 and 64 columns, CRLF and LF)", "[mikey][carrier]") {
  const Bytes msg = private_call();
  const std::string flat = base64::encode(msg);
  for (const auto& [width, brk, fin] : {std::tuple{76u, "\r\n", true}, std::tuple{64u, "\r\n", false},
                                        std::tuple{76u, "\n", true}}) {
    const std::string body = b64_lines(flat, width, brk, fin);
    const auto c = mikey::decode_carrier(Kind::body, body, "base64", rules());
    REQUIRE(c.has_value());
    CHECK(c->bytes == msg);
    CHECK(mikey::encode_carrier(*c, msg) == body);
    // A message of another length keeps the same width and breaks.
    Bytes other = msg;
    other.resize(msg.size() - 7);
    const std::string again = mikey::encode_carrier(*c, other);
    CHECK(again == b64_lines(base64::encode(other), width, brk, fin));
  }
}

TEST_CASE("carrier: MCPC field 192 is binary or base64 like a body", "[mikey][carrier]") {
  const Bytes msg = private_call();
  auto c = mikey::decode_carrier(Kind::mcpc, as_string(msg), "", rules());
  REQUIRE(c.has_value());
  CHECK(c->encoding == Enc::binary);
  c = mikey::decode_carrier(Kind::mcpc, base64::encode(msg), "", rules());
  REQUIRE(c.has_value());
  CHECK(c->encoding == Enc::base64);
  CHECK(c->bytes == msg);
}

TEST_CASE("carrier: GKTP hexBinary keeps the letter case and the surrounding whitespace", "[mikey][carrier]") {
  const Bytes msg = private_call();
  for (const bool upper : {false, true}) {
    const std::string value = "\n    " + hex(msg, upper) + "\n  ";
    const auto c = mikey::decode_carrier(Kind::gktp, value, "", rules());
    REQUIRE(c.has_value());
    CHECK(c->encoding == Enc::hex);
    CHECK(c->upper == upper);
    CHECK(c->bytes == msg);
    CHECK(mikey::encode_carrier(*c, msg) == value);
  }
  // No letter digit at all: upper case on output.
  const auto digits = mikey::decode_carrier(Kind::gktp, "0123", "", rules());
  REQUIRE(digits.has_value());
  CHECK(mikey::encode_carrier(*digits, Bytes{0xAB}) == "AB");
}

TEST_CASE("carrier: bad hexBinary is not in the carrier's encoding", "[mikey][carrier]") {
  for (std::string_view v : {"", "   ", "abc", "zz", "12 34", "canary"}) {
    CHECK_FALSE(mikey::decode_carrier(Kind::gktp, v, "", rules()).has_value());
  }
}

TEST_CASE("carrier: SDP values must be base64", "[mikey][carrier]") {
  const Bytes msg = private_call();
  CHECK(mikey::decode_carrier(Kind::sdp, base64::encode(msg), "", rules()).has_value());
  CHECK_FALSE(mikey::decode_carrier(Kind::sdp, as_string(msg), "", rules()).has_value());
}
