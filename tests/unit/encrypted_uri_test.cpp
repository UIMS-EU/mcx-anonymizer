// SPDX-License-Identifier: GPL-3.0-or-later
//
// An encrypted URI attribute (TS 33.180 §9.3.4.3):
// "sip:<b64 ciphertext>;iv=<b64>;key-id=<b64>;alg=128-aes-gcm@<domain>" keeps its structure. The
// ciphertext token takes a sip-user pseudonym, the IV the nonce mapping, the key-id the key
// identifier mapping (in the same base64 alphabet), alg is kept; any other form keeps the
// whole-user-part mapping of 002.
#include "bytes/base64.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/sip_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 31 + 3);
  return s;
}

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters counters;
  sip::Context ctx{rules, mapper, {}, counters};

  std::string run(const std::string& uri) {
    auto r = sip::rewrite_uri_text(uri, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
};

const Bytes kIv{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB};  // 96 bits
const Bytes kKey{0x2C, 0x5E, 0x91, 0xD0};                                                // a CSK-ID
const Bytes kCt{0x01, 0x22, 0x43, 0x64, 0x85, 0xA6, 0xC7, 0xE8, 0x09, 0x2A, 0x4B, 0x6C, 0x8D, 0xAE, 0xCF, 0xF0, 0x11, 0x32};

struct Parts {
  std::string token, iv, key_id, alg, host;
};

Parts split(const std::string& uri) {
  Parts p;
  const auto at = uri.rfind('@');
  REQUIRE(at != std::string::npos);
  p.host = uri.substr(at + 1);
  std::string user = uri.substr(4, at - 4);
  const auto i1 = user.find(";iv=");
  const auto i2 = user.find(";key-id=");
  const auto i3 = user.find(";alg=");
  REQUIRE(i1 != std::string::npos);
  REQUIRE(i2 != std::string::npos);
  REQUIRE(i3 != std::string::npos);
  p.token = user.substr(0, i1);
  p.iv = user.substr(i1 + 4, i2 - i1 - 4);
  p.key_id = user.substr(i2 + 8, i3 - i2 - 8);
  p.alg = user.substr(i3 + 5);
  return p;
}

}  // namespace

TEST_CASE("encrypted uri: standard alphabet, the structure kept and every part mapped", "[sip][encrypted-uri]") {
  Fixture f;
  base64::Layout l;
  const std::string in = "sip:" + base64::encode(kCt, l) + ";iv=" + base64::encode(kIv, l) + ";key-id=" +
                         base64::encode(kKey, l) + ";alg=128-aes-gcm@mc1-encryption.3gppnetwork.org";
  const auto out = split(f.run(in));
  const auto orig = split(in);
  CHECK(out.token != orig.token);
  CHECK_FALSE(out.token.empty());
  CHECK(base64::decode(out.iv)->bytes == *f.mapper.bytes(Category::nonce, kIv));
  const auto k = *f.mapper.key_id(0x2C5E91D0u);
  CHECK(base64::decode(out.key_id)->bytes ==
        Bytes{static_cast<std::uint8_t>(k >> 24), static_cast<std::uint8_t>(k >> 16), static_cast<std::uint8_t>(k >> 8),
              static_cast<std::uint8_t>(k)});
  CHECK(out.alg == "128-aes-gcm");
  CHECK(out.host != orig.host);
}

TEST_CASE("encrypted uri: the URL-safe alphabet without padding stays URL-safe", "[sip][encrypted-uri]") {
  Fixture f;
  base64::Layout l;
  l.padded = false;
  const std::string in = "sip:" + base64::encode(kCt, l, base64::Alphabet::url) + ";iv=" +
                         base64::encode(kIv, l, base64::Alphabet::url) + ";key-id=" +
                         base64::encode(kKey, l, base64::Alphabet::url) + ";alg=128-AES-GCM@mc1-encryption.3gppnetwork.org";
  const auto out = split(f.run(in));
  CHECK(out.key_id.size() == 6);
  CHECK(out.key_id.find_first_of("+/=") == std::string::npos);
  CHECK(base64::decode(out.key_id, base64::Alphabet::url).has_value());
  CHECK(base64::decode(out.iv, base64::Alphabet::url)->bytes == *f.mapper.bytes(Category::nonce, kIv));
  CHECK(out.alg == "128-AES-GCM");
}

TEST_CASE("encrypted uri: other forms keep the whole-user-part mapping", "[sip][encrypted-uri]") {
  Fixture f;
  // The corpus example (TS 33.180 §9.3.4.3): its 6-character key-id is not the base64 of 32 bits.
  for (const std::string& in : {
           std::string("sip:98yudFG45tx_89TYGedb4ujF;iv=FGD567kjhfH7d4-D;key-id=eV9kl7;alg=128-aes-gcm@mc1-encryption.3gppnetwork.org"),
           std::string("sip:98yudFG45tx_89TYGedb4ujF;iv=FGD567kjhfH7d4-D;key-id=LF6R0A;alg=256-aes-cbc@mc1-encryption.3gppnetwork.org"),
           std::string("sip:98yudFG45tx_89TYGedb4ujF;key-id=LF6R0A;iv=FGD567kjhfH7d4-D;alg=128-aes-gcm@mc1-encryption.3gppnetwork.org")}) {
    const auto out = f.run(in);
    CHECK(out.find(";key-id=") == std::string::npos);
    CHECK(out.find("FGD567kjhfH7d4-D") == std::string::npos);
    CHECK(out.find("98yudFG45tx_89TYGedb4ujF") == std::string::npos);
  }
}
