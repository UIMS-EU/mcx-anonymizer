// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/hex.hpp"
#include "pseudo/hmac.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

TEST_CASE("HMAC-SHA-256, RFC 4231 test cases 1 and 2", "[pseudo][hmac]") {
  // Test case 1: key = 0x0b * 20, data = "Hi There".
  const Bytes key1(20, 0x0b);
  const std::string data1 = "Hi There";
  CHECK(to_hex(hmac_sha256(key1, Bytes(data1.begin(), data1.end()))) ==
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  // Test case 2: key = "Jefe", data = "what do ya want for nothing?".
  const std::string key2 = "Jefe";
  const std::string data2 = "what do ya want for nothing?";
  CHECK(to_hex(hmac_sha256(Bytes(key2.begin(), key2.end()), Bytes(data2.begin(), data2.end()))) ==
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("derivation input layout", "[pseudo][hmac]") {
  const Bytes original{10, 0, 0, 1};
  const Bytes msg = derivation_message("ipv4", original, 7);
  // "mcxanon/v1" 0x00 "ipv4" 0x00 original counter_be32
  const std::string prefix = "mcxanon/v1";
  Bytes expected(prefix.begin(), prefix.end());
  expected.push_back(0);
  expected.insert(expected.end(), {'i', 'p', 'v', '4'});
  expected.push_back(0);
  expected.insert(expected.end(), original.begin(), original.end());
  expected.insert(expected.end(), {0, 0, 0, 7});
  CHECK(msg == expected);
}

TEST_CASE("derivation is deterministic and separates categories and counters", "[pseudo][hmac]") {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i);
  const Bytes orig{192, 168, 0, 1};
  const auto a = derive(s, "ipv4", orig, 0);
  CHECK(a == derive(s, "ipv4", orig, 0));
  CHECK(a != derive(s, "ipv4", orig, 1));
  CHECK(a != derive(s, "ipv4-pp", orig, 0));
  Secret t = s;
  t[0] ^= 1;
  CHECK(a != derive(t, "ipv4", orig, 0));
  CHECK(a == hmac_sha256(s, derivation_message("ipv4", orig, 0)));
}
