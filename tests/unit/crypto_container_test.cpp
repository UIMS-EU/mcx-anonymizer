// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/crypto.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {
KdfParams fast_params() {
  KdfParams p;
  p.m_kib = 64;  // small for tests; production uses 64 MiB
  p.t = 1;
  p.p = 1;
  for (std::size_t i = 0; i < p.salt.size(); ++i) p.salt[i] = static_cast<std::uint8_t>(i);
  return p;
}
Bytes data(const std::string& s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("container round trip", "[crypto]") {
  const auto params = fast_params();
  auto key = derive_key("correct horse battery staple", params);
  REQUIRE(key.has_value());
  auto sealed = seal(*key, params, "mapping", data("{\"format\": 1}"));
  REQUIRE(sealed.has_value());
  CHECK(std::string(sealed->begin(), sealed->begin() + 8) == "MCXENC01");
  CHECK(sealed->size() == 48 + 13 + 16);
  auto opened = open_sealed(*key, "mapping", *sealed);
  REQUIRE(opened.has_value());
  CHECK(*opened == data("{\"format\": 1}"));
  auto p = container_params(*sealed);
  REQUIRE(p.has_value());
  CHECK(p->m_kib == 64);
  CHECK(p->salt == params.salt);
}

TEST_CASE("wrong passphrase, tampering and swapped roles are rejected", "[crypto]") {
  const auto params = fast_params();
  auto key = derive_key("right", params);
  auto other = derive_key("wrong", params);
  REQUIRE(key.has_value());
  REQUIRE(other.has_value());
  auto sealed = seal(*key, params, "secret", data("0123456789abcdef0123456789abcdef"));
  REQUIRE(sealed.has_value());
  auto w = open_sealed(*other, "secret", *sealed);
  REQUIRE_FALSE(w.has_value());
  CHECK(w.error().code == ErrorCode::input);
  CHECK(w.error().message.find("wrong passphrase or tampered") != std::string::npos);
  for (std::size_t i : {0u, 9u, 20u, 40u, 50u, 70u}) {
    Bytes t = *sealed;
    t[i] ^= 0x01;
    INFO(i);
    CHECK_FALSE(open_sealed(*key, "secret", t).has_value());
  }
  CHECK_FALSE(open_sealed(*key, "mapping", *sealed).has_value());  // AAD binds the role
  CHECK_FALSE(open_sealed(*key, "secret", Bytes(10, 0)).has_value());
}

TEST_CASE("every write uses a fresh nonce", "[crypto]") {
  const auto params = fast_params();
  auto key = derive_key("pw", params);
  REQUIRE(key.has_value());
  auto a = seal(*key, params, "mapping", data("same"));
  auto b = seal(*key, params, "mapping", data("same"));
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(Bytes(a->begin() + 36, a->begin() + 48) != Bytes(b->begin() + 36, b->begin() + 48));
  CHECK(*a != *b);
}

TEST_CASE("key derivation is deterministic per salt", "[crypto]") {
  auto p1 = fast_params();
  auto p2 = p1;
  p2.salt[0] ^= 1;
  CHECK(*derive_key("x", p1) == *derive_key("x", p1));
  CHECK(*derive_key("x", p1) != *derive_key("x", p2));
}
