// SPDX-License-Identifier: GPL-3.0-or-later
//
// (moved forward, see Phase 3 notes): reveal and lookup for the categories of
// feature 005 — key-id as 8 hex digits, nonce and uid as hex (uid also as base64).
#include "bytes/base64.hpp"
#include "bytes/hex.hpp"
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {
std::string hex8(std::uint32_t v, bool upper = false) {
  char b[16];
  std::snprintf(b, sizeof b, upper ? "%08X" : "%08x", v);
  return b;
}
std::vector<LookupResult> look(Fixture& f, std::string_view v, LookupDirection d) {
  auto r = reveal::lookup_mapping(f.mapping, v, d, nullptr);
  REQUIRE(r.has_value());
  return *r;
}
}  // namespace

TEST_CASE("reveal: a key identifier as 8 hex digits, with and without 0x, either case", "[reveal][mikey]") {
  Fixture f;
  const std::uint32_t orig = 0x1ABCDEF0u;
  auto k = f.p.key_id(orig);
  REQUIRE(k.has_value());
  CHECK(f.reveal("PCK-ID " + hex8(*k) + " used") == "PCK-ID " + hex8(orig) + " used");
  CHECK(f.reveal("PCK-ID 0x" + hex8(*k) + ".") == "PCK-ID 0x" + hex8(orig) + ".");
  CHECK(f.reveal("PCK-ID " + hex8(*k, true)) == "PCK-ID " + hex8(orig, true));
}

TEST_CASE("reveal: nonce and uid as hex, uid also as base64", "[reveal][mikey]") {
  Fixture f;
  const Bytes rand(16, 0x52);
  auto n = f.p.bytes(Category::nonce, rand);
  REQUIRE(n.has_value());
  CHECK(f.reveal("RAND " + to_hex(*n) + " end") == "RAND " + to_hex(rand) + " end");
  CHECK(f.reveal("RAND " + to_hex(*n, true)) == "RAND " + to_hex(rand, true));
  const Bytes uid(32, 0x55);
  auto u = f.p.bytes(Category::uid, uid);
  REQUIRE(u.has_value());
  CHECK(f.reveal("UID " + to_hex(*u)) == "UID " + to_hex(uid));
  CHECK(f.reveal("UID " + base64::encode(*u) + " x") == "UID " + base64::encode(uid) + " x");
}

TEST_CASE("lookup: the new categories in both directions", "[reveal][mikey][lookup]") {
  Fixture f;
  auto k = f.p.key_id(0x2000AAAAu);
  REQUIRE(k.has_value());
  auto r = look(f, hex8(*k), LookupDirection::to_original);
  REQUIRE(r.size() == 1);
  CHECK(r[0].category == "key-id");
  CHECK(r[0].counterpart == "2000aaaa");
  auto back = look(f, "2000aaaa", LookupDirection::to_pseudonym);
  REQUIRE(back.size() == 1);
  CHECK(back[0].counterpart == hex8(*k));
  const Bytes rand(16, 0x31);
  auto n = f.p.bytes(Category::nonce, rand);
  REQUIRE(n.has_value());
  auto rn = look(f, to_hex(*n), LookupDirection::to_original);
  REQUIRE(rn.size() == 1);
  CHECK(rn[0].category == "nonce");
  CHECK(rn[0].counterpart == to_hex(rand));
}
