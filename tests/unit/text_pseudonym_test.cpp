// SPDX-License-Identifier: GPL-3.0-or-later
//
// Text and numeric pseudonym categories of feature 002.
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>

using namespace mcxanon;

namespace {
Secret secret(std::uint8_t seed = 7) {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * seed + 1);
  return s;
}
bool matches(const std::string& s, const char* re) { return std::regex_match(s, std::regex(re)); }

std::string text(Pseudonymiser& p, Category c, std::string_view v) {
  auto r = p.text(c, v);
  REQUIRE(r.has_value());
  return *r;
}

int luhn_ok(const std::string& d) {
  int sum = 0;
  for (std::size_t i = 0; i < d.size(); ++i) {
    int x = d[d.size() - 1 - i] - '0';
    if (i % 2 == 1) {
      x *= 2;
      if (x > 9) x -= 9;
    }
    sum += x;
  }
  return sum % 10 == 0;
}
}  // namespace

TEST_CASE("fixed-format text categories render their format", "[pseudo][text]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  CHECK(matches(text(p, Category::sip_user, "alice.nowak"), "u-[0-9a-f]{8}"));
  CHECK(matches(text(p, Category::display_name, "Alice Nowak"), "n-[0-9a-f]{8}"));
  CHECK(matches(text(p, Category::call_id, "a84b4c76e66710@pc33.example.net"), "c-[0-9a-f]{16}"));
  CHECK(matches(text(p, Category::tag, "1928301774"), "t-[0-9a-f]{8}"));
  CHECK(matches(text(p, Category::branch, "z9hG4bK776asdhds"), "z9hG4bKb-[0-9a-f]{12}"));
  CHECK(matches(text(p, Category::branch, "rfc2543-branch"), "b-[0-9a-f]{12}"));
  CHECK(matches(text(p, Category::entity_tag, "dx200xyz"), "e-[0-9a-f]{12}"));
  CHECK(matches(text(p, Category::charging_id, "AyretyU0dm+6O2IrT5tAFrbHLso="), "i-[0-9a-f]{16}"));
  CHECK(matches(text(p, Category::session_id, "ab30317f1a784dc48ff824d0d3715d86"), "[0-9a-f]{32}"));
  CHECK(matches(text(p, Category::boundary, "unique-boundary-1"), "mcxb-[0-9a-f]{24}"));
  CHECK(text(p, Category::boundary, "b").size() <= 70);  // RFC 2046 §5.1.1
  CHECK(matches(text(p, Category::msrp_session, "jshA7weztas"), "ms-[0-9a-f]{20}"));
  CHECK(matches(text(p, Category::reg_token, "1234567"), "rt-[0-9a-f]{8}"));
  CHECK(matches(text(p, Category::cname, "a1b2c3d4"), "cn-[0-9a-f]{12}"));
}

TEST_CASE("pseudonyms are deterministic per secret and differ across secrets", "[pseudo][text]") {
  const auto s1 = secret(7);
  const auto s2 = secret(11);
  Mapping m1, m2, m3;
  Pseudonymiser a(s1, m1), b(s1, m2), c(s2, m3);
  for (auto cat : {Category::sip_user, Category::display_name, Category::tag, Category::call_id,
                   Category::branch, Category::cname}) {
    const auto pa = text(a, cat, "Original-Value-1");
    CHECK(text(a, cat, "Original-Value-1") == pa);  // reused
    CHECK(text(b, cat, "Original-Value-1") == pa);  // fresh mapping, same secret
    CHECK(text(c, cat, "Original-Value-1") != pa);  // other project
    CHECK(text(a, cat, "Original-Value-2") != pa);
  }
  // The user part is case-sensitive (RFC 3261 §19.1.4).
  CHECK(text(a, Category::sip_user, "Alice") != text(a, Category::sip_user, "alice"));
  CHECK(a.stats().new_entries.at("sip-user") == 4);
}

TEST_CASE("a forced collision bumps the counter", "[pseudo][text][collision]") {
  const auto s = secret();
  Mapping fresh;
  Pseudonymiser probe(s, fresh);
  const auto first = text(probe, Category::tag, "tag-original");
  // Another original already holds the counter-0 candidate of "tag-original".
  Mapping m;
  const std::string other = "tag-other";
  REQUIRE(m.insert(MappingEntry{Category::tag, Bytes(other.begin(), other.end()),
                                Bytes(first.begin(), first.end()), 0, 0}));
  Pseudonymiser p(s, m);
  const auto got = text(p, Category::tag, "tag-original");
  CHECK(got != first);
  CHECK(matches(got, "t-[0-9a-f]{8}"));
  const std::string orig = "tag-original";
  const auto* e = m.find(Category::tag, Bytes(orig.begin(), orig.end()));
  REQUIRE(e != nullptr);
  CHECK(e->counter == 1);
  CHECK(p.stats().collisions_resolved == 1);
}

TEST_CASE("an original equal to an issued text pseudonym is a collision", "[pseudo][text][collision]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto u = text(p, Category::sip_user, "bob");
  const auto r = p.text(Category::sip_user, u);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::collision);
}

TEST_CASE("domains are pseudonymised per label under .invalid", "[pseudo][text][domain]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto full = p.domain("mcx.example.net");
  const auto parent = p.domain("example.net");
  const auto sibling = p.domain("ims.example.net");
  REQUIRE(full);
  REQUIRE(parent);
  REQUIRE(sibling);
  CHECK(matches(*full, "d-[0-9a-f]{8}\\.d-[0-9a-f]{8}\\.invalid"));
  CHECK(matches(*parent, "d-[0-9a-f]{8}\\.invalid"));
  // Subdomains of one parent keep a visibly shared suffix.
  CHECK(full->substr(11) == *parent);
  CHECK(sibling->substr(11) == *parent);
  CHECK(full->substr(0, 10) != sibling->substr(0, 10));
  // A label is derived together with its parent suffix: "mcx" under another parent differs.
  CHECK(p.domain("mcx.example.org")->substr(0, 10) != full->substr(0, 10));
  // Host names are case-insensitive (RFC 3261 §19.1.4); the canonical form is lowercase.
  CHECK(*p.domain("MCX.Example.NET") == *full);
  const std::string key = "mcx.example.net";
  CHECK(m.find(Category::domain, Bytes(key.begin(), key.end())) != nullptr);
  // A name already under .invalid is pseudonymised like any other; its top label stays.
  const auto inv = p.domain("mbms.invalid");
  REQUIRE(inv);
  CHECK(matches(*inv, "d-[0-9a-f]{8}\\.invalid"));
  CHECK(*inv != "mbms.invalid");
  // A realm that is not a host name is one label under.invalid.
  const auto realm = p.domain("Lab Realm 1");
  REQUIRE(realm);
  CHECK(matches(*realm, "d-[0-9a-f]{8}\\.invalid"));
  // A single-label host name.
  CHECK(matches(*p.domain("pcscf"), "d-[0-9a-f]{8}\\.invalid"));
  // A trailing dot of an absolute name is kept.
  CHECK(*p.domain("mcx.example.net.") == *full + ".");
}

TEST_CASE("telephone numbers keep digit count, plus and separators", "[pseudo][text][tel]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto a = p.tel("+48-601-234-567");
  REQUIRE(a);
  CHECK(matches(*a, "\\+[0-9]{2}-[0-9]{3}-[0-9]{3}-[0-9]{3}"));
  CHECK(*a != "+48-601-234-567");
  // Visual separators do not change the identity (RFC 3966 §5.1.1).
  const auto b = p.tel("+48601234567");
  REQUIRE(b);
  std::string digits_a;
  std::copy_if(a->begin(), a->end(), std::back_inserter(digits_a),
               [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)) != 0; });
  CHECK("+" + digits_a == *b);
  const auto local = p.tel("(0)22.555.0199");
  REQUIRE(local);
  CHECK(matches(*local, "\\([0-9]\\)[0-9]{2}\\.[0-9]{3}\\.[0-9]{4}"));
  // Special numbers of up to 3 digits are kept.
  CHECK(*p.tel("112") == "112");
  CHECK(*p.tel("+999") == "+999");
  CHECK(*p.tel("1234") != "1234");
}

TEST_CASE("IMEI pseudonyms keep 14 digits and a valid Luhn check digit", "[pseudo][text][imei]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto i = text(p, Category::imei, "35209900176148");
  CHECK(matches(i, "[0-9]{15}"));
  CHECK(luhn_ok(i));
  CHECK(i.substr(0, 14) != "35209900176148");
}

TEST_CASE("UUID pseudonyms are version 4 UUIDs", "[pseudo][text][uuid]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto u = text(p, Category::uuid, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
  CHECK(matches(u, "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"));
  // Case-insensitive original.
  CHECK(text(p, Category::uuid, "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6") == u);
}

TEST_CASE("digest and cell-id pseudonyms keep length and alphabet", "[pseudo][text][digest]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const std::string hex = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
  const auto h = text(p, Category::digest, hex);
  CHECK(h.size() == hex.size());
  CHECK(matches(h, "[0-9a-f]+"));
  CHECK(h != hex);
  const std::string upper = "6629FAE49393A05397450978507C4EF1";
  CHECK(matches(text(p, Category::digest, upper), "[0-9A-F]{32}"));
  const std::string b64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==";
  const auto b = text(p, Category::digest, b64);
  CHECK(b.size() == b64.size());
  CHECK(matches(b, "[A-Za-z0-9+/]{30}=="));
  const std::string tok = "0a4f113b-Opaque.Value";
  const auto t = text(p, Category::digest, tok);
  CHECK(matches(t, "[0-9][a-z][0-9][a-z][0-9]{3}[a-z]-[A-Z][a-z]{5}\\.[A-Z][a-z]{4}"));
  CHECK(text(p, Category::digest, "42").size() == 2);
  const auto cell = text(p, Category::cell_id, "234151D0FCE11");
  CHECK(cell.size() == 13);
  CHECK(matches(cell, "[0-9A-F]{13}"));
  CHECK(matches(text(p, Category::cell_id, "3101500010000001"), "[0-9]{16}"));
}

TEST_CASE("SDP session id keeps digit count; the version keeps its +1 steps", "[pseudo][text][sdp]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto id = text(p, Category::sdp_sess, "2890844526");
  CHECK(matches(id, "[1-9][0-9]{9}"));
  CHECK(id != "2890844526");
  CHECK(matches(text(p, Category::sdp_sess, "0123"), "[0-9]{4}"));
  const auto v1 = p.sdp_version("2890844526", "2890842807");
  const auto v2 = p.sdp_version("2890844526", "2890842808");
  REQUIRE(v1);
  REQUIRE(v2);
  CHECK(v1->size() == 10);
  CHECK(*v1 != "2890842807");
  CHECK(std::stoull(*v2) == (std::stoull(*v1) + 1) % 10000000000ull);
  // The offset depends on the session id.
  CHECK(*p.sdp_version("2890844527", "2890842807") != *v1);
  // Wrap-around modulo 10^digits keeps the digit count.
  const auto w = p.sdp_version("1", "9");
  REQUIRE(w);
  CHECK(w->size() == 1);
  // A very long number is handled digit-wise.
  const std::string long_id(40, '7');
  CHECK(text(p, Category::sdp_sess, long_id).size() == 40);
  CHECK(p.sdp_version(long_id, std::string(30, '1'))->size() == 30);
}

TEST_CASE("SPI and SSRC pseudonyms", "[pseudo][text][spi]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  for (std::uint32_t v : {0u, 1u, 255u}) CHECK(*p.spi(v) == v);  // RFC 4303 §2.1 reserved
  const auto a = p.spi(0x12345678u);
  REQUIRE(a);
  CHECK(*a > 255u);
  CHECK(*a != 0x12345678u);
  CHECK(*p.spi(0x12345678u) == *a);
  const auto x = p.ssrc(0x12345678u);
  REQUIRE(x);
  CHECK(*x != 0x12345678u);
  CHECK(*p.ssrc(0x12345678u) == *x);
}

TEST_CASE("every text category name round-trips", "[pseudo][text]") {
  for (const char* n : {"sip-user", "domain", "display-name", "tel", "call-id", "tag", "branch",
                        "entity-tag", "charging-id", "session-id", "imei", "uuid", "cell-id",
                        "spi", "ssrc", "digest", "sdp-sess", "boundary", "msrp-session",
                        "reg-token", "cname"}) {
    const auto c = category_from_string(n);
    REQUIRE(c.has_value());
    CHECK(to_string(*c) == n);
    // Text categories never share a value space with address categories.
    CHECK(family_of(*c) != family_of(Category::ipv4));
    CHECK(family_of(*c) != family_of(Category::mac));
  }
  CHECK(family_of(Category::tag) != family_of(Category::call_id));
}

TEST_CASE("short SDP session ids never end a run with a collision", "[pseudo][text][sdp]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  // Every one-digit original after every other: some original always equals an issued pseudonym.
  for (const char* v : {"1", "2", "3", "4", "5", "6", "7", "8", "9"}) {
    INFO(v);
    const auto r = p.text(Category::sdp_sess, v);
    REQUIRE(r.has_value());
    CHECK(*r != v);
  }
}
