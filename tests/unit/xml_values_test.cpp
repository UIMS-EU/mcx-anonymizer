// SPDX-License-Identifier: GPL-3.0-or-later
//
// Value types of `keep` rules (feature 003, FR-008).
#include "xml/values.hpp"

#include <catch2/catch_test_macros.hpp>

#include <limits>

using namespace mcxanon::xml;
using K = ValueType::Kind;

namespace {
ValueType t(K k) {
  ValueType v;
  v.kind = k;
  return v;
}
ValueType en(std::vector<std::string> vals) {
  ValueType v = t(K::enumeration);
  v.values = std::move(vals);
  return v;
}
ValueType integer(std::int64_t min, std::uint64_t max) {
  ValueType v = t(K::integer);
  v.min = min;
  v.max = max;
  return v;
}
ValueType tok(TokenGrammar g) {
  ValueType v = t(K::token);
  v.grammar = g;
  return v;
}
}  // namespace

TEST_CASE("xml values: boolean") {
  for (auto s : {"true", "false", "1", "0", " true\r\n"}) CHECK(matches(t(K::boolean), s));
  for (auto s : {"TRUE", "yes", "", "2", "true false"}) CHECK_FALSE(matches(t(K::boolean), s));
}

TEST_CASE("xml values: enumeration is exact") {
  const auto e = en({"prearranged", "chat", "private"});
  CHECK(matches(e, "chat"));
  CHECK(matches(e, "\n  chat  "));
  CHECK_FALSE(matches(e, "Chat"));
  CHECK_FALSE(matches(e, "chat room"));
  CHECK_FALSE(matches(e, ""));
}

TEST_CASE("xml values: integers with bounds, including the 64-bit caps of X9") {
  const auto u8 = integer(0, 255);
  CHECK(matches(u8, "0"));
  CHECK(matches(u8, "255"));
  CHECK(matches(u8, "+7"));
  CHECK(matches(u8, "007"));
  CHECK_FALSE(matches(u8, "256"));
  CHECK_FALSE(matches(u8, "-1"));
  CHECK_FALSE(matches(u8, "1.5"));
  CHECK_FALSE(matches(u8, "0x10"));
  CHECK_FALSE(matches(u8, ""));
  CHECK_FALSE(matches(u8, "+"));
  const auto u64 = integer(0, std::numeric_limits<std::uint64_t>::max());
  CHECK(matches(u64, "18446744073709551615"));
  CHECK_FALSE(matches(u64, "18446744073709551616"));
  const auto s64 = integer(std::numeric_limits<std::int64_t>::min(), std::numeric_limits<std::int64_t>::max());
  CHECK(matches(s64, "-9223372036854775808"));
  CHECK_FALSE(matches(s64, "-9223372036854775809"));
  CHECK_FALSE(matches(s64, "9223372036854775808"));
  const auto pos = integer(1, 100);
  CHECK_FALSE(matches(pos, "0"));
}

TEST_CASE("xml values: XSD date and time forms") {
  for (auto s : {"2026-11-13T10:20:30Z", "2026-11-13T10:20:30.125+01:00", "2026-11-13T10:20:30", "-0044-03-15T12:00:00Z"})
    CHECK(matches(t(K::datetime), s));
  for (auto s : {"2026-11-13", "2026-13-01T00:00:00Z", "2026-11-13T25:00:00Z", "2026-11-13 10:20:30Z", "2026-11-13T10:20Z", "now"})
    CHECK_FALSE(matches(t(K::datetime), s));
  CHECK(matches(t(K::date), "2026-11-13"));
  CHECK(matches(t(K::date), "2026-11-13Z"));
  CHECK_FALSE(matches(t(K::date), "2026-11-13T00:00:00Z"));
  CHECK(matches(t(K::time), "23:59:59.5"));
  CHECK_FALSE(matches(t(K::time), "24:00:01"));
  for (auto s : {"PT30S", "P1Y2M3DT4H5M6.5S", "-P1D", "PT0S", "P0D"}) CHECK(matches(t(K::duration), s));
  for (auto s : {"P", "PT", "P1H", "1D", "PT1.S", "P1DT"}) CHECK_FALSE(matches(t(K::duration), s));
}

TEST_CASE("xml values: hex with fixed lengths") {
  ValueType h = t(K::hex);
  h.lengths = {4, 6};
  CHECK(matches(h, "00aF"));
  CHECK(matches(h, "abcdef"));
  CHECK_FALSE(matches(h, "abcde"));
  CHECK_FALSE(matches(h, "00g0"));
}

TEST_CASE("xml values: closed token grammars") {
  CHECK(matches(tok(TokenGrammar::trigger_id), "Trigger-1.a_b:c"));
  CHECK_FALSE(matches(tok(TokenGrammar::trigger_id), "two words"));
  CHECK_FALSE(matches(tok(TokenGrammar::trigger_id), std::string(65, 'a')));
  CHECK(matches(tok(TokenGrammar::hex_counter), "0A1b"));
  CHECK(matches(tok(TokenGrammar::hex_counter), "12345678"));
  CHECK_FALSE(matches(tok(TokenGrammar::hex_counter), "123456789"));
  CHECK(matches(tok(TokenGrammar::r_value), "mcpttp.0"));
  CHECK(matches(tok(TokenGrammar::r_value), "ets.2"));
  CHECK_FALSE(matches(tok(TokenGrammar::r_value), "mcpttp"));
  CHECK_FALSE(matches(tok(TokenGrammar::r_value), "a.b.c"));
  CHECK(matches(tok(TokenGrammar::ncname), "tuple-1"));
  CHECK_FALSE(matches(tok(TokenGrammar::ncname), "1tuple"));
  // RFC 3863 XSD qvalue (pidf contact@priority, User Story 2).
  for (const char* q : {"0", "0.", "0.5", "0.123", "1", "1.0", "1.000"}) CHECK(matches(tok(TokenGrammar::qvalue), q));
  for (const char* q : {"", "2", "0.1234", "1.5", "01", ".5", "1.0001"}) CHECK_FALSE(matches(tok(TokenGrammar::qvalue), q));
  // RFC 3261 token (RFC 4574 labels, User Story 5).
  CHECK(matches(tok(TokenGrammar::rfc_token), "audio-1"));
  CHECK(matches(tok(TokenGrammar::rfc_token), "1"));
  CHECK_FALSE(matches(tok(TokenGrammar::rfc_token), "a b"));
  CHECK_FALSE(matches(tok(TokenGrammar::rfc_token), "a/b"));
  CHECK(token_grammar("trigger-id") == TokenGrammar::trigger_id);
  CHECK(token_grammar("free-text") == std::nullopt);
}

TEST_CASE("xml values: standard URIs, language tags and empty") {
  ValueType u = t(K::std_uri);
  u.values = {"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"};
  CHECK(matches(u, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"));
  CHECK_FALSE(matches(u, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha1"));
  for (auto s : {"en", "en-GB", "pl", "zh-Hant-TW", "x-private"}) CHECK(matches(t(K::lang), s));
  for (auto s : {"", "en_GB", "toolongtag", "en--GB", "-en"}) CHECK_FALSE(matches(t(K::lang), s));
  CHECK(matches(t(K::empty), ""));
  CHECK(matches(t(K::empty), " \r\n\t"));
  CHECK_FALSE(matches(t(K::empty), "x"));
  CHECK(trim_xml_space("\t a b \n") == "a b");
}
