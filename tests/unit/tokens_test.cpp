// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scan set includes every original of the new mapping categories (FR-030),
// and the scanner finds them in the encodings of FR-032.
#include "pipeline/tokens.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <map>
#include <string>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i + 77);
  return s;
}
std::span<const std::uint8_t> bytes(const std::string& s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}
}  // namespace

TEST_CASE("every new mapping category becomes a scan token", "[tokens][sip]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const std::map<Category, std::string> originals{
      {Category::sip_user, "alice.nowak"},       {Category::display_name, "Alice Nowak"},
      {Category::call_id, "a84b4c76e66710"},     {Category::tag, "1928301774"},
      {Category::branch, "z9hG4bK776asdhds"},    {Category::entity_tag, "dx200xyz"},
      {Category::charging_id, "AyretyU0dm+6O2Ir"}, {Category::session_id, "ab30317f1a784dc48ff824d0d3715d86"},
      {Category::imei, "35209900176148"},        {Category::uuid, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"},
      {Category::cell_id, "234151D0FCE11"},      {Category::digest, "6629fae49393a05397450978507c4ef1"},
      {Category::sdp_sess, "2890844526"},        {Category::boundary, "unique-boundary-1"},
      {Category::msrp_session, "kjhd37s2s20w2a"}, {Category::reg_token, "1234567"},
      {Category::cname, "a1b2c3d4e5"}};
  for (const auto& [c, v] : originals) REQUIRE(p.text(c, v));
  REQUIRE(p.domain("mcx.example.net"));
  REQUIRE(p.tel("+48601234567"));
  REQUIRE(p.spi(0x12345678u));
  REQUIRE(p.ssrc(0x0BADCAFEu));

  const auto tokens = mapping_tokens(m);
  const auto find = [&](scan::TokenCategory cat, const std::string& value) {
    return std::find_if(tokens.begin(), tokens.end(), [&](const scan::Token& t) {
      return t.category == cat && std::string(t.value.begin(), t.value.end()) == value;
    });
  };
  for (const auto& [c, v] : originals) {
    INFO(to_string(c));
    const bool numeric = c == Category::imei || c == Category::sdp_sess;
    const auto it = find(numeric ? scan::TokenCategory::number : scan::TokenCategory::string, v);
    REQUIRE(it != tokens.end());
    // Labelled with the pseudonym, never with the original.
    const auto* e = m.find(c, Bytes(v.begin(), v.end()));
    REQUIRE(e != nullptr);
    CHECK(it->label.find(std::string(e->pseudonym.begin(), e->pseudonym.end())) != std::string::npos);
    CHECK(it->label.find(v) == std::string::npos);
  }
  CHECK(find(scan::TokenCategory::string, "mcx.example.net") != tokens.end());
  CHECK(find(scan::TokenCategory::string, "example.net") != tokens.end());
  CHECK(find(scan::TokenCategory::number, "48601234567") != tokens.end());  // digits, without "+"
  const auto spi = std::find_if(tokens.begin(), tokens.end(), [](const scan::Token& t) {
    return t.category == scan::TokenCategory::binary && t.value == Bytes{0x12, 0x34, 0x56, 0x78};
  });
  CHECK(spi != tokens.end());
  CHECK(std::any_of(tokens.begin(), tokens.end(), [](const scan::Token& t) {
    return t.category == scan::TokenCategory::binary && t.value == Bytes{0x0B, 0xAD, 0xCA, 0xFE};
  }));
}

TEST_CASE("number, binary and SIP-escaped forms are found (FR-032)", "[tokens][sip][scan]") {
  std::vector<scan::Token> t{
      {scan::TokenCategory::number, Bytes{'4', '8', '6', '0', '1', '2', '3', '4', '5', '6', '7'}, "tel#1"},
      {scan::TokenCategory::binary, Bytes{0x12, 0x34, 0x56, 0x78}, "spi#1"},
      {scan::TokenCategory::string, Bytes{'a', 'l', 'i', 'c', 'e', '.', 'n'}, "u-1"}};
  const scan::Index ix(t);
  const auto hits = [&](const std::string& data) { return scan::scan_bytes(bytes(data), ix).hits.size(); };
  CHECK(hits("tel:+48601234567;x") == 1);
  CHECK(hits("x 486012345678 y") == 0);   // digit-bounded: part of a longer number
  CHECK(hits("x 148601234567 y") == 0);
  CHECK(hits("spi-c=305419896;") == 1);   // the decimal form of the binary value
  CHECK(hits("spi-c=3054198960;") == 0);
  CHECK(hits(std::string("\x12\x34\x56\x78", 4)) == 1);
  CHECK(hits("sip:%61%6C%69%63%65%2E%6E@x") == 1);  // every character escaped (RFC 3261 §25.1)
  CHECK(hits("sip:%61%6c%69%63%65%2e%6e@x") == 1);
  CHECK(hits("sip:ALICE.N@x") == 1);
  // Short tokens are unscannable, counted by category and reason.
  std::vector<scan::Token> s{{scan::TokenCategory::number, Bytes{'1', '2', '3'}, "tel#2"},
                             {scan::TokenCategory::string, Bytes{'a', 'b'}, "u-2"}};
  const scan::Index sx(s);
  const auto r = scan::scan_bytes(bytes("123 ab"), sx);
  CHECK(r.unscannable_tokens == 2);
  CHECK(r.unscannable_by_category.at("number/short") == 1);
  CHECK(r.unscannable_by_category.at("string/short") == 1);
}
