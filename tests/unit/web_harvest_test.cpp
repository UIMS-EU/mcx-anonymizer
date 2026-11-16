// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own HTTP harvest and output carriers.
#include "scan/walker/hpack_strings.hpp"
#include "scan/walker/web_carriers.hpp"
#include "scan/walker/web_harvest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>

using namespace mcxanon;
using namespace mcxanon::scan::detail;

namespace {
std::set<std::string> values(WebHarvest& h) {
  std::set<std::string> out;
  for (const auto& t : h.take()) out.emplace(t.value.begin(), t.value.end());
  return out;
}
}  // namespace

TEST_CASE("web harvest: targets, headers, forms, JSON and JWTs", "[scan][web]") {
  WebHarvest h;
  h.text("GET /org.3gpp.mcptt.user-profile/users/sip%3Ahenry%40example.org/index?state=st4t3val&scope=openid HTTP/1.1\r\n"
         "Host: gms.example.org:8080\r\nAuthorization: Basic dXNlcjE6cGFzc3dvcmQx\r\nCookie: SID=c00kieval\r\n"
         "X-3GPP-Asserted-Identity: \"sip:ivyuser@example.org\"\r\n\r\n"
         "grant_type=password&username=jackuser&password=pa55word\r\n"
         "{\"access_token\":\"eyJhbGciOiJub25lIn0.eyJzdWIiOiJzaXA6a2F0ZUBleGFtcGxlLm9yZyJ9.c2lnbmF0dXJl\"}");
  const auto v = values(h);
  for (const char* x : {"henry", "example.org", "st4t3val", "gms.example.org", "user1", "password1", "c00kieval", "ivyuser",
                        "jackuser", "pa55word", "kate", "c2lnbmF0dXJl"}) {
    INFO(x);
    CHECK(v.contains(x));
  }
  CHECK_FALSE(v.contains("openid"));
  CHECK_FALSE(v.contains("password"));
}

TEST_CASE("web harvest: loopback addresses are kept, other IPv4 literals are binary tokens", "[scan][web]") {
  WebHarvest h;
  h.text("GET /cb?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcb HTTP/1.1\r\nHost: 10.1.2.3\r\n\r\n");
  const auto t = h.take();
  bool loop = false;
  bool ten = false;
  for (const auto& x : t) {
    if (x.category == scan::TokenCategory::ipv4 && x.value == std::vector<std::uint8_t>{10, 1, 2, 3}) ten = true;
    if (std::string(x.value.begin(), x.value.end()).find("127.0.0.1") != std::string::npos) loop = true;
  }
  CHECK(ten);
  CHECK_FALSE(loop);
}

TEST_CASE("web carriers: JWT segments and Huffman HPACK strings are decoded", "[scan][web]") {
  const std::string jwt = "x eyJhbGciOiJub25lIn0.eyJzdWIiOiJsZWFrIn0.sig y";
  auto c = find_web_carriers(std::span(reinterpret_cast<const std::uint8_t*>(jwt.data()), jwt.size()));
  bool claim = false;
  for (const auto& s : c) claim = claim || std::string(s.decoded.begin(), s.decoded.end()).find("leak") != std::string::npos;
  CHECK(claim);
  // HEADERS frame with a Huffman literal "custom-key: custom-value" (RFC 7541 C.4.3 encoding).
  const std::string block = std::string("\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf", 20);
  std::string frame = std::string("\x00\x00", 2) + static_cast<char>(block.size()) + std::string("\x01\x04\x00\x00\x00\x01", 6) + block;
  auto h = find_web_carriers(std::span(reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size()));
  REQUIRE(h.size() >= 1);
  bool val = false;
  for (const auto& s : h) val = val || std::string(s.decoded.begin(), s.decoded.end()) == "custom-value";
  CHECK(val);
  CHECK(hpack_huffman(std::string("\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f", 8)) == std::string("custom-key"));
}
