// SPDX-License-Identifier: GPL-3.0-or-later
//
// HPACK (RFC 7541; feature 007). The examples of RFC 7541 Appendix C decode
// with one dynamic table per connection direction; the encoder writes literals without indexing
// and without Huffman coding, which a fresh decoder reads back without any table insertion.
#include "http/hpack.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon::http;

namespace {

std::string unhex(std::string_view h) {
  std::string out;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<char>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
  return out;
}

std::vector<std::pair<std::string, std::string>> pairs(const std::vector<HeaderField>& v) {
  std::vector<std::pair<std::string, std::string>> out;
  for (const auto& f : v) out.emplace_back(f.name, f.value);
  return out;
}

using P = std::vector<std::pair<std::string, std::string>>;

}  // namespace

TEST_CASE("hpack: RFC 7541 C.3 requests without Huffman coding, one table", "[http][hpack]") {
  HpackDecoder d;
  auto a = d.decode(unhex("828684410f7777772e6578616d706c652e636f6d"));
  REQUIRE(a);
  CHECK(pairs(*a) == P{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}});
  CHECK(d.table_size() == 57);
  auto b = d.decode(unhex("828684be58086e6f2d6361636865"));
  REQUIRE(b);
  CHECK(pairs(*b) == P{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"},
                       {"cache-control", "no-cache"}});
  auto c = d.decode(unhex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"));
  REQUIRE(c);
  CHECK(pairs(*c) == P{{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"},
                       {":authority", "www.example.com"}, {"custom-key", "custom-value"}});
  CHECK(d.table_size() == 164);
}

TEST_CASE("hpack: RFC 7541 C.4 requests with Huffman coding", "[http][hpack]") {
  HpackDecoder d;
  auto a = d.decode(unhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"));
  REQUIRE(a);
  CHECK((*a)[3].value == "www.example.com");
  auto b = d.decode(unhex("828684be5886a8eb10649cbf"));
  REQUIRE(b);
  CHECK((*b)[4].value == "no-cache");
  auto c = d.decode(unhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"));
  REQUIRE(c);
  CHECK((*c)[4].name == "custom-key");
  CHECK((*c)[4].value == "custom-value");
}

TEST_CASE("hpack: RFC 7541 C.5.1 and C.6.1 responses", "[http][hpack]") {
  HpackDecoder plain;
  auto r = plain.decode(unhex("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d54"
                              "6e1768747470733a2f2f7777772e6578616d706c652e636f6d"));
  REQUIRE(r);
  CHECK(pairs(*r) == P{{":status", "302"}, {"cache-control", "private"}, {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                       {"location", "https://www.example.com"}});
  HpackDecoder huff;
  auto h = huff.decode(unhex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"));
  REQUIRE(h);
  CHECK(pairs(*h) == pairs(*r));
}

TEST_CASE("hpack: the encoder writes literals without indexing, raw strings", "[http][hpack]") {
  const std::vector<HeaderField> in{{":method", "GET"}, {":path", "/x"}, {"x-unknown", "v"}};
  const auto e = hpack_encode(in);
  // :method has static name index 2: 0000 0010; the value is a raw string (H bit 0).
  CHECK(static_cast<unsigned char>(e[0]) == 0x02);
  CHECK(static_cast<unsigned char>(e[1]) == 0x03);
  HpackDecoder d;
  auto back = d.decode(e);
  REQUIRE(back);
  CHECK(pairs(*back) == pairs(in));
  CHECK(d.table_size() == 0);  // nothing inserted
}

TEST_CASE("hpack: hostile blocks are refused", "[http][hpack]") {
  HpackDecoder d;
  CHECK_FALSE(d.decode(unhex("be")));            // dynamic index 62 with an empty table
  CHECK_FALSE(d.decode(unhex("80")));            // index 0
  CHECK_FALSE(d.decode(unhex("82" "3fe11f")));   // size update after a field
  CHECK_FALSE(d.decode(unhex("3fffffffff0f"))); // integer overflow
  CHECK_FALSE(d.decode(unhex("0081ff")));        // a name literal cut short
  CHECK_FALSE(huffman_decode(unhex("ff")));      // 8 bits of padding
  CHECK_FALSE(huffman_decode(unhex("fe")));      // padding that is not all ones
  CHECK(huffman_decode(huffman_encode("custom-value")) == std::string("custom-value"));
}
