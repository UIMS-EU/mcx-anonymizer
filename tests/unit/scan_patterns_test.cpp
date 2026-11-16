// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/patterns.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace mcxanon;
using namespace mcxanon::scan;
using namespace mcxanon::scan::detail;

namespace {
std::vector<std::uint8_t> b(std::initializer_list<int> v) {
  std::vector<std::uint8_t> o;
  for (int x : v) o.push_back(static_cast<std::uint8_t>(x));
  return o;
}
std::vector<std::uint8_t> s(const std::string& t) { return {t.begin(), t.end()}; }
std::vector<std::uint8_t> u16le(const std::string& t) {
  std::vector<std::uint8_t> o;
  for (char ch : t) {
    o.push_back(static_cast<std::uint8_t>(ch));
    o.push_back(0);
  }
  return o;
}
bool has(const std::vector<Pattern>& ps, const std::vector<std::uint8_t>& bytes, const std::string& enc) {
  return std::any_of(ps.begin(), ps.end(), [&](const Pattern& p) { return p.bytes == bytes && p.encoding == enc; });
}
}  // namespace

TEST_CASE("IPv4 token encodings", "[scan][patterns]") {
  bool ok = false;
  const auto ps = expand(Token{TokenCategory::ipv4, b({10, 1, 2, 3}), "240.0.0.1"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, b({10, 1, 2, 3}), "binary"));
  CHECK(has(ps, s("10.1.2.3"), "text"));
  CHECK(has(ps, s("3.2.1.10.in-addr.arpa"), "reverse-dns"));
  CHECK(has(ps, s("0a010203"), "hex"));
  CHECK(has(ps, s("0A010203"), "hex-upper"));
  CHECK(has(ps, u16le("10.1.2.3"), "utf16le"));
  CHECK(has(ps, b({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3}), "ipv4-in-ipv6"));
  CHECK(has(ps, s("::ffff:10.1.2.3"), "ipv4-in-ipv6-text"));
  CHECK(has(ps, b({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 1, 2, 3}), "ipv4-in-ipv6"));  // NAT64
  CHECK(has(ps, b({0x20, 0x02, 10, 1, 2, 3}), "ipv4-in-ipv6"));                                      // 6to4
  const auto bin = std::find_if(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "binary"; });
  CHECK(bin->short_binary);
  CHECK(std::any_of(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "base64"; }));
}

TEST_CASE("IPv6 token encodings (RFC 5952 text)", "[scan][patterns]") {
  bool ok = false;
  const auto v6 = b({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  const auto ps = expand(Token{TokenCategory::ipv6, v6, "x"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, v6, "binary"));
  CHECK(has(ps, s("2001:db8::1"), "text"));
  CHECK(has(ps, s("2001:0db8:0000:0000:0000:0000:0000:0001"), "text-full"));
  CHECK(has(ps, s("2001:DB8::1"), "text-upper"));
  CHECK(has(ps, s("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"), "reverse-dns"));
  const auto fe = b({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55});
  const auto ps2 = expand(Token{TokenCategory::ipv6, fe, "x"}, 0, ok);
  CHECK(has(ps2, s("fe80::211:22ff:fe33:4455"), "text"));
  CHECK(format_ipv6(b({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}).data()) == "::");
  CHECK(format_ipv6(b({0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}).data()) == "2001:db8:1::1:0:1");
}

TEST_CASE("MAC token encodings, including modified EUI-64", "[scan][patterns]") {
  bool ok = false;
  const auto ps = expand(Token{TokenCategory::mac, b({0x00, 0x11, 0x22, 0x33, 0x44, 0x55}), "x"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, b({0x00, 0x11, 0x22, 0x33, 0x44, 0x55}), "binary"));
  CHECK(has(ps, s("00:11:22:33:44:55"), "text"));
  CHECK(has(ps, s("00-11-22-33-44-55"), "text-dash"));
  CHECK(has(ps, s("0011.2233.4455"), "text-dot"));
  CHECK(has(ps, s("001122334455"), "text-plain"));
  CHECK(has(ps, b({0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}), "eui64"));
  const auto bin = std::find_if(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "binary"; });
  CHECK_FALSE(bin->short_binary);  // 6 bytes: never suppressed
}

TEST_CASE("string tokens are case-insensitive and multi-encoding", "[scan][patterns]") {
  bool ok = false;
  const auto ps = expand(Token{TokenCategory::deny, s("Acme Secret"), "deny#1"}, 0, ok);
  REQUIRE(ok);
  const auto text = std::find_if(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "text"; });
  REQUIRE(text != ps.end());
  CHECK(text->fold);
  CHECK(text->bytes == s("acme secret"));
  CHECK(has(ps, u16le("acme secret"), "utf16le"));
  CHECK(has(ps, s("acme%20secret"), "url"));
  CHECK(std::any_of(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "base64" && !p.fold; }));
}

TEST_CASE("tokens shorter than four bytes are not scannable", "[scan][patterns]") {
  bool ok = true;
  const auto ps = expand(Token{TokenCategory::string, s("abc"), "x"}, 0, ok);
  CHECK_FALSE(ok);
  CHECK(ps.empty());
}

TEST_CASE("a 32-bit binary token below 2^16 is unscannable; larger ones are searched", "[scan][patterns][media]") {
  bool ok = false;
  // Feature 004: an SSRC like 0x00001234 would match zeroed payloads by chance.
  CHECK(expand(Token{TokenCategory::binary, b({0x00, 0x00, 0x12, 0x34}), "ssrc:1"}, 0, ok).empty());
  const auto ps = expand(Token{TokenCategory::binary, b({0x00, 0x01, 0x00, 0x00}), "ssrc:2"}, 0, ok);
  CHECK(has(ps, b({0x00, 0x01, 0x00, 0x00}), "binary"));
  CHECK(has(ps, s("65536"), "decimal"));
}

TEST_CASE("tokens with XML special characters are also searched in their XML-escaped forms", "[scan][patterns][xml]") {
  // Feature 003: a value written into an XML body as text or as an attribute
  // value in either quote style.
  bool ok = false;
  const auto ps = expand(Token{TokenCategory::string, s("Tom & \"Jerry's\" <unit>"), "x"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, s("tom &amp; \"jerry's\" &lt;unit&gt;"), "xml-escaped"));
  CHECK(has(ps, s("tom &amp; &quot;jerry's&quot; &lt;unit&gt;"), "xml-escaped"));
  CHECK(has(ps, s("tom &amp; \"jerry&apos;s\" &lt;unit&gt;"), "xml-escaped"));
  CHECK(has(ps, s("tom &amp; &quot;jerry&apos;s&quot; &lt;unit&gt;"), "xml-escaped"));
  const auto plain = expand(Token{TokenCategory::string, s("alice.nowak"), "y"}, 0, ok);
  CHECK(std::none_of(plain.begin(), plain.end(), [](const Pattern& p) { return p.encoding == "xml-escaped"; }));
}

// Feature 005: key identifiers and byte strings.
TEST_CASE("key token encodings: raw short binary, hex, base64, decimal", "[scan][patterns][mikey]") {
  bool ok = false;
  const auto v = b({0x1a, 0xbc, 0xde, 0xf0});
  const auto ps = expand(Token{TokenCategory::key, v, "key-id:1234abcd"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, v, "binary"));
  const auto bin = std::find_if(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "binary"; });
  CHECK(bin->short_binary);
  CHECK(has(ps, s("1abcdef0"), "hex"));
  CHECK(has(ps, s("1ABCDEF0"), "hex-upper"));
  CHECK(has(ps, s(std::to_string(0x1abcdef0u)), "decimal"));
  CHECK(std::any_of(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "base64"; }));
  bool small = true;
  expand(Token{TokenCategory::key, b({0, 0, 0, 1}), "x"}, 0, small);
  CHECK(small);  // a key identifier is scannable whatever its value (the hex form is 8 digits)
  bool wrong = true;
  expand(Token{TokenCategory::key, b({1, 2, 3}), "x"}, 0, wrong);
  CHECK_FALSE(wrong);
}

TEST_CASE("bytes token encodings: raw, hex, base64", "[scan][patterns][mikey]") {
  bool ok = false;
  std::vector<std::uint8_t> v(32);
  for (std::size_t i = 0; i < v.size(); ++i) v[i] = static_cast<std::uint8_t>(0x80 + i);
  const auto ps = expand(Token{TokenCategory::bytes, v, "uid:1"}, 0, ok);
  REQUIRE(ok);
  CHECK(has(ps, v, "binary"));
  std::string hex;
  static const char* d = "0123456789abcdef";
  for (auto x : v) {
    hex += d[x >> 4];
    hex += d[x & 15];
  }
  CHECK(has(ps, s(hex), "hex"));
  CHECK(std::count_if(ps.begin(), ps.end(), [](const Pattern& p) { return p.encoding == "base64"; }) == 3);
  bool short_ok = true;
  expand(Token{TokenCategory::bytes, b({1, 2, 3}), "x"}, 0, short_ok);
  CHECK_FALSE(short_ok);  // shorter than the 4-byte minimum pattern
}

TEST_CASE("token category names", "[scan][patterns][mikey]") {
  CHECK(to_string(TokenCategory::key) == "key");
  CHECK(to_string(TokenCategory::bytes) == "bytes");
}
