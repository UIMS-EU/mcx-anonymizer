// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 008 (FR-001): a value that the scanner's SIP/SDP harvester reads up to the end of a TCP
// payload may continue in the next segment. It is not an original value until its end is seen:
// it is dropped (and counted) when the next payload of the direction gives the whole value, and
// searched anyway when the direction never continues. This test includes nothing from src/sip/.
#include "scan/walker/sip_harvest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace mcxanon;
using namespace mcxanon::scan;

namespace {
std::span<const std::uint8_t> bytes(const std::string& s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}
bool has(const std::vector<Token>& t, TokenCategory c, const std::string& v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) {
    return x.category == c && std::string(x.value.begin(), x.value.end()) == v;
  });
}
bool has_bin(const std::vector<Token>& t, TokenCategory c, std::vector<std::uint8_t> v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) { return x.category == c && x.value == v; });
}
const std::vector<std::uint8_t> kDir{10, 0, 0, 1, 10, 0, 0, 2, 0x13, 0xc4, 0x9c, 0x40, 0};
const std::string kCookie = "z9hG4bK";
const std::string kHead =
    "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP core.example.net:5060;received=192.0.2.7;branch=";
const std::string kTail = "77ac41e09d.0\r\nCall-ID: 5c1f2a@ua.example.net\r\nContent-Length: 0\r\n\r\n";
}  // namespace

TEST_CASE("a branch cut inside the magic cookie is not a token; the whole branch is", "[scan][fragment]") {
  for (std::size_t k = 1; k < kCookie.size(); ++k) {
    INFO("cut after " << k << " cookie characters");
    detail::SipHarvest h;
    h.feed(bytes(kHead + kCookie.substr(0, k)), kDir, true);
    h.feed(bytes(kCookie.substr(k) + kTail), kDir, true);
    const auto t = h.take();
    CHECK(has(t, TokenCategory::string, kCookie + "77ac41e09d.0"));
    CHECK(has(t, TokenCategory::string, "core.example.net"));
    for (std::size_t n = 4; n < kCookie.size(); ++n) CHECK_FALSE(has(t, TokenCategory::string, kCookie.substr(0, n)));
    // Only fragments of at least 4 bytes would have been tokens.
    CHECK(h.fragments() == (k >= 4 ? 1u : 0u));
  }
}

TEST_CASE("a cut host, telephone number and Call-ID are resolved by their continuation", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes("INVITE sip:bob@example.net SIP/2.0\r\nFrom: <sip:alice@lab.exam"), kDir, true);
  h.feed(bytes("ple.net>;tag=88331\r\nTo: <tel:+4860123"), kDir, true);
  h.feed(bytes("4567>\r\nCall-ID: abcdef"), kDir, true);
  h.feed(bytes("123456\r\nContent-Length: 0\r\n\r\n"), kDir, true);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "lab.example.net"));
  CHECK_FALSE(has(t, TokenCategory::string, "lab.exam"));
  CHECK(has(t, TokenCategory::number, "48601234567"));
  CHECK_FALSE(has(t, TokenCategory::number, "4860123"));
  CHECK(has(t, TokenCategory::string, "abcdef123456"));
  CHECK_FALSE(has(t, TokenCategory::string, "abcdef"));
  CHECK(h.fragments() == 3);
}

TEST_CASE("a user part cut before its @ is resolved by the whole user part", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes("INVITE sip:bob@example.net SIP/2.0\r\nFrom: <sip:charlie.split"), kDir, true);
  h.feed(bytes("user@lab.example.net>;tag=987654321\r\n"), kDir, true);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "charlie.splituser"));
  CHECK_FALSE(has(t, TokenCategory::string, "charlie.split"));
  CHECK(h.fragments() == 1);
}

TEST_CASE("a value cut at the end of a direction that never continues is still searched", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes("INVITE sip:bob@example.net SIP/2.0\r\nCall-ID: lastcallid12345"), kDir, true);
  h.feed(bytes("SIP/2.0 100 Trying\r\nCall-ID: othercallid999\r\n"), {1, 1, 1, 1}, true);  // another direction
  auto t = h.take();
  CHECK(has(t, TokenCategory::string, "lastcallid12345"));
  CHECK(h.fragments() == 0);
  // An SDP address cut at the end of the capture.
  detail::SipHarvest g;
  g.feed(bytes("SIP/2.0 200 OK\r\nContent-Length: 30\r\n\r\nv=0\r\nc=IN IP4 10.20.30.4"), kDir, true);
  t = g.take();
  CHECK(has_bin(t, TokenCategory::ipv4, {10, 20, 30, 4}));
}

TEST_CASE("a value that ends exactly at a segment end is a token once it is seen whole", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes("INVITE sip:bob@example.net SIP/2.0\r\nCall-ID: exactcallid777"), kDir, true);
  h.feed(bytes("\r\nContent-Length: 0\r\n\r\n"), kDir, true);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "exactcallid777"));
  CHECK(h.fragments() == 0);  // the value was whole: nothing was dropped
}

TEST_CASE("a payload that is not the continuation leaves the fragment searched", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes("SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP core.example.net;branch=z9hGlost"), kDir, true);
  h.feed(bytes(""), kDir, true);  // a pure acknowledgement: the fragment stays pending
  h.feed(bytes(">garbage that cannot continue a branch"), kDir, true);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "z9hGlost"));
}

TEST_CASE("a UDP datagram is whole: its last value is a token", "[scan][fragment]") {
  detail::SipHarvest h;
  h.feed(bytes(kHead + "z9hG"), kDir, false);
  CHECK(has(h.take(), TokenCategory::string, "z9hG"));
  CHECK(h.fragments() == 0);
}
