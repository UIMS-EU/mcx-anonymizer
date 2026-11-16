// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own RTCP / MCX APP harvester (FR-031). It shares no code with the
// anonymiser: this test includes nothing from src/media/ or src/sip/.
#include "scan/walker/media_harvest.hpp"
#include "scan/walker/sip_harvest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::scan;

namespace {
using B = std::vector<std::uint8_t>;
void put32(B& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}
B packet(std::uint8_t pt, std::uint8_t count, const B& body) {
  B p{static_cast<std::uint8_t>(0x80 | count), pt, 0, static_cast<std::uint8_t>(body.size() / 4)};
  p.insert(p.end(), body.begin(), body.end());
  return p;
}
bool has_text(const std::vector<Token>& t, const std::string& v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) { return std::string(x.value.begin(), x.value.end()) == v; });
}
bool has_bin(const std::vector<Token>& t, std::uint32_t v) {
  B b;
  put32(b, v);
  return std::any_of(t.begin(), t.end(), [&](const Token& x) { return x.category == TokenCategory::binary && x.value == b; });
}
std::vector<Token> harvest(const B& payload) {
  detail::SipHarvest sip;
  detail::MediaHarvest media(sip);
  media.feed_udp(payload);
  return sip.take();
}
}  // namespace

TEST_CASE("SR, SDES and BYE give SSRC, SDES item and reason tokens", "[scan][harvest][media]") {
  B sr;
  put32(sr, 0xCAFE0001);
  for (int i = 0; i < 5; ++i) put32(sr, 0x01000000u + static_cast<std::uint32_t>(i));
  put32(sr, 0xCAFE0002);  // report block SSRC
  for (int i = 0; i < 5; ++i) put32(sr, 0);
  B sdes;
  put32(sdes, 0xCAFE0001);
  for (const auto& [t, v] : {std::pair{1, std::string("alice@ue.example.net")}, std::pair{2, std::string("Alice Nowak")}}) {
    sdes.push_back(static_cast<std::uint8_t>(t));
    sdes.push_back(static_cast<std::uint8_t>(v.size()));
    sdes.insert(sdes.end(), v.begin(), v.end());
  }
  sdes.push_back(0);
  while (sdes.size() % 4) sdes.push_back(0);
  B bye;
  put32(bye, 0xCAFE0003);
  const std::string reason = "network congestion";
  bye.push_back(static_cast<std::uint8_t>(reason.size()));
  bye.insert(bye.end(), reason.begin(), reason.end());
  while (bye.size() % 4) bye.push_back(0);
  B d = packet(200, 1, sr);
  for (const auto& p : {packet(202, 1, sdes), packet(203, 1, bye)}) d.insert(d.end(), p.begin(), p.end());
  const auto t = harvest(d);
  CHECK(has_bin(t, 0xCAFE0001));
  CHECK(has_bin(t, 0xCAFE0002));
  CHECK(has_bin(t, 0xCAFE0003));
  CHECK(has_text(t, "alice@ue.example.net"));
  CHECK(has_text(t, "Alice Nowak"));
  CHECK(has_text(t, reason));
}

TEST_CASE("MCX APP header SSRCs and URI field values are harvested", "[scan][harvest][media]") {
  B body;
  put32(body, 0xCAFE0010);
  for (char c : std::string("MCPT")) body.push_back(static_cast<std::uint8_t>(c));
  const std::string uri = "sip:dispatcher.north@mcx.example.net";
  body.push_back(6);
  body.push_back(static_cast<std::uint8_t>(uri.size()));
  body.insert(body.end(), uri.begin(), uri.end());
  while ((body.size()) % 4) body.push_back(0);
  const auto t = harvest(packet(204, 0, body));
  CHECK(has_bin(t, 0xCAFE0010));
  CHECK(has_text(t, "dispatcher.north"));
}

TEST_CASE("a payload that is not RTCP-shaped gives no media token", "[scan][harvest][media]") {
  B junk{0x00, 0xC8, 0x00, 0x01, 0xCA, 0xFE, 0x00, 0x20};  // version 0
  CHECK(harvest(junk).empty());
  B partial = packet(200, 0, B(24, 1));
  partial.pop_back();  // does not tile
  CHECK(harvest(partial).empty());
}

TEST_CASE("a Message Name value is not taken for an SSRC", "[scan][harvest][media]") {
  B body;
  put32(body, 0xCAFE0020);
  for (char c : std::string("MCV2")) body.push_back(static_cast<std::uint8_t>(c));
  body.insert(body.end(), {16, 6, 'M', 'C', 'V', '1', 0, 0});
  const auto t = harvest(packet(204, 4, body));
  CHECK_FALSE(has_bin(t, 0x4D435631));  // "MCV1"
  CHECK(has_bin(t, 0xCAFE0020));
}

TEST_CASE("MSRP transaction ids, Message-IDs and paths are harvested from TCP payloads", "[scan][harvest][media]") {
  const std::string m = "MSRP tx-9f8e7d6c SEND\r\nTo-Path: msrp://10.0.0.2:7002/sess-b1;tcp\r\n"
                        "From-Path: msrp://alice@10.0.0.1:7001/sess-a1;tcp\r\nMessage-ID: mid-31337\r\n-------tx-9f8e7d6c$\r\n";
  detail::SipHarvest sip;
  detail::MediaHarvest media(sip);
  media.feed_tcp(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(m.data()), m.size()));
  const auto t = sip.take();
  CHECK(has_text(t, "tx-9f8e7d6c"));
  CHECK(has_text(t, "mid-31337"));
  CHECK(has_text(t, "sess-b1"));
  CHECK(has_text(t, "sess-a1"));
}
