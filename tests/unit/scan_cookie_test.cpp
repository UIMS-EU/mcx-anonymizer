// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 008 (FR-002): every rewritten branch keeps the RFC 3261 §8.1.1.7 magic cookie
// "z9hG4bK". A match whose bytes lie entirely inside that cookie, right after "branch=", carries
// nothing of any input value: it is a chance match, counted apart. The same bytes anywhere else,
// a match running past the cookie, and deny-list entries stay hits.
#include "mcxanon/scan.hpp"

#include "capture/pcap.hpp"
#include "packet_builder.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {

Bytes ascii(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::filesystem::path pcap_with_payload(const TempDir& tmp, const std::string& payload) {
  PcapFileHeader h;
  h.linktype = kLinkRaw;
  Bytes file = build_pcap_file_header(h);
  const Bytes packet = udp4(kIpA, kIpB, 5060, 5060, ascii(payload));
  Bytes rec(16);
  store_pcap_packet_header(rec, PcapPacketHeader{1, 2, static_cast<std::uint32_t>(packet.size()),
                                                 static_cast<std::uint32_t>(packet.size())},
                           Endian::little);
  file = file + rec + packet;
  const auto p = tmp.path() / "x.pcap";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  return p;
}

scan::Token str(const std::string& v, scan::TokenCategory c = scan::TokenCategory::string) {
  return {c, Bytes(v.begin(), v.end()), c == scan::TokenCategory::deny ? "deny#1" : "input:branch#1"};
}

scan::ScanResult run_scan(const std::filesystem::path& p, std::vector<scan::Token> tokens) {
  const scan::Index ix(std::move(tokens));
  auto r = scan::scan_file(p, ix);
  REQUIRE(r.has_value());
  return *r;
}

const std::string kVia =
    "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP d-4b064b0f.invalid:5060;branch=z9hG4bKb-51cf659a9835\r\n"
    "v: SIP/2.0/UDP d-4659f45d.invalid;BRANCH=z9hG4bKb-e96c5eb021d2\r\n\r\n";

}  // namespace

TEST_CASE("a match inside the kept branch cookie is a counted chance match", "[scan][cookie]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, kVia);
  for (const char* v : {"z9hG", "9hG4b", "hG4bK", "z9hG4bK"}) {
    INFO(v);
    const auto r = run_scan(p, {str(v)});
    CHECK(r.hits.empty());
    CHECK(r.suppressed_cookie_matches == 2);  // both Vias, the parameter name in any case
    CHECK(r.suppressed_chance_matches == 0);
  }
}

TEST_CASE("a 4-byte address whose bytes spell part of the cookie is suppressed there", "[scan][cookie]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, kVia);
  // 122.57.104.71 is "z9hG" in binary.
  const auto r = run_scan(p, {{scan::TokenCategory::ipv4, Bytes{122, 57, 104, 71}, "240.0.0.9"}});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_cookie_matches == 2);
}

TEST_CASE("the cookie bytes outside a branch parameter are a hit", "[scan][cookie]") {
  TempDir tmp;
  for (const auto& payload : {std::string("MESSAGE sip:x SIP/2.0\r\nSubject: z9hG4bK\r\n\r\n"),
                                    std::string("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;xbranch=z9hG4bK1\r\n\r\n"),
                                    std::string("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;branch=Az9hG4bK1\r\n\r\n")}) {
    INFO(payload);
    const auto p = pcap_with_payload(tmp, payload);
    const auto r = run_scan(p, {str("z9hG")});
    CHECK(r.hits.size() == 1);
    CHECK(r.suppressed_cookie_matches == 0);
  }
}

TEST_CASE("a match that runs past the cookie is a hit", "[scan][cookie]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, kVia);
  for (const char* v : {"z9hG4bKb-5", "4bKb-5"}) {
    INFO(v);
    const auto r = run_scan(p, {str(v)});
    CHECK(r.hits.size() == 1);
    CHECK(r.suppressed_cookie_matches == 0);
  }
}

TEST_CASE("a deny-list entry inside the cookie is a hit", "[scan][cookie]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, kVia);
  const auto r = run_scan(p, {str("z9hG", scan::TokenCategory::deny)});
  CHECK(r.hits.size() == 2);
  CHECK(r.suppressed_cookie_matches == 0);
}
