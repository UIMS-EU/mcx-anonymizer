// SPDX-License-Identifier: GPL-3.0-or-later
// FR-032a extension: a match of a 4-byte token (an IPv4 address or a 32-bit
// value) in a text encoding is a chance match when it lies entirely inside an occurrence of
// a pseudonym the anonymiser wrote. A text pseudonym "d-0a281477" is the hex form of
// 10.40.20.119 by chance; it carries nothing of that address.
#include "mcxanon/scan.hpp"

#include "capture/pcap.hpp"
#include "packet_builder.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fcntl.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {

Bytes ascii(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::filesystem::path pcap_of(const TempDir& tmp, const std::vector<Bytes>& packets) {
  PcapFileHeader h;
  h.linktype = kLinkRaw;
  Bytes file = build_pcap_file_header(h);
  for (const auto& packet : packets) {
    Bytes rec(16);
    store_pcap_packet_header(rec, PcapPacketHeader{1, 2, static_cast<std::uint32_t>(packet.size()),
                                                   static_cast<std::uint32_t>(packet.size())},
                             Endian::little);
    file = file + rec + packet;
  }
  const auto p = tmp.path() / "x.pcap";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  return p;
}

std::filesystem::path pcap_with_payload(const TempDir& tmp, const std::string& payload) {
  return pcap_of(tmp, {udp4(kIpA, kIpB, 5060, 5060, ascii(payload))});
}

// 10.40.20.119, hex 0a281477.
const V4 kOrig{10, 40, 20, 119};
scan::Token v4_token() { return {scan::TokenCategory::ipv4, raw(kOrig), "240.1.2.3"}; }

scan::ScanResult run_scan(const std::filesystem::path& p, std::vector<scan::Token> tokens,
                      std::vector<std::string> pseudonyms) {
  const scan::Index ix(std::move(tokens), std::move(pseudonyms));
  auto r = scan::scan_file(p, ix);
  REQUIRE(r.has_value());
  return *r;
}

}  // namespace

TEST_CASE("without the pseudonym list, hex text of an IPv4 token is a hit", "[scan][pseudonym]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, "From: <sip:u-83486084@d-0a281477.invalid>\r\n");
  const auto r = run_scan(p, {v4_token()}, {});
  REQUIRE(r.hits.size() == 1);
  CHECK(r.hits[0].encoding == "hex");
}

TEST_CASE("hex text of an IPv4 token inside a pseudonym occurrence is a chance match", "[scan][pseudonym]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, "From: <sip:u-83486084@d-0a281477.invalid>\r\nTo: <sip:d-0a281477>\r\n");
  const auto r = run_scan(p, {v4_token()}, {"u-83486084", "d-0a281477"});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_chance_matches == 2);
}

TEST_CASE("an in-place hex pseudonym (digest) also covers the match", "[scan][pseudonym]") {
  TempDir tmp;
  const std::string digest = "5be3c10a2814779e1f00aa7c3b2d4e60";
  const auto p = pcap_with_payload(tmp, "Authorization: Digest response=\"" + digest + "\"\r\n");
  const auto r = run_scan(p, {v4_token()}, {digest});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_chance_matches == 1);
}

TEST_CASE("the same hex text outside any pseudonym stays a hit", "[scan][pseudonym]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, "X: 0a281477\r\nFrom: <sip:d-0a281477>\r\n");
  const auto r = run_scan(p, {v4_token()}, {"d-0a281477"});
  REQUIRE(r.hits.size() == 1);
  CHECK(r.suppressed_chance_matches == 1);
}

TEST_CASE("a match that only partly overlaps a pseudonym stays a hit", "[scan][pseudonym]") {
  TempDir tmp;
  // The pseudonym "d-0a2814" covers 0a2814 but not the trailing 77.
  const auto p = pcap_with_payload(tmp, "From: <sip:d-0a281477>\r\n");
  const auto r = run_scan(p, {v4_token()}, {"d-0a2814"});
  CHECK(r.hits.size() == 1);
}

TEST_CASE("the raw 4-byte form is not covered by a pseudonym", "[scan][pseudonym]") {
  TempDir tmp;
  const std::string bin(reinterpret_cast<const char*>(kOrig.data()), kOrig.size());
  const auto p = pcap_with_payload(tmp, "n-" + bin + "zz");
  const auto r = run_scan(p, {v4_token()}, {"n-" + bin + "zz"});
  CHECK(r.hits.size() == 1);
}

TEST_CASE("the decimal text of a 32-bit token inside a pseudonym is a chance match", "[scan][pseudonym]") {
  TempDir tmp;
  // 0x12345678 = 305419896.
  const scan::Token spi{scan::TokenCategory::binary, {0x12, 0x34, 0x56, 0x78}, "spi:1"};
  const auto p = pcap_with_payload(tmp, "Security-Client: ipsec-3gpp;spi-c=305419896;port-c=5062\r\n");
  CHECK(run_scan(p, {spi}, {}).hits.size() == 1);
  const auto r = run_scan(p, {spi}, {"305419896"});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_chance_matches == 1);
}

TEST_CASE("longer tokens are never covered by a pseudonym", "[scan][pseudonym]") {
  TempDir tmp;
  const scan::Token s{scan::TokenCategory::string, ascii("canary7q"), "u-11111111"};
  const auto p = pcap_with_payload(tmp, "From: <sip:x-canary7q>\r\n");
  CHECK(run_scan(p, {s}, {"x-canary7q"}).hits.size() == 1);
}

TEST_CASE("a pseudonym split over two packets does not cover the match (fail-closed)", "[scan][pseudonym]") {
  TempDir tmp;
  const auto q = pcap_of(tmp, {udp4(kIpA, kIpB, 5060, 5060, ascii("From: <sip:d-0a281477")),
                               udp4(kIpA, kIpB, 5060, 5060, ascii("ab>\r\n"))});
  // The match is whole in the first packet; the pseudonym "d-0a281477ab" is not.
  CHECK(run_scan(q, {v4_token()}, {"d-0a281477ab"}).hits.size() == 1);
}

TEST_CASE("the unpublished output (scan_fd) gets the same rule", "[scan][pseudonym]") {
  TempDir tmp;
  const auto p = pcap_with_payload(tmp, "From: <sip:d-0a281477>\r\n");
  const scan::Index ix({v4_token()}, {"d-0a281477"});
  const int fd = ::open(p.c_str(), O_RDONLY);
  REQUIRE(fd >= 0);
  auto r = scan::scan_fd(fd, ix);
  ::close(fd);
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

// Feature 005: a 32-bit key identifier's text forms are coverable like the 4-byte
// binary tokens of 002 I19.
TEST_CASE("a key identifier's hex form inside a pseudonym is a chance match", "[scan][pseudonym][mikey]") {
  TempDir tmp;
  const scan::Token k{scan::TokenCategory::key, Bytes{0x1a, 0xbc, 0xde, 0xf0}, "key-id:1234abcd"};
  const auto p = pcap_with_payload(tmp, "From: <sip:u-1abcdef0>\r\n");
  const auto r = run_scan(p, {k}, {"u-1abcdef0"});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_chance_matches == 1);
  const auto q = pcap_with_payload(tmp, "X: 1abcdef0\r\n");
  CHECK(run_scan(q, {k}, {"u-1abcdef0"}).hits.size() == 1);
}

// Feature 007: the raw 4 octets of an IPv4 token inside a byte-string pseudonym
// (a TLS random or session id, a MIKEY RAND) are a chance match; outside it, and with no byte
// pseudonyms given, they are a hit.
TEST_CASE("raw IPv4 octets inside a byte-string pseudonym are a chance match", "[scan][pseudonym][d21]") {
  TempDir tmp;
  std::string nonce(32, '\x5a');
  nonce.replace(9, 4, std::string("\x0a\x28\x14\x77", 4));  // 10.40.20.119 by chance
  const std::string payload = std::string("\x16\x03\x03") + nonce + std::string(8, '\x11');
  const auto p = pcap_with_payload(tmp, payload);
  const scan::Index with(std::vector<scan::Token>{v4_token()}, {}, {nonce});
  auto r = scan::scan_file(p, with);
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
  const scan::Index without(std::vector<scan::Token>{v4_token()}, {}, {});
  auto r2 = scan::scan_file(p, without);
  REQUIRE(r2.has_value());
  CHECK(r2->hits.size() == 1);
  // The same octets next to, not inside, the pseudonym: a hit.
  const std::string plain(16, '\x5a');
  const auto q = pcap_with_payload(tmp, plain + std::string("\x0a\x28\x14\x77", 4));
  const scan::Index part(std::vector<scan::Token>{v4_token()}, {}, {plain});
  auto r3 = scan::scan_file(q, part);
  REQUIRE(r3.has_value());
  CHECK(r3->hits.size() == 1);
}
