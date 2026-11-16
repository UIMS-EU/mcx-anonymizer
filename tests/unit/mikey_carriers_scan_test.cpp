// SPDX-License-Identifier: GPL-3.0-or-later
//
//The scanner decodes the MIKEY carriers of the output itself and searches the
// decoded bytes, so a key identifier inside base64 MIKEY is found at every alignment (FR-022).
#include "mcxanon/scan.hpp"

#include "bytes/base64.hpp"
#include "capture/pcap.hpp"
#include "packet_builder.hpp"
#include "scan/walker/mikey_carriers.hpp"
#include "temp_dir.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <string>

using namespace mcxanon;
using namespace mcxanon::test;
using namespace mikey_test;

namespace {

std::filesystem::path pcap_with_payload(const TempDir& tmp, const std::string& payload) {
  PcapFileHeader h;
  h.linktype = kLinkRaw;
  Bytes file = build_pcap_file_header(h);
  const Bytes packet = udp4(kIpA, kIpB, 5060, 5060, Bytes(payload.begin(), payload.end()));
  Bytes rec(16);
  store_pcap_packet_header(rec, PcapPacketHeader{1, 2, static_cast<std::uint32_t>(packet.size()),
                                                 static_cast<std::uint32_t>(packet.size())},
                           Endian::little);
  file = file + rec + packet;
  const auto p = tmp.path() / "x.pcap";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
  return p;
}

}  // namespace

TEST_CASE("mikey carriers: an a=key-mgmt value is located and decoded", "[mikey][scan]") {
  const Bytes m = private_call();
  const std::string sdp = "v=0\r\na=key-mgmt:mikey " + base64::encode(m) + "\r\nm=audio 1 RTP/SAVP 0\r\n";
  const auto found = scan::detail::find_mikey_carriers(std::span(reinterpret_cast<const std::uint8_t*>(sdp.data()), sdp.size()));
  REQUIRE(found.size() == 1);
  CHECK(found[0].decoded == m);
  CHECK(found[0].carrier == "sdp");
  CHECK(sdp.substr(found[0].offset, 4) == base64::encode(m).substr(0, 4));
}

TEST_CASE("mikey carriers: a key identifier inside base64 MIKEY is a hit at every alignment", "[mikey][scan]") {
  for (std::size_t shift = 0; shift < 3; ++shift) {
    TempDir tmp;
    // A RAND of 16 + shift octets moves the CSB-ID-like value through the three base64 alignments.
    Bytes r(16 + shift, 0x01);
    for (int x : {0x2c, 0x5e, 0x91, 0xd3}) r.push_back(static_cast<std::uint8_t>(x));
    const Bytes m = message(Header{}, {t(1), rand(r), sakke(Bytes(4, 1)), sign(Bytes(129, 1))});
    const auto p = pcap_with_payload(tmp, "v=0\r\na=key-mgmt:mikey " + base64::encode(m) + "\r\n");
    const scan::Token k{scan::TokenCategory::key, Bytes{0x2c, 0x5e, 0x91, 0xd3}, "key-id:00000000"};
    auto res = scan::scan_file(p, scan::Index({k}));
    REQUIRE(res.has_value());
    CHECK(res->hits.size() >= 1);
  }
}

namespace {

std::vector<scan::detail::MikeyCarrierSpan> carriers_of(const std::string& text) {
  return scan::detail::find_mikey_carriers(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

std::string hex(const Bytes& b, bool upper) {
  const char* d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string s;
  for (auto x : b) {
    s += d[x >> 4];
    s += d[x & 15];
  }
  return s;
}

}  // namespace

TEST_CASE("mikey carriers: application/mikey bodies and parts, binary and base64", "[mikey][scan]") {
  const Bytes m = private_call();
  const std::string bin(m.begin(), m.end());
  std::string b64 = base64::encode(m);
  b64.insert(76, "\r\n");
  const std::string msg = "MESSAGE sip:x SIP/2.0\r\nContent-Type: multipart/mixed;boundary=b\r\n\r\n--b\r\n"
                          "Content-Type: application/mikey\r\n\r\n" + bin + "\r\n--b\r\n"
                          "Content-Type: application/mikey\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64 +
                          "\r\n--b--\r\n";
  const auto found = carriers_of(msg);
  REQUIRE(found.size() == 2);
  for (const auto& c : found) {
    CHECK(c.carrier == "body");
    CHECK(c.decoded == m);
  }
  CHECK(msg.substr(found[0].offset, 2) == bin.substr(0, 2));
  CHECK(msg.substr(found[1].offset, 4) == b64.substr(0, 4));
  // A body of another type is not a carrier.
  CHECK(carriers_of("SIP/2.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + bin).empty());
}

TEST_CASE("mikey carriers: <GKTP> hexBinary in either case and with whitespace", "[mikey][scan]") {
  const Bytes m = private_call();
  const std::string xml = "<x:GKTPs><x:GMK-GKTPs><x:GKTP id=\"1\">\n " + hex(m, false) + "\n</x:GKTP>"
                          "<GKTP id=\"2\">" + hex(m, true) + "</GKTP></x:GMK-GKTPs></x:GKTPs>";
  const auto found = carriers_of(xml);
  REQUIRE(found.size() == 2);
  for (const auto& c : found) {
    CHECK(c.carrier == "gktp");
    CHECK(c.decoded == m);
  }
  CHECK(carriers_of("<GKTP id=\"3\">not hex</GKTP>").empty());
}

TEST_CASE("mikey carriers: MCPC field 192 in an RTCP APP packet", "[mikey][scan]") {
  for (const bool b64 : {false, true}) {
    const Bytes m = private_call();
    const std::string v = b64 ? base64::encode(m) : std::string(m.begin(), m.end());
    Bytes app{0x90, 204, 0, 0, 1, 2, 3, 4, 'M', 'C', 'P', 'C', 192};
    put16(app, static_cast<unsigned>(v.size()));
    app.insert(app.end(), v.begin(), v.end());
    while (app.size() % 4 != 0) app.push_back(0);
    app[2] = static_cast<std::uint8_t>((app.size() / 4 - 1) >> 8);
    app[3] = static_cast<std::uint8_t>(app.size() / 4 - 1);
    const auto found = scan::detail::find_mikey_carriers(app);
    REQUIRE(found.size() == 1);
    CHECK(found[0].carrier == "mcpc");
    CHECK(found[0].decoded == m);
    CHECK(found[0].offset == 15);
  }
}

TEST_CASE("scan: a byte string of one repeated octet is not searched (feature 005)", "[mikey][scan]") {
  // A zero RAND in the project mapping would match every zeroed region of the output.
  const std::vector<scan::Token> tokens{{scan::TokenCategory::bytes, Bytes(16, 0), "nonce:0"},
                                        {scan::TokenCategory::key, Bytes(4, 0x11), "key-id:0"},
                                        {scan::TokenCategory::bytes, Bytes{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "nonce:1"}};
  const Bytes data(4096, 0);
  const auto r = scan::scan_bytes(data, tokens);
  CHECK(r.hits.empty());
  CHECK(r.unscannable_by_category.at("bytes/degenerate") == 1);
  CHECK(r.unscannable_by_category.at("key/degenerate") == 1);
}
