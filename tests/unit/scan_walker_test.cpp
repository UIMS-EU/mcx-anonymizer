// SPDX-License-Identifier: GPL-3.0-or-later
// FR-032a: chance matches of short binary tokens inside recognised header
// fields are suppressed unless they sit on an IPv4 address position;
// everything else is a hit.
#include "mcxanon/scan.hpp"

#include "capture/pcap.hpp"
#include "capture/pcapng.hpp"
#include "packet_builder.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
std::filesystem::path pcap_with(const TempDir& tmp, const Bytes& packet, std::uint16_t lt = kLinkRaw) {
  PcapFileHeader h;
  h.linktype = lt;
  Bytes file = build_pcap_file_header(h);
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
scan::Token v4(const V4& a) { return {scan::TokenCategory::ipv4, raw(a), "240.0.0.9"}; }
}  // namespace

TEST_CASE("a 4-byte token inside numeric IPv4 fields is a suppressed chance match", "[scan][walker]") {
  TempDir tmp;
  // The token bytes appear as IPv4 identification + flags/fragment offset.
  const V4 tok{0x12, 0x34, 0x40, 0x00};
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 1, 2, {}));
  auto r = scan::scan_file(p, std::vector{v4(tok)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("a 4-byte token in an address field is a hit with its frame number", "[scan][walker]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 1, 2, {}));
  auto r = scan::scan_file(p, std::vector{v4(kIpB)});
  REQUIRE(r.has_value());
  REQUIRE(r->hits.size() == 1);
  CHECK(r->hits[0].frame_number == 1);
  CHECK(r->hits[0].file_offset == 24 + 16 + 16);
  CHECK(r->hits[0].encoding == "binary");
  CHECK(r->hits[0].label == "240.0.0.9");
}

TEST_CASE("a 4-byte token in payload or unclassified bytes is a hit", "[scan][walker]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 1, 2, Bytes{0, 0x12, 0x34, 0x40, 0x00, 0}));
  auto r = scan::scan_file(p, std::vector{v4({0x12, 0x34, 0x40, 0x00})});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);  // the payload copy; the header copy is suppressed
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("tokens of six bytes or more are never suppressed", "[scan][walker]") {
  TempDir tmp;
  // TCP sequence + acknowledgement numbers carry the 6 MAC bytes.
  const Bytes pkt = tcp4(kIpA, kIpB, 1, 2, 0x00112233, 0x44550000, 0x10, {}, {});
  const auto p = pcap_with(tmp, pkt);
  auto r = scan::scan_file(p, std::vector{scan::Token{scan::TokenCategory::mac, raw(kMacA), "02:00:00:00:00:01"}});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
  CHECK(r->suppressed_chance_matches == 0);
}

TEST_CASE("pcap record headers and timestamps are numeric", "[scan][walker]") {
  TempDir tmp;
  const auto p = pcap_with(tmp, udp4(kIpA, kIpB, 1, 2, {}));
  // The token equals the record's ts_sec field (1, little-endian).
  auto r = scan::scan_file(p, std::vector{v4({0x01, 0x00, 0x00, 0x00})});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches >= 1);
}

TEST_CASE("an unparseable file is scanned raw, without suppression", "[scan][walker]") {
  TempDir tmp;
  const auto p = tmp.path() / "raw.bin";
  std::ofstream(p, std::ios::binary) << "garbage 10.1.2.3 more";
  auto r = scan::scan_file(p, std::vector{v4(kIpA)});
  REQUIRE(r.has_value());
  REQUIRE(r->hits.size() == 1);
  CHECK(r->hits[0].encoding == "text");
  CHECK(r->hits[0].frame_number == 0);
}

namespace {
scan::ScanResult scan_packet(const Bytes& pkt, const V4& token, std::uint16_t lt = kLinkRaw) {
  TempDir tmp;
  auto r = scan::scan_file(pcap_with(tmp, pkt, lt), std::vector{v4(token)});
  REQUIRE(r.has_value());
  return *r;
}
constexpr std::uint64_t kPkt = 24 + 16;  // packet data offset of the first record
}  // namespace

TEST_CASE("a 4-byte match inside a MAC address or straddling MAC and EtherType is a chance match",
          "[scan][walker]") {
  const Mac6 src{0x02, 0xAA, 0x0B, 0x0C, 0x0D, 0x0E};
  const Bytes pkt = eth(kMacB, src, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));
  auto inside = scan_packet(pkt, {0x0B, 0x0C, 0x0D, 0x0E}, 1);
  CHECK(inside.hits.empty());
  CHECK(inside.suppressed_chance_matches == 1);
  auto straddle = scan_packet(pkt, {0x0D, 0x0E, 0x08, 0x00}, 1);
  CHECK(straddle.hits.empty());
  CHECK(straddle.suppressed_chance_matches == 1);
}

TEST_CASE("a 4-byte match straddling two IPv4 header fields is a chance match", "[scan][walker]") {
  // Last two bytes of the source address and first two of the destination.
  const Bytes pkt = udp4(kIpA, kIpB, 1, 2, {});
  auto r = scan_packet(pkt, {2, 3, 192, 168});
  CHECK(r.hits.empty());
  CHECK(r.suppressed_chance_matches == 1);
}

TEST_CASE("a 4-byte match exactly on an IPv4 address field is always a hit", "[scan][walker]") {
  auto src = scan_packet(udp4(kIpA, kIpB, 1, 2, {}), kIpA);
  REQUIRE(src.hits.size() == 1);
  CHECK(src.hits[0].file_offset == kPkt + 12);
  // ARP sender and target protocol addresses.
  const Bytes arp = b16(1) + b16(0x0800) + Bytes{6, 4} + b16(1) + raw(kMacA) + raw(kIpA) + raw(kMacB) + raw(kIpB);
  auto a = scan_packet(eth(kMacB, kMacA, 0x0806, arp), kIpB, 1);
  REQUIRE(a.hits.size() == 1);
  CHECK(a.hits[0].file_offset == kPkt + 14 + 24);
}

TEST_CASE("IPv4 positions inside IPv6 addresses depend on the embedding prefix", "[scan][walker]") {
  V6 mapped{};
  mapped[10] = 0xFF;
  mapped[11] = 0xFF;
  V6 doc{0x20, 0x01, 0x0d, 0xb8};
  for (std::size_t i = 0; i < 4; ++i) {
    mapped[12 + i] = kIpA[i];
    doc[12 + i] = kIpA[i];
  }
  const auto binary_hits = [](const scan::ScanResult& r) {
    std::size_t n = 0;
    for (const auto& h : r.hits) n += h.encoding == "binary" ? 1u : 0u;
    return n;
  };
  // ::ffff:a.b.c.d carries an IPv4 address: the bare binary form counts too.
  auto m = scan_packet(ipv6(mapped, kIp6B, 59, {}), kIpA);
  CHECK(binary_hits(m) == 1);
  auto d = scan_packet(ipv6(doc, kIp6B, 59, {}), kIpA);
  CHECK(d.hits.empty());  // a random tail of an ordinary IPv6 address does not
  CHECK(d.suppressed_chance_matches == 1);
  V6 six{0x20, 0x02, kIpA[0], kIpA[1], kIpA[2], kIpA[3]};
  CHECK(binary_hits(scan_packet(ipv6(six, kIp6B, 59, {}), kIpA)) == 1);  // 6to4
}

TEST_CASE("addresses of tunnelled and quoted packets are IPv4 positions", "[scan][walker]") {
  const V4 inner_src{10, 9, 9, 9};
  const Bytes inner = udp4(inner_src, kIpB, 5, 6, {});
  // GTP-U G-PDU on port 2152 (3GPP TS 29.281 clause 5.1).
  const Bytes gtp = Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(0x01020304) + inner;
  auto g = scan_packet(udp4(kIpA, kIpB, 2152, 2152, gtp), inner_src);
  REQUIRE(g.hits.size() == 1);
  CHECK(g.hits[0].file_offset == kPkt + 20 + 8 + 8 + 12);
  // The TEID is a recognised numeric field.
  auto teid = scan_packet(udp4(kIpA, kIpB, 2152, 2152, gtp), {0x01, 0x02, 0x03, 0x04});
  CHECK(teid.hits.empty());
  // GRE (RFC 2784) carrying IPv4, and IP-in-IP.
  auto gre = scan_packet(ipv4(kIpA, kIpB, 47, b16(0) + b16(0x0800) + inner), inner_src);
  CHECK(gre.hits.size() == 1);
  auto ipip = scan_packet(ipv4(kIpA, kIpB, 4, inner), inner_src);
  CHECK(ipip.hits.size() == 1);
  // ICMP destination unreachable quoting the original packet.
  const Bytes icmp = Bytes{3, 1, 0, 0} + b32(0) + inner;
  auto q = scan_packet(ipv4(kIpA, kIpB, 1, icmp), inner_src);
  REQUIRE(q.hits.size() == 1);
  CHECK(q.hits[0].file_offset == kPkt + 20 + 8 + 12);
}

TEST_CASE("the harvest finds addresses inside tunnels", "[scan][walker]") {
  TempDir tmp;
  const V4 inner_src{10, 9, 9, 9};
  const Bytes inner = udp4(inner_src, kIpB, 5, 6, {});
  const Bytes gtp = Bytes{0x30, 0xFF} + b16(static_cast<std::uint16_t>(inner.size())) + b32(7) + inner;
  auto toks = scan::harvest_input(pcap_with(tmp, udp4(kIpA, kIpB, 2152, 2152, gtp)));
  REQUIRE(toks.has_value());
  bool found = false;
  for (const auto& t : *toks) found = found || (t.category == scan::TokenCategory::ipv4 && t.value == raw(inner_src));
  CHECK(found);
}

TEST_CASE("a 4-byte match straddling pcapng padding and the block trailer is a chance match", "[scan][walker]") {
  TempDir tmp;
  // Ethernet + IPv4 + UDP without payload: 42 bytes, padded to 44 in the EPB.
  const Bytes pkt = eth(kMacB, kMacA, 0x0800, udp4(kIpA, kIpB, 1, 2, {}));
  REQUIRE(pkt.size() % 4 == 2);
  Bytes idb_body(8, 0);
  store16(idb_body, 0, kLinkEthernet, Endian::little);
  Bytes epb_body(20, 0);
  store32(epb_body, 12, static_cast<std::uint32_t>(pkt.size()), Endian::little);
  store32(epb_body, 16, static_cast<std::uint32_t>(pkt.size()), Endian::little);
  epb_body = epb_body + pkt;
  const Bytes file = build_shb(Endian::little, {}) + build_block(1, idb_body, {}, Endian::little) +
                     build_block(6, epb_body, {}, Endian::little);
  const auto p = tmp.path() / "x.pcapng";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  // Two padding zeros, then the low bytes of the EPB total length (28 + 44 + 4 = 76).
  auto r = scan::scan_file(p, std::vector{v4({0x00, 0x00, 76, 0x00})});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches >= 1);
}

// FR-032a extension: zero bytes right after a recognised header field (the
// payload the anonymiser zeroed) count with the header run, so a short binary match made of a
// header field and those zeros is a chance match; a non-zero payload byte is not covered.
TEST_CASE("a 4-byte match over the UDP checksum and the zeroed payload is a chance match", "[scan][walker]") {
  TempDir tmp;
  const Bytes pkt = udp4(kIpA, kIpB, 30228, 9000, Bytes(16, 0));
  // Raw IPv4: 20-byte IP header, UDP checksum at 26..27, payload from 28.
  const V4 tok{pkt[26], pkt[27], 0x00, 0x00};
  auto r = scan::scan_file(pcap_with(tmp, pkt), std::vector{v4(tok)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

// FR-032a extension: a short binary match that starts in a
// recognised header field (not on a value slot) and runs into the payload is a chance match: a
// leaked value lies wholly in the payload. One that starts in the zeroed payload stays a hit.
TEST_CASE("a 4-byte match from the UDP checksum into a non-zero payload is a chance match", "[scan][walker]") {
  TempDir tmp;
  const Bytes text{'I', 'N', 'F', 'O', ' ', 's'};
  const Bytes pkt = udp4(kIpA, kIpB, 5060, 5060, text);
  const V4 tok{pkt[26], pkt[27], 'I', 'N'};
  auto r = scan::scan_file(pcap_with(tmp, pkt), std::vector{v4(tok)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("a 4-byte match from the zeroed payload into non-zero bytes stays a hit", "[scan][walker]") {
  TempDir tmp;
  Bytes payload(16, 0);
  payload[2] = 0x0a;
  payload[3] = 0x05;
  const Bytes pkt = udp4(kIpA, kIpB, 30228, 9000, payload);
  auto r = scan::scan_file(pcap_with(tmp, pkt), std::vector{v4({0x00, 0x00, 0x0a, 0x05})});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
}

TEST_CASE("a 4-byte match from inside an address field (off its slot) into the payload is a chance match",
          "[scan][walker]") {
  TempDir tmp;
  // Raw IPv4 without UDP: protocol 253 (experimental), the destination address ends the header.
  Bytes pkt = udp4(kIpA, kIpB, 1, 2, {});
  pkt.resize(20);
  pkt[9] = 253;
  pkt.push_back('x');
  pkt.push_back('y');
  const V4 tok{pkt[18], pkt[19], 'x', 'y'};
  auto r = scan::scan_file(pcap_with(tmp, pkt), std::vector{v4(tok)});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("zero bytes inside the payload, away from the header, are not covered", "[scan][walker]") {
  TempDir tmp;
  Bytes payload(32, 'x');
  for (std::size_t i = 10; i < 20; ++i) payload[i] = 0;
  payload[20] = 0x05;
  const Bytes pkt = udp4(kIpA, kIpB, 30228, 9000, payload);
  auto r = scan::scan_file(pcap_with(tmp, pkt), std::vector{v4({0x00, 0x00, 0x00, 0x05})});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
}

// FR-032a extension: no packet field crosses a record
// boundary, so a short binary match that starts in one record and ends in the next one (the
// last bytes of a packet and the next record header) is a chance match.
namespace {
std::filesystem::path pcap_two(const TempDir& tmp, const Bytes& first, std::uint32_t second_ts_sec) {
  PcapFileHeader h;
  h.linktype = kLinkRaw;
  Bytes file = build_pcap_file_header(h);
  const Bytes second = udp4(kIpA, kIpB, 1, 2, {});
  for (const auto& [pkt, ts] : {std::pair{first, 1u}, std::pair{second, second_ts_sec}}) {
    Bytes rec(16);
    store_pcap_packet_header(rec, PcapPacketHeader{ts, 2, static_cast<std::uint32_t>(pkt.size()),
                                                   static_cast<std::uint32_t>(pkt.size())},
                             Endian::little);
    file = file + rec + pkt;
  }
  const auto p = tmp.path() / "two.pcap";
  std::ofstream(p, std::ios::binary).write(reinterpret_cast<const char*>(file.data()),
                                           static_cast<std::streamsize>(file.size()));
  return p;
}
}  // namespace

TEST_CASE("a 4-byte match over the end of a packet and the next record header is a chance match",
          "[scan][walker]") {
  TempDir tmp;
  // A SIP-like payload ending in LF (0x0a), then a record whose ts_sec is 0x6acf3328: the bytes
  // 0a 28 33 cf read as the IPv4 address 10.40.51.207.
  const Bytes text{'O', 'K', '\r', '\n'};
  auto r = scan::scan_file(pcap_two(tmp, udp4(kIpA, kIpB, 5060, 5060, text), 0x6acf3328u),
                           std::vector{v4({0x0a, 0x28, 0x33, 0xcf})});
  REQUIRE(r.has_value());
  CHECK(r->hits.empty());
  CHECK(r->suppressed_chance_matches == 1);
}

TEST_CASE("the same 4 bytes inside one packet's payload stay a hit", "[scan][walker]") {
  TempDir tmp;
  const Bytes text{'O', 'K', '\r', '\n', 0x28, 0x33, 0xcf, '!'};
  auto r = scan::scan_file(pcap_two(tmp, udp4(kIpA, kIpB, 5060, 5060, text), 7u),
                           std::vector{v4({0x0a, 0x28, 0x33, 0xcf})});
  REQUIRE(r.has_value());
  CHECK(r->hits.size() == 1);
}
