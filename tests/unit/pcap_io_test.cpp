// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "capture/detect.hpp"
#include "capture/pcap.hpp"
#include "capture/reader.hpp"
#include "capture/writer.hpp"
#include "capture_test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

using namespace mcxanon;
using test::Buf;

namespace {

// pcap-09 §4: magic, version 2.4, reserved, snaplen, linktype; §5: 16-byte record header.
Bytes pcap_file(Endian e, std::uint32_t magic, std::uint32_t linktype_field,
                std::initializer_list<Bytes> packets) {
  Buf b(e);
  b.u32(magic).u16(2).u16(4).u32(0).u32(0).u32(262144).u32(linktype_field);
  std::uint32_t sec = 1700000000;
  for (const auto& p : packets) {
    b.u32(sec++).u32(123456).u32(static_cast<std::uint32_t>(p.size()))
        .u32(static_cast<std::uint32_t>(p.size())).raw(p);
  }
  return b.bytes();
}

std::vector<Record> read_all(CaptureReader& r) {
  std::vector<Record> out;
  for (;;) {
    auto rec = r.next();
    REQUIRE(rec.has_value());
    if (!rec->has_value()) break;
    out.push_back(std::move(**rec));
  }
  return out;
}

}  // namespace

TEST_CASE("pcap: all four magic numbers are recognised", "[capture][pcap]") {
  struct Case { Endian e; std::uint32_t magic; bool ns; };
  auto c = GENERATE(Case{Endian::big, 0xA1B2C3D4u, false}, Case{Endian::big, 0xA1B23C4Du, true},
                    Case{Endian::little, 0xA1B2C3D4u, false},
                    Case{Endian::little, 0xA1B23C4Du, true});
  const Bytes file = pcap_file(c.e, c.magic, 1, {Bytes{1, 2, 3}});
  auto hdr = parse_pcap_file_header(file);
  REQUIRE(hdr.has_value());
  CHECK(hdr->endian == c.e);
  CHECK(hdr->nanosecond == c.ns);
  CHECK(hdr->snaplen == 262144);
  CHECK(hdr->linktype == 1);
  CHECK(*detect_format(file) == CaptureFormat::pcap);
}

TEST_CASE("pcap: byte-identical round trip", "[capture][pcap]") {
  const Bytes file = pcap_file(Endian::little, 0xA1B2C3D4u, 1,
                               {Bytes{0xAA, 0xBB}, Bytes(60, 0x11), Bytes{}});
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  CHECK(reader->format() == CaptureFormat::pcap);
  auto records = read_all(*reader);
  REQUIRE(records.size() == 4);
  CHECK(records[0].kind == RecordKind::pcap_file_header);
  CHECK(records[1].kind == RecordKind::pcap_packet);
  CHECK(records[1].frame_number == 1);
  CHECK(records[3].frame_number == 3);
  CHECK(reader->truncated_tail_bytes() == 0);

  auto writer = CaptureWriter::to_memory();
  for (const auto& r : records) REQUIRE(writer.write(r).has_value());
  REQUIRE(writer.finish().has_value());
  CHECK(writer.memory() == file);
}

TEST_CASE("pcap: packet header fields are decoded", "[capture][pcap]") {
  const Bytes file = pcap_file(Endian::big, 0xA1B23C4Du, 101, {Bytes{9, 8, 7, 6}});
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  auto records = read_all(*reader);
  REQUIRE(records.size() == 2);
  auto ph = parse_pcap_packet_header(records[1].bytes, Endian::big);
  REQUIRE(ph.has_value());
  CHECK(ph->ts_sec == 1700000000u);
  CHECK(ph->ts_frac == 123456u);
  CHECK(ph->caplen == 4);
  CHECK(ph->origlen == 4);
  CHECK(pcap_packet_data(records[1]).size() == 4);
}

TEST_CASE("pcap: truncated final record is reported, not copied", "[capture][pcap]") {
  Bytes file = pcap_file(Endian::little, 0xA1B2C3D4u, 1, {Bytes(10, 1), Bytes(10, 2)});
  file.resize(file.size() - 4);  // cut into the second record's data
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  auto records = read_all(*reader);
  CHECK(records.size() == 2);  // header + first packet
  CHECK(reader->truncated_tail_bytes() == 16 + 6);
}

TEST_CASE("pcap: bad magic is an input error", "[capture][pcap]") {
  Bytes file = pcap_file(Endian::little, 0xA1B2C3D4u, 1, {});
  file[0] = 0x00;
  auto fmt = detect_format(file);
  REQUIRE_FALSE(fmt.has_value());
  CHECK(fmt.error().code == ErrorCode::input);
  CHECK_FALSE(CaptureReader::from_memory(file).has_value());
}

TEST_CASE("compressed captures are rejected with a hint", "[capture]") {
  auto magic = GENERATE(Bytes{0x1f, 0x8b, 0x08, 0x00}, Bytes{0x28, 0xb5, 0x2f, 0xfd},
                        Bytes{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, Bytes{'B', 'Z', 'h', '9'},
                        Bytes{0x04, 0x22, 0x4d, 0x18});
  Bytes file = magic;
  file.resize(64, 0);
  auto fmt = detect_format(file);
  REQUIRE_FALSE(fmt.has_value());
  CHECK(fmt.error().code == ErrorCode::input);
  CHECK(fmt.error().message.find("decompress") != std::string::npos);
}

TEST_CASE("pcap: non-zero reserved bits in the LinkType field are an input error",
          "[capture][pcap]") {
  // pcap-09: Reserved3 and R bit MUST be zero; readers SHOULD treat non-zero as an error.
  auto field = GENERATE(0x00010001u /* Reserved3 */, 0x08000001u /* R bit */);
  const Bytes file = pcap_file(Endian::little, 0xA1B2C3D4u, field, {});
  auto hdr = parse_pcap_file_header(file);
  REQUIRE_FALSE(hdr.has_value());
  CHECK(hdr.error().code == ErrorCode::input);
}

TEST_CASE("pcap: FCS bits in the LinkType field are decoded", "[capture][pcap]") {
  // FCS len = 2 (16-bit words, Ethernet), P bit set, link type 1.
  const std::uint32_t field = (2u << 28) | (1u << 26) | 1u;
  const Bytes file = pcap_file(Endian::little, 0xA1B2C3D4u, field, {});
  auto hdr = parse_pcap_file_header(file);
  REQUIRE(hdr.has_value());
  CHECK(hdr->fcs_present);
  CHECK(hdr->fcs_len_words == 2);
  CHECK(hdr->linktype == 1);
}

TEST_CASE("pcap: oversized record length is an input error", "[capture][pcap]") {
  Buf b(Endian::little);
  b.u32(0xA1B2C3D4u).u16(2).u16(4).u32(0).u32(0).u32(65535).u32(1);
  b.u32(0).u32(0).u32(0x7FFFFFFFu).u32(0x7FFFFFFFu).raw({1, 2, 3});
  auto reader = CaptureReader::from_memory(b.bytes());
  REQUIRE(reader.has_value());
  REQUIRE(reader->next().has_value());  // file header
  auto rec = reader->next();
  REQUIRE_FALSE(rec.has_value());
  CHECK(rec.error().code == ErrorCode::input);
}

TEST_CASE("empty and tiny inputs are input errors, never undefined behaviour", "[capture]") {
  CHECK_FALSE(CaptureReader::from_memory(Bytes{}).has_value());
  CHECK_FALSE(CaptureReader::from_memory(Bytes{0xD4}).has_value());
  auto hdr_only = CaptureReader::from_memory(Bytes{0xD4, 0xC3, 0xB2, 0xA1});
  REQUIRE(hdr_only.has_value());
  auto rec = hdr_only->next();
  CHECK_FALSE(rec.has_value());
}
