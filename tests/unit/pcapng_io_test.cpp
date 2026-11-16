// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "capture/detect.hpp"
#include "capture/pcapng.hpp"
#include "capture/reader.hpp"
#include "capture/writer.hpp"
#include "capture_test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {

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

Bytes section(Endian e) {
  return cat({shb(e, cat({opt(e, 2, "hw"), opt(e, 3, "os"), opt_end(e)})),
              idb(e, 1, 65535, cat({opt(e, 9, "\x09"), opt_end(e)})),
              epb(e, 0, 1000, Bytes{1, 2, 3, 4, 5}), epb(e, 0, 2000, Bytes(64, 0x42))});
}

}  // namespace

TEST_CASE("pcapng: both byte orders and mixed-order sections", "[capture][pcapng]") {
  const Bytes file = cat({section(Endian::little), section(Endian::big)});
  CHECK(*detect_format(file) == CaptureFormat::pcapng);
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  auto records = read_all(*reader);
  REQUIRE(records.size() == 8);
  CHECK(records[0].block_type == kPcapngShb);
  CHECK(records[0].endian == Endian::little);
  CHECK(records[4].block_type == kPcapngShb);
  CHECK(records[4].endian == Endian::big);
  CHECK(records[2].frame_number == 1);
  CHECK(records[7].frame_number == 4);
  // The interface table is per section; the second IDB is interface 0 of section 2.
  REQUIRE(reader->interfaces().size() == 1);
  CHECK(reader->interfaces()[0].tsresol == 9);
  CHECK(reader->interfaces()[0].linktype == 1);

  auto writer = CaptureWriter::to_memory();
  for (const auto& r : records) REQUIRE(writer.write(r).has_value());
  REQUIRE(writer.finish().has_value());
  CHECK(writer.memory() == file);
}

TEST_CASE("pcapng: options parse and serialise with zero padding", "[capture][pcapng]") {
  const auto e = GENERATE(Endian::little, Endian::big);
  const Bytes region = cat({opt(e, 1, "comment!"), opt(e, 2, "abc"), opt_end(e)});
  auto opts = parse_options(region, e);
  REQUIRE(opts.has_value());
  REQUIRE(opts->size() == 2);
  CHECK((*opts)[0].code == 1);
  CHECK((*opts)[0].value == Bytes{'c', 'o', 'm', 'm', 'e', 'n', 't', '!'});
  CHECK((*opts)[1].value.size() == 3);
  CHECK(serialize_options(*opts, e) == region);
  CHECK(serialize_options({}, e).empty());
}

TEST_CASE("pcapng: option overrunning its region is an input error", "[capture][pcapng]") {
  Buf b(Endian::little);
  b.u16(1).u16(40).str("short");
  auto opts = parse_options(b.bytes(), Endian::little);
  REQUIRE_FALSE(opts.has_value());
  CHECK(opts.error().code == ErrorCode::input);
}

TEST_CASE("pcapng: invalid block total length is an input error", "[capture][pcapng]") {
  const auto e = Endian::little;
  Bytes good = cat({shb(e), idb(e, 1, 65535)});
  SECTION("trailing length differs") {
    Bytes file = good;
    file[file.size() - 4] ^= 0x04;
    auto reader = CaptureReader::from_memory(file);
    REQUIRE(reader.has_value());
    REQUIRE(reader->next().has_value());
    auto rec = reader->next();
    REQUIRE_FALSE(rec.has_value());
    CHECK(rec.error().code == ErrorCode::input);
  }
  SECTION("length not a multiple of 4") {
    Buf b(e);
    b.u32(1).u32(21).raw(Bytes(9, 0)).u32(21);
    Bytes file = cat({shb(e), b.bytes()});
    auto reader = CaptureReader::from_memory(file);
    REQUIRE(reader.has_value());
    REQUIRE(reader->next().has_value());
    auto rec = reader->next();
    REQUIRE_FALSE(rec.has_value());
    CHECK(rec.error().code == ErrorCode::input);
  }
}

TEST_CASE("pcapng: blocks above 64 MiB are an input error", "[capture][pcapng]") {
  const auto e = Endian::little;
  Buf b(e);
  b.u32(6).u32(0x04000010u);  // 64 MiB + 16
  Bytes file = cat({shb(e), b.bytes(), Bytes(64, 0)});
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  REQUIRE(reader->next().has_value());
  auto rec = reader->next();
  REQUIRE_FALSE(rec.has_value());
  CHECK(rec.error().code == ErrorCode::input);
}

TEST_CASE("pcapng: truncated final block is reported as tail", "[capture][pcapng]") {
  const auto e = Endian::little;
  Bytes file = cat({shb(e), idb(e, 1, 65535), epb(e, 0, 1, Bytes(40, 7))});
  const std::size_t cut = 10;
  file.resize(file.size() - cut);
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  auto records = read_all(*reader);
  CHECK(records.size() == 2);
  CHECK(reader->truncated_tail_bytes() == epb(e, 0, 1, Bytes(40, 7)).size() - cut);
}

TEST_CASE("pcapng: a block before the first SHB is an input error", "[capture][pcapng]") {
  const auto e = Endian::little;
  Bytes file = cat({idb(e, 1, 65535)});
  CHECK_FALSE(CaptureReader::from_memory(file).has_value());
}

TEST_CASE("pcapng: local-use and unknown block types are surfaced", "[capture][pcapng]") {
  const auto e = Endian::little;
  Bytes file = cat({shb(e), block(e, 0x80000001u, Bytes(8, 0)), block(e, 0x00000BADu, Bytes(8, 0)),
                    block(e, 0x1234u, Bytes(4, 0))});
  auto reader = CaptureReader::from_memory(file);
  REQUIRE(reader.has_value());
  auto records = read_all(*reader);
  REQUIRE(records.size() == 4);
  CHECK(records[1].block_type == 0x80000001u);
  CHECK(is_local_use_type(records[1].block_type));
  CHECK(records[2].block_type == kPcapngCustomCopy);
  CHECK_FALSE(is_local_use_type(records[3].block_type));
  CHECK(is_local_use_type(std::uint32_t{0x8000}, true));  // option codes: MSB of 16 bits
}

TEST_CASE("pcapng: option region offsets per block type", "[capture][pcapng]") {
  const auto e = Endian::little;
  const Bytes data{1, 2, 3, 4, 5};
  const Bytes epb_block = epb(e, 0, 1, data, cat({opt(e, 1, "x"), opt_end(e)}));
  auto off = option_region_offset(kPcapngEpb, epb_block, e);
  REQUIRE(off.has_value());
  REQUIRE(off->has_value());
  CHECK(**off == 8 + 20 + 8);  // header + fixed EPB fields + padded data
  const Bytes spb_block = block(e, kPcapngSpb, Buf(e).u32(5).raw(data).pad4().bytes());
  auto none = option_region_offset(kPcapngSpb, spb_block, e);
  REQUIRE(none.has_value());
  CHECK_FALSE(none->has_value());  // SPB has no options
}

TEST_CASE("pcapng: SHB builder writes Section Length -1", "[capture][pcapng]") {
  const auto e = GENERATE(Endian::little, Endian::big);
  const Bytes b = build_shb(e, {});
  REQUIRE(b.size() == 28);
  CHECK(load32(b, 0, e) == kPcapngShb);
  CHECK(load32(b, 8, e) == 0x1A2B3C4Du);
  CHECK(load64(b, 16, e) == 0xFFFFFFFFFFFFFFFFull);
  CHECK(load32(b, 24, e) == 28);
}

TEST_CASE("pcapng: block builder pads body and repeats total length", "[capture][pcapng]") {
  const auto e = Endian::little;
  const Bytes b = build_block(kPcapngIdb, Buf(e).u16(1).u16(0).u32(65535).bytes(),
                              {PcapngOption{2, Bytes{'e', 't', 'h', '0', 'x'}}}, e);
  CHECK(b.size() % 4 == 0);
  CHECK(load32(b, 4, e) == b.size());
  CHECK(load32(b, b.size() - 4, e) == b.size());
}
