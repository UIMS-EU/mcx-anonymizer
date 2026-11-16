// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"
#include "bytes/hex.hpp"
#include "bytes/reader.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;

TEST_CASE("endian loads and stores", "[bytes]") {
  Bytes b{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  CHECK(load16(b, 0, Endian::big) == 0x0102);
  CHECK(load16(b, 0, Endian::little) == 0x0201);
  CHECK(load32(b, 1, Endian::big) == 0x02030405u);
  CHECK(load32(b, 1, Endian::little) == 0x05040302u);
  CHECK(load64(b, 0, Endian::big) == 0x0102030405060708ull);
  CHECK(load64(b, 0, Endian::little) == 0x0807060504030201ull);

  Bytes out(8, 0);
  store16(out, 0, 0xA1B2, Endian::big);
  store16(out, 2, 0xA1B2, Endian::little);
  store32(out, 4, 0x11223344u, Endian::big);
  CHECK(out == Bytes{0xA1, 0xB2, 0xB2, 0xA1, 0x11, 0x22, 0x33, 0x44});
  store64(out, 0, 0x0102030405060708ull, Endian::little);
  CHECK(out == Bytes{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
}

TEST_CASE("raw loads outside the buffer are programmer errors", "[bytes]") {
  Bytes b{0x01, 0x02, 0x03};
  CHECK_THROWS(load32(b, 0, Endian::big));
  CHECK_THROWS(load16(b, 2, Endian::big));
}

TEST_CASE("bounded reader returns errors on overrun", "[bytes]") {
  Bytes b{0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF, 0x07};
  Reader r(b);
  auto v16 = r.u16();
  REQUIRE(v16.has_value());
  CHECK(*v16 == 42);
  auto v32 = r.u32();
  REQUIRE(v32.has_value());
  CHECK(*v32 == 0xDEADBEEFu);
  CHECK(r.offset() == 6);
  CHECK(r.remaining() == 1);
  auto bad = r.u16();
  REQUIRE_FALSE(bad.has_value());
  CHECK(bad.error().code == ErrorCode::input);
  CHECK(r.offset() == 6);  // a failed read does not advance
  auto last = r.u8();
  REQUIRE(last.has_value());
  CHECK(*last == 7);
  CHECK(r.empty());
  CHECK_FALSE(r.bytes(1).has_value());
  CHECK_FALSE(r.skip(1).has_value());
}

TEST_CASE("reader honours byte order and yields views", "[bytes]") {
  Bytes b{0x34, 0x12, 0xAA, 0xBB, 0xCC};
  Reader r(b, Endian::little);
  CHECK(*r.u16() == 0x1234);
  auto view = r.bytes(2);
  REQUIRE(view.has_value());
  CHECK(view->size() == 2);
  CHECK((*view)[1] == 0xBB);
  REQUIRE(r.skip(1).has_value());
  CHECK(r.empty());
}

TEST_CASE("hex encode and decode", "[bytes]") {
  Bytes b{0x00, 0x0A, 0xFF, 0x10};
  CHECK(to_hex(b) == "000aff10");
  CHECK(to_hex(b, true) == "000AFF10");
  auto back = from_hex("000AfF10");
  REQUIRE(back.has_value());
  CHECK(*back == b);
  CHECK_FALSE(from_hex("abc").has_value());   // odd length
  CHECK_FALSE(from_hex("zz").has_value());    // not hex
  CHECK(from_hex("")->empty());
}
