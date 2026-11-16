// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/bytes.hpp"
#include "rewrite/checksum.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using namespace mcxanon;

namespace {
Bytes ascii(std::string_view s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("Internet checksum, RFC 1071 section 3 example", "[checksum]") {
  // RFC 1071 §3: the sum of 00 01 f2 03 f4 f5 f6 f7 is ddf2; the checksum is its complement.
  Bytes data{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  CHECK(inet_fold_sum(inet_accumulate(data)) == 0xddf2);
  CHECK(inet_checksum(data) == 0x220d);
}

TEST_CASE("Internet checksum over data containing its checksum is zero", "[checksum]") {
  // A real IPv4 header (checksum field filled in).
  Bytes hdr{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
            0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
  CHECK(inet_checksum(hdr) == 0x0000);
  hdr[10] = 0;
  hdr[11] = 0;
  CHECK(inet_checksum(hdr) == 0xb861);
}

TEST_CASE("Internet checksum of odd-length data pads with zero", "[checksum]") {
  Bytes odd{0x01, 0x02, 0x03};
  Bytes even{0x01, 0x02, 0x03, 0x00};
  CHECK(inet_checksum(odd) == inet_checksum(even));
}

TEST_CASE("Incremental update, RFC 1624 section 4 example", "[checksum]") {
  // RFC 1624 §4: HC = 0xDD2F, m = 0x5555 -> m' = 0x3285 gives HC' = 0x0000 with eqn. 3.
  CHECK(inet_update16(0xDD2F, 0x5555, 0x3285) == 0x0000);
}

TEST_CASE("Incremental update agrees with full recomputation", "[checksum]") {
  Bytes hdr{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
            0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
  const auto before = inet_checksum(hdr);
  Bytes changed = hdr;
  changed[12] = 0xF0;  // first 16-bit word of the source address: 0xc0a8 -> 0xf0a8
  CHECK(inet_update16(before, 0xc0a8, 0xf0a8) == inet_checksum(changed));
}

TEST_CASE("CRC-32 (Ethernet FCS) check value", "[checksum]") {
  CHECK(crc32_ethernet(ascii("123456789")) == 0xCBF43926u);
  CHECK(crc32_ethernet(Bytes{}) == 0x00000000u);
}

TEST_CASE("CRC32c check value and RFC 3720 B.4 vectors", "[checksum]") {
  CHECK(crc32c(ascii("123456789")) == 0xE3069283u);
  Bytes zeros(32, 0x00);
  Bytes ones(32, 0xFF);
  Bytes inc(32);
  Bytes dec(32);
  for (std::size_t i = 0; i < 32; ++i) {
    inc[i] = static_cast<std::uint8_t>(i);
    dec[i] = static_cast<std::uint8_t>(31 - i);
  }
  CHECK(crc32c(zeros) == 0x8A9136AAu);
  CHECK(crc32c(ones) == 0x62A8AB43u);
  CHECK(crc32c(inc) == 0x46DD794Eu);
  CHECK(crc32c(dec) == 0x113FDB5Cu);
}
