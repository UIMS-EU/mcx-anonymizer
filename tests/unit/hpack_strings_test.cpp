// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 007: the scanner's own HPACK string reader (src/scan/walker/hpack_strings.*), which
// decodes Huffman-coded literals of the output for the residual-leak search, on the examples of
// RFC 7541 Appendix C.4.1 (requests with Huffman coding).
#include "scan/walker/hpack_strings.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon::scan::detail;

namespace {
std::string bytes(std::initializer_list<int> v) {
  std::string s;
  for (int b : v) s.push_back(static_cast<char>(b));
  return s;
}
}  // namespace

TEST_CASE("hpack strings: the Huffman code of RFC 7541 C.4.1", "[scan][web][hpack]") {
  const auto www = bytes({0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff});
  REQUIRE(hpack_huffman(www) == std::optional<std::string>("www.example.com"));
  // The scanner does not enforce the padding rule of RFC 7541 §5.2: it searches whatever decodes,
  // so a string with excess padding still yields its characters.
  CHECK(hpack_huffman(www + bytes({0xff})) == std::optional<std::string>("www.example.com"));
}

TEST_CASE("hpack strings: the literals of a request block (RFC 7541 C.4.1)", "[scan][web][hpack]") {
  // :method GET, :scheme http, :path /, :authority www.example.com (literal with incremental
  // indexing, indexed name 1, Huffman-coded value).
  const auto block = bytes({0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
                            0xf4, 0xff});
  const auto lits = hpack_literals(block);
  REQUIRE(lits.size() == 1);
  CHECK(lits[0].name == ":authority");
  CHECK(lits[0].value == "www.example.com");
  CHECK(lits[0].huffman);
  // A truncated block yields what parsed before the cut.
  CHECK(hpack_literals(block.substr(0, 6)).empty());
}
