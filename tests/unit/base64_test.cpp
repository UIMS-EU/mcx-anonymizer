// SPDX-License-Identifier: GPL-3.0-or-later
//
// The strict base64 codec of feature 005 (RFC 4648 §4 and §5).
#include "bytes/base64.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {
Bytes b(std::string_view s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("base64: RFC 4648 §10 test vectors round-trip", "[base64]") {
  const std::pair<std::string_view, std::string_view> v[] = {
      {"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"}, {"foob", "Zm9vYg=="},
      {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
  for (const auto& [plain, text] : v) {
    auto d = base64::decode(text);
    REQUIRE(d.has_value());
    CHECK(d->bytes == b(plain));
    CHECK(base64::encode(d->bytes, d->layout) == text);
  }
}

TEST_CASE("base64: strict decoding rejects what is not base64", "[base64]") {
  CHECK_FALSE(base64::decode("Zm9v YmFy").has_value());   // embedded space
  CHECK_FALSE(base64::decode("Zm9vY").has_value());       // one character left over
  CHECK_FALSE(base64::decode("Zg=").has_value());         // short padding
  CHECK_FALSE(base64::decode("Zg==Zg==").has_value());    // padding inside
  CHECK_FALSE(base64::decode("Zm9v!mFy").has_value());    // not in the alphabet
  CHECK_FALSE(base64::decode("Zm9v_mFy").has_value());    // URL-safe character, standard alphabet
  CHECK_FALSE(base64::decode("Zh==").has_value());        // non-zero pad bits
}

TEST_CASE("base64: the line layout is captured and reproduced", "[base64]") {
  Bytes data(100);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 7);
  const std::string one = base64::encode(data, {});
  REQUIRE(one.find('\n') == std::string::npos);
  std::string folded;
  for (std::size_t i = 0; i < one.size(); i += 76) folded += one.substr(i, 76) + "\r\n";
  auto d = base64::decode(folded);
  REQUIRE(d.has_value());
  CHECK(d->bytes == data);
  CHECK(d->layout.line == 76);
  CHECK(d->layout.final_break);
  CHECK(base64::encode(d->bytes, d->layout) == folded);
  // Unequal line lengths (other than the last) are not a layout we can reproduce: rejected.
  std::string ragged = one.substr(0, 10) + "\r\n" + one.substr(10, 76) + "\r\n" + one.substr(86);
  CHECK_FALSE(base64::decode(ragged).has_value());
  // Bare LF breaks are kept as LF.
  std::string lf;
  for (std::size_t i = 0; i < one.size(); i += 64) lf += one.substr(i, 64) + "\n";
  auto d2 = base64::decode(lf);
  REQUIRE(d2.has_value());
  CHECK_FALSE(d2->layout.crlf);
  CHECK(base64::encode(d2->bytes, d2->layout) == lf);
}

TEST_CASE("base64: the URL-safe alphabet is a separate mode, padding optional", "[base64]") {
  const Bytes v{0xfb, 0xff, 0xbf};
  CHECK(base64::encode(v, {}, base64::Alphabet::url) == "-_-_");
  auto d = base64::decode("-_-_", base64::Alphabet::url);
  REQUIRE(d.has_value());
  CHECK(d->bytes == v);
  auto u = base64::decode("Zm8", base64::Alphabet::url);  // unpadded
  REQUIRE(u.has_value());
  CHECK(u->bytes == b("fo"));
  CHECK_FALSE(u->layout.padded);
  CHECK(base64::encode(u->bytes, u->layout, base64::Alphabet::url) == "Zm8");
  CHECK_FALSE(base64::decode("Zm8", base64::Alphabet::standard).has_value());
}
