// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own passthrough locator (spec FR-018): the four MIKEY carriers
// and xenc:EncryptedData subtrees of an output payload, with exact byte ranges; a hit is
// downgraded only when it lies wholly inside one range.
#include "bytes/base64.hpp"
#include "scan/walker/passthrough.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using namespace mikey_test;
using scan::detail::PassthroughRange;

namespace {

std::vector<PassthroughRange> ranges_of(const std::string& text) {
  return scan::detail::passthrough_ranges(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

}  // namespace

TEST_CASE("passthrough locator: a=key-mgmt, application/mikey and <GKTP> carriers", "[scan][passthrough]") {
  const Bytes m = private_call();
  const std::string b64 = base64::encode(m);
  std::string hex;
  for (auto x : m) {
    static constexpr char d[] = "0123456789abcdef";
    hex += d[x >> 4];
    hex += d[x & 15];
  }
  const std::string text = "INVITE sip:x SIP/2.0\r\nContent-Type: multipart/mixed;boundary=b\r\n\r\n--b\r\n"
                           "Content-Type: application/sdp\r\n\r\nv=0\r\na=key-mgmt:mikey " + b64 + "\r\n--b\r\n"
                           "Content-Type: application/mikey\r\n\r\n" + b64 + "\r\n--b\r\n"
                           "Content-Type: application/xcap-diff+xml\r\n\r\n<g:GKTP id=\"1\">" + hex + "</g:GKTP>\r\n--b--\r\n";
  const auto r = ranges_of(text);
  REQUIRE(r.size() == 3);
  CHECK(r[0].carrier == "sdp");
  CHECK(text.substr(r[0].offset, r[0].length) == b64);
  CHECK(r[1].carrier == "body");
  CHECK(text.substr(r[1].offset, r[1].length) == b64);
  CHECK(r[2].carrier == "gktp");
  CHECK(text.substr(r[2].offset, r[2].length) == hex);
}

TEST_CASE("passthrough locator: xenc:EncryptedData subtrees, prefixed or default namespace", "[scan][passthrough]") {
  const std::string enc1 = "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">"
                           "<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData>"
                           "</xenc:EncryptedData>";
  const std::string enc2 = "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"><CipherData>"
                           "<CipherValue>REVG</CipherValue></CipherData></EncryptedData>";
  const std::string text = "MESSAGE sip:x SIP/2.0\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n"
                           "<mcpttinfo><a type=\"Encrypted\">" + enc1 + "</a><b type=\"Encrypted\">" + enc2 +
                           "</b></mcpttinfo>";
  const auto r = ranges_of(text);
  REQUIRE(r.size() == 2);
  for (const auto& x : r) CHECK(x.carrier == "encrypted-xml");
  CHECK(text.substr(r[0].offset, r[0].length) == enc1);
  CHECK(text.substr(r[1].offset, r[1].length) == enc2);
  // An unterminated subtree is not a passthrough element.
  CHECK(ranges_of("<xenc:EncryptedData xmlns:xenc=\"x\"><xenc:CipherValue>QUJD").empty());
}

TEST_CASE("passthrough locator: MCPC field 192", "[scan][passthrough]") {
  const Bytes m = private_call();
  Bytes app{0x90, 204, 0, 0, 1, 2, 3, 4, 'M', 'C', 'P', 'C', 192};
  put16(app, static_cast<unsigned>(m.size()));
  app.insert(app.end(), m.begin(), m.end());
  while (app.size() % 4 != 0) app.push_back(0);
  app[2] = static_cast<std::uint8_t>((app.size() / 4 - 1) >> 8);
  app[3] = static_cast<std::uint8_t>(app.size() / 4 - 1);
  const auto r = scan::detail::passthrough_ranges(app);
  REQUIRE(r.size() == 1);
  CHECK(r[0].carrier == "mcpc");
  CHECK(r[0].offset == 15);
  CHECK(r[0].length == m.size());
}

TEST_CASE("passthrough locator: only a hit wholly inside a range is covered", "[scan][passthrough]") {
  const std::vector<PassthroughRange> r{{10, 20, "sdp"}, {50, 5, "gktp"}};
  CHECK(scan::detail::covering(r, 10, 20) == &r[0]);
  CHECK(scan::detail::covering(r, 15, 4) == &r[0]);
  CHECK(scan::detail::covering(r, 50, 5) == &r[1]);
  CHECK(scan::detail::covering(r, 9, 4) == nullptr);   // straddles the start
  CHECK(scan::detail::covering(r, 28, 4) == nullptr);  // straddles the end
  CHECK(scan::detail::covering(r, 40, 2) == nullptr);  // outside
}
