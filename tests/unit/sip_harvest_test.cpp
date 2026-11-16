// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own SIP/SDP harvester (FR-031). It shares no code with the
// anonymiser: this test includes nothing from src/sip/.
#include "scan/walker/sip_harvest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace mcxanon;
using namespace mcxanon::scan;

namespace {
std::span<const std::uint8_t> bytes(const std::string& s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}
bool has(const std::vector<Token>& t, TokenCategory c, const std::string& v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) {
    return x.category == c && std::string(x.value.begin(), x.value.end()) == v;
  });
}
bool has_bin(const std::vector<Token>& t, TokenCategory c, std::vector<std::uint8_t> v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) { return x.category == c && x.value == v; });
}

const std::string kRegister =
    "REGISTER sip:ims.example.net SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.lab.example.net:5060;branch=z9hG4bK776asdhds\r\n"
    "v: SIP/2.0/TCP 10.47.16.5;branch=z9hG4bKnashds8\r\n"
    "From: \"Alice Nowak\" <sip:alice.nowak@mcx.example.net>;tag=1928301774\r\n"
    "To: <tel:+48-601-234-567>\r\n"
    "i: a84b4c76e66710@pc33.lab.example.net\r\n"
    "Contact: <sip:+48601234567@[fd12:3456:789a:20::10]:5060;user=phone>;"
    "+sip.instance=\"<urn:gsma:imei:35209900-176148-1>\"\r\n"
    "Authorization: Digest username=\"260011234567890@ims.mnc001.mcc260.3gppnetwork.org\", "
    "realm=\"ims.mnc001.mcc260.3gppnetwork.org\", nonce=\"\"\r\n"
    "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=2600100A1B2C3D4\r\n"
    "Content-Length: 0\r\n\r\n";
}  // namespace

TEST_CASE("the harvester extracts SIP identities by syntax", "[scan][harvest][sip]") {
  detail::SipHarvest h;
  h.feed(bytes(kRegister), {}, false);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "alice.nowak"));
  CHECK(has(t, TokenCategory::string, "mcx.example.net"));
  CHECK(has(t, TokenCategory::string, "Alice Nowak"));
  CHECK(has(t, TokenCategory::string, "1928301774"));
  CHECK(has(t, TokenCategory::string, "z9hG4bK776asdhds"));
  CHECK(has(t, TokenCategory::string, "a84b4c76e66710@pc33.lab.example.net"));
  CHECK(has(t, TokenCategory::string, "pc33.lab.example.net"));
  CHECK(has(t, TokenCategory::number, "48601234567"));
  CHECK(has(t, TokenCategory::string, "260011234567890@ims.mnc001.mcc260.3gppnetwork.org"));
  CHECK(has(t, TokenCategory::string, "260011234567890"));
  CHECK(has(t, TokenCategory::string, "ims.mnc001.mcc260.3gppnetwork.org"));
  CHECK(has(t, TokenCategory::string, "urn:gsma:imei:35209900-176148-1"));
  CHECK(has(t, TokenCategory::string, "2600100A1B2C3D4"));
  CHECK(has_bin(t, TokenCategory::ipv4, {10, 47, 16, 5}));
  CHECK(has_bin(t, TokenCategory::ipv6, {0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x10}));
  for (const auto& x : t) {
    INFO(x.label);
    CHECK(x.label.starts_with("input:"));
  }
}

TEST_CASE("the harvester extracts SDP o=, c= and a=rtcp", "[scan][harvest][sdp]") {
  detail::SipHarvest h;
  const std::string sdp = "v=0\r\no=alice 2890844526 2890842807 IN IP4 10.1.2.3\r\ns=-\r\n"
                          "c=IN IP4 mbms.invalid\r\nc=IN IP4 0.0.0.0\r\nc=IN IP6 fd00::9\r\nt=0 0\r\n"
                          "m=audio 5000 RTP/AVP 0\r\na=rtcp:5001 IN IP4 10.9.9.9\r\n"
                          "m=message 2855 TCP/MSRP *\r\na=path:msrp://h1.example.net:2855/kjhd37s2s20w2a;tcp\r\n";
  h.feed(bytes(sdp), {}, false);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "alice"));
  CHECK(has(t, TokenCategory::number, "2890844526"));
  CHECK(has_bin(t, TokenCategory::ipv4, {10, 1, 2, 3}));
  CHECK(has_bin(t, TokenCategory::ipv4, {10, 9, 9, 9}));
  CHECK(has_bin(t, TokenCategory::ipv6, {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}));
  CHECK(has(t, TokenCategory::string, "h1.example.net"));
  CHECK(has(t, TokenCategory::string, "kjhd37s2s20w2a"));
  // Values the output keeps on purpose are not harvested: the hold address, .invalid hosts.
  CHECK_FALSE(has_bin(t, TokenCategory::ipv4, {0, 0, 0, 0}));
  CHECK_FALSE(has(t, TokenCategory::string, "mbms.invalid"));
}

TEST_CASE("values split across two TCP segments are found through the carry-over", "[scan][harvest][tcp]") {
  detail::SipHarvest h;
  const std::vector<std::uint8_t> dir{1, 2, 3, 4};
  const std::string a = "INVITE sip:bob@example.net SIP/2.0\r\nFrom: <sip:charlie.split";
  const std::string b = "user@lab.example.net>;tag=987654321\r\n";
  h.feed(bytes(a), dir, true);
  h.feed(bytes(b), dir, true);
  const auto t = h.take();
  CHECK(has(t, TokenCategory::string, "charlie.splituser"));
  CHECK(has(t, TokenCategory::string, "987654321"));
  // Another direction does not inherit the carry-over.
  detail::SipHarvest g;
  g.feed(bytes(a), dir, true);
  g.feed(bytes(b), {9, 9, 9, 9}, true);
  CHECK_FALSE(has(g.take(), TokenCategory::string, "charlie.splituser"));
}

TEST_CASE("the harvester is bounded and tolerates garbage", "[scan][harvest]") {
  detail::SipHarvest h;
  std::string junk(100000, 'x');
  junk += "sip:";  // a scheme at the very end
  h.feed(bytes(junk), {}, false);
  std::string binary;
  for (int i = 0; i < 4096; ++i) binary.push_back(static_cast<char>(i * 37));
  h.feed(bytes(binary), {}, false);
  CHECK(h.take().size() < 64);
}
