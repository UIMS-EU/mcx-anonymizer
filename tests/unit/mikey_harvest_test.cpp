// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own MIKEY harvester. It never includes the
// anonymiser's MIKEY parser: the messages here are built by the test's own builder.
#include "bytes/base64.hpp"
#include "scan/walker/mikey_harvest.hpp"
#include "scan/walker/sip_harvest.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::scan;
using namespace mikey_test;

namespace {

bool has_token(const std::vector<Token>& t, TokenCategory c, const Bytes& v) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) { return x.category == c && x.value == v; });
}
bool has_containing(const std::vector<Token>& t, const std::string& part) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) {
    return std::string(x.value.begin(), x.value.end()).find(part) != std::string::npos;
  });
}
bool has_run_of(const std::vector<Token>& t, std::uint8_t b) {
  return std::any_of(t.begin(), t.end(), [&](const Token& x) {
    return x.value.size() >= 8 && std::all_of(x.value.begin(), x.value.end(), [&](std::uint8_t y) { return y == b; });
  });
}

std::vector<Token> harvest_sdp(const Bytes& msg) {
  const std::string sdp_text = "INVITE sip:x@y SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"
                               "a=key-mgmt:mikey " + base64::encode(msg) + "\r\n";
  detail::SipHarvest h;
  h.feed(std::span(reinterpret_cast<const std::uint8_t*>(sdp_text.data()), sdp_text.size()), {}, false);
  return h.take();
}

}  // namespace

TEST_CASE("mikey harvest: the values of an I_MESSAGE in a=key-mgmt become tokens", "[mikey][harvest]") {
  const auto t = harvest_sdp(private_call(0x1ABCDEF0u));
  CHECK(has_containing(t, "alice"));
  CHECK(has_containing(t, "kms.example.org"));
  CHECK(has_token(t, TokenCategory::key, Bytes{0x1a, 0xbc, 0xde, 0xf0}));
  CHECK(has_token(t, TokenCategory::bytes, Bytes(16, 0x52)));   // RAND
  CHECK(has_token(t, TokenCategory::bytes, Bytes(129, 0x47)));  // signature
  CHECK_FALSE(has_run_of(t, 0x53));                             // SAKKE data: kept ciphertext, no token
}

TEST_CASE("mikey harvest: hidden identities, SPIs and the key parameters header", "[mikey][harvest]") {
  Header h;
  h.csb_id = 0x0BBBBBBCu;  // the DPPK-ID equals the CSB ID (TS 33.180 §E.6.1)
  h.blocks = {block(4, 0, {0}, {}, Bytes{0x0A, 0xAA, 0xAA, 0xAB, 0x0B, 0xBB, 0xBB, 0xBC})};
  Bytes kp{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  kp.insert(kp.end(), 16, 0x49);                     // IV
  for (int x : {0x0B, 0xBB, 0xBB, 0xBC}) kp.push_back(static_cast<std::uint8_t>(x));  // DPPK-ID
  kp.push_back(0x78);
  put16(kp, 4);
  kp.insert(kp.end(), 4, 0x43);
  const Bytes uid_raw(32, 0x55);
  const std::string uid_b64 = base64::encode(Bytes(32, 0x56));
  const Bytes m = message(h, {t(1), rand(Bytes(16, 0x52)), idr(8, 2, uid_raw), idr(9, 1, text(uid_b64)),
                              ext(7, kp), sakke(Bytes(4, 0x53)), sign(Bytes(129, 0x47))});
  const auto tok = harvest_sdp(m);
  CHECK(has_token(tok, TokenCategory::bytes, uid_raw));
  CHECK(has_token(tok, TokenCategory::bytes, Bytes(32, 0x56)));  // the base64 UID, decoded
  CHECK(has_token(tok, TokenCategory::key, Bytes{0x0A, 0xAA, 0xAA, 0xAB}));
  CHECK(has_token(tok, TokenCategory::key, Bytes{0x0B, 0xBB, 0xBB, 0xBC}));
  CHECK(has_token(tok, TokenCategory::bytes, Bytes(16, 0x49)));  // the IV
}

TEST_CASE("mikey harvest: not-MIKEY and garbage give no MIKEY tokens and never crash", "[mikey][harvest]") {
  CHECK(detail::walk_mikey(Bytes{}).empty());
  CHECK(detail::walk_mikey(Bytes(9, 0x1a)).empty());
  Header h;
  h.data_type = 2;
  CHECK(detail::walk_mikey(message(h, {t(1), rand(Bytes(16, 1)), sign(Bytes(16, 1), 0)})).empty());
  Bytes m = private_call();
  for (std::size_t cut = 0; cut < m.size(); ++cut) {
    (void)detail::walk_mikey(Bytes(m.begin(), m.begin() + static_cast<std::ptrdiff_t>(cut)));
  }
}

TEST_CASE("mikey harvest: application/mikey bodies and <GKTP> text feed the MIKEY harvester",
          "[mikey][harvest]") {
  const Bytes m = private_call(0x2ABCDEF1u);
  const std::string body = "MESSAGE sip:x@y SIP/2.0\r\nContent-Type: application/mikey\r\n"
                           "Content-Transfer-Encoding: base64\r\n\r\n" + base64::encode(m);
  detail::SipHarvest h;
  h.feed(std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()), {}, false);
  auto t = h.take();
  CHECK(has_containing(t, "alice"));
  CHECK(has_token(t, TokenCategory::key, Bytes{0x2a, 0xbc, 0xde, 0xf1}));
  CHECK(has_token(t, TokenCategory::bytes, Bytes(16, 0x52)));
  // <GKTP>: the decoded I_MESSAGE gives tokens; its hex text is not a raw value.
  std::string hexs;
  for (auto x : m) {
    static constexpr char d[] = "0123456789abcdef";
    hexs += d[x >> 4];
    hexs += d[x & 15];
  }
  const std::string notify = "NOTIFY sip:x@y SIP/2.0\r\nContent-Type: application/xcap-diff+xml\r\n\r\n"
                             "<?xml version=\"1.0\"?>\n<d:xcap-diff xmlns:d=\"urn:ietf:params:xml:ns:xcap-diff\">"
                             "<g:GKTPs xmlns:g=\"urn:3gpp:ns:mcpttGKTP:1.0\"><g:GMK-GKTPs><g:GKTP id=\"k1\">" + hexs +
                             "</g:GKTP></g:GMK-GKTPs></g:GKTPs></d:xcap-diff>\n";
  detail::SipHarvest g;
  g.feed(std::span(reinterpret_cast<const std::uint8_t*>(notify.data()), notify.size()), {}, false);
  t = g.take();
  CHECK(has_containing(t, "bob"));
  CHECK(has_token(t, TokenCategory::key, Bytes{0x2a, 0xbc, 0xde, 0xf1}));
  CHECK_FALSE(has_containing(t, hexs.substr(0, 40)));
  CHECK_FALSE(has_containing(t, ":GKTP "));  // GKTP element names are vocabulary
}
