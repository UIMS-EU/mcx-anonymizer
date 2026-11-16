// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 007, User Story 4 (FR-025): reveal of the textual forms tshark shows for
// HTTP and TLS values — the percent-encoded user part of an XCAP request URI, header and JSON
// values as plain text, TLS hello randoms, session ids and key identifiers as hex, and the
// certificate serial number, which the anonymiser writes as a positive minimal INTEGER (its first
// octet adjusted, RFC 5280 §4.1.2.2) and tshark shows as hex with its leading zero octet.
#include "bytes/hex.hpp"
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using reveal_test::Fixture;

namespace {

// The serial number as src/tls/x509.cpp writes it (map_serial): the nonce pseudonym of the octets
// after a leading zero, with the sign bit restored, or with the sign bit cleared.
Bytes serial_out(Fixture& f, const Bytes& serial) {
  const bool lead = serial.size() > 1 && serial[0] == 0;
  Bytes body(serial.begin() + (lead ? 1 : 0), serial.end());
  auto m = f.p.bytes(Category::nonce, body);
  REQUIRE(m.has_value());
  Bytes out = *m;
  if (lead) {
    out[0] |= 0x80;
    out.insert(out.begin(), 0);
  } else {
    out[0] &= 0x7F;
    if (out.size() > 1 && out[0] == 0) out[0] = 1;
  }
  return out;
}

}  // namespace

TEST_CASE("reveal web: XCAP request URI with a percent-encoded SIP URI", "[reveal][web]") {
  Fixture f;
  const std::string u = f.user("alice");
  const std::string h = f.host("mcx.example.net");
  const std::string uri = "/org.openmobilealliance.xdm/users/sip%3A" + u + "%40" + h + "/index";
  CHECK(f.reveal("Request URI: " + uri + "\n") ==
        "Request URI: /org.openmobilealliance.xdm/users/sip%3Aalice%40mcx.example.net/index\n");
}

TEST_CASE("reveal web: header and JSON values as plain text", "[reveal][web]") {
  Fixture f;
  const std::string c = f.text(Category::opaque, "mcptt-client-17");
  const std::string s = f.user("bob");
  CHECK(f.reveal("{\"client_id\":\"" + c + "\",\"sub\":\"" + s + "\"}") ==
        "{\"client_id\":\"mcptt-client-17\",\"sub\":\"bob\"}");
  CHECK(f.reveal("X-3GPP-Asserted-Identity: \"sip:" + s + "@" + f.host("ims.example.org") + "\"\n") ==
        "X-3GPP-Asserted-Identity: \"sip:bob@ims.example.org\"\n");
}

TEST_CASE("reveal web: TLS random, session id and key identifier as hex", "[reveal][web][tls]") {
  Fixture f;
  Bytes random(32);
  for (std::size_t i = 0; i < random.size(); ++i) random[i] = static_cast<std::uint8_t>(0x40 + i);
  const Bytes sid(32, 0x7A);
  const Bytes ski(20, 0x3C);
  auto r = f.p.bytes(Category::nonce, random);
  auto s = f.p.bytes(Category::nonce, sid);
  auto k = f.p.bytes(Category::nonce, ski);
  REQUIRE((r && s && k));
  CHECK(f.reveal("            Random: " + to_hex(*r) + "\n") == "            Random: " + to_hex(random) + "\n");
  CHECK(f.reveal(to_hex(*r) + "\t" + to_hex(*s) + "\n") == to_hex(random) + "\t" + to_hex(sid) + "\n");
  CHECK(f.reveal("keyIdentifier: " + to_hex(*k)) == "keyIdentifier: " + to_hex(ski));
}

TEST_CASE("reveal web: certificate serial numbers in both sign cases", "[reveal][web][tls]") {
  Fixture f;
  // A serial with a leading zero octet (high bit of the next octet set) and one without.
  const Bytes neg{0x00, 0xC5, 0x89, 0xF6, 0x9E, 0xEC, 0xB0, 0x91, 0xA4, 0x99, 0xD4, 0xDC, 0xFE};
  const Bytes pos{0x7E, 0x11, 0x22, 0x33, 0x44};
  const Bytes on = serial_out(f, neg);
  const Bytes op = serial_out(f, pos);
  CHECK(f.reveal("serialNumber: 0x" + to_hex(on) + "\n") == "serialNumber: 0x" + to_hex(neg) + "\n");
  CHECK(f.reveal("\t" + to_hex(on) + "," + to_hex(op) + "\t") == "\t" + to_hex(neg) + "," + to_hex(pos) + "\t");
  CHECK(f.reveal("serialNumber: 0x" + to_hex(op)) == "serialNumber: 0x" + to_hex(pos));
}

TEST_CASE("reveal web: a ServerHello random with a downgrade sentinel and a wildcard name", "[reveal][web][tls]") {
  Fixture f;
  // The anonymiser maps the 24 octets before the sentinel (RFC 8446 §4.1.3, src/tls/handshake.cpp).
  const Bytes head(24, 0x6B);
  auto m = f.p.bytes(Category::nonce, head);
  REQUIRE(m.has_value());
  const std::string sentinel = "444f574e47524401";
  CHECK(f.reveal("Random: " + to_hex(*m) + sentinel + "\n") == "Random: " + to_hex(head) + sentinel + "\n");
  const std::string h = f.host("srv.example.org");
  CHECK(f.reveal("dNSName: *." + h + "\n") == "dNSName: *.srv.example.org\n");
}
