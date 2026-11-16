// SPDX-License-Identifier: GPL-3.0-or-later
//
// Recognisers and renderers (FR-010, FR-014).
#include "pseudo/text_formats.hpp"
#include "reveal_fixture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <cstdio>
#include <string>

using namespace mcxanon;
using reveal_test::dotted;
using reveal_test::Fixture;
using reveal_test::hex32;
using reveal_test::mac_text;

namespace {
std::string upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

// IPv6 text styles.
std::string v6_full(const Ipv6& a, bool zeros) {
  std::string o;
  char b[8];
  for (std::size_t i = 0; i < 16; i += 2) {
    if (i) o.push_back(':');
    std::snprintf(b, sizeof b, zeros ? "%04x" : "%x", (a[i] << 8) | a[i + 1]);
    o += b;
  }
  return o;
}
// RFC 5952 §4.2: the longest run of two or more zero groups (the first on a tie) becomes "::".
std::string v6_compressed(const Ipv6& a) {
  const auto zero = [&](std::size_t g) { return a[2 * g] == 0 && a[2 * g + 1] == 0; };
  std::size_t best = 8, best_len = 0;
  for (std::size_t i = 0; i < 8;) {
    if (zero(i)) {
      std::size_t j = i;
      while (j < 8 && zero(j)) ++j;
      if (j - i > best_len && j - i >= 2) {
        best = i;
        best_len = j - i;
      }
      i = j;
    } else {
      ++i;
    }
  }
  std::string o;
  char b[8];
  for (std::size_t i = 0; i < 8; ++i) {
    if (i == best) {
      o += "::";
      i += best_len - 1;
      continue;
    }
    if (!o.empty() && o.back() != ':') o.push_back(':');
    std::snprintf(b, sizeof b, "%x", (a[2 * i] << 8) | a[2 * i + 1]);
    o += b;
  }
  return o;
}
Ipv6 v6(std::initializer_list<int> groups) {
  Ipv6 a{};
  std::size_t i = 0;
  for (int g : groups) {
    a[i++] = static_cast<std::uint8_t>(g >> 8);
    a[i++] = static_cast<std::uint8_t>(g);
  }
  return a;
}
}  // namespace

TEST_CASE("text categories: prefixed hex pseudonyms", "[reveal][recognise]") {
  Fixture f;
  struct Case {
    Category c;
    const char* orig;
  };
  const Case cases[] = {
      {Category::call_id, "4HHkVRn12z2Cx-SQ@10.0.0.1"},
      {Category::tag, "a1"},
      {Category::branch, "z9hG4bK1XwKZAIwULg_"},
      {Category::branch, "plain-branch-1"},
      {Category::entity_tag, "aff-hb6E"},
      {Category::charging_id, "icid-value-01"},
      {Category::session_id, "0123456789abcdef0123456789abcdef"},
      {Category::boundary, "mcdata-af"},
      {Category::msrp_session, "aB3dE5fG7h"},
      {Category::reg_token, "reg-17"},
      {Category::cname, "user@host-1"},
      {Category::display_name, "Alice Smith"},
  };
  for (const auto& k : cases) {
    const auto p = f.text(k.c, k.orig);
    INFO(std::string(to_string(k.c)) << " " << p);
    CHECK(f.reveal("value " + p + ";next") == std::string("value ") + k.orig + ";next");
    CHECK(f.reveal("<x>" + p + "</x>") == std::string("<x>") + k.orig + "</x>");
  }
  // Folded categories match in upper case; the original keeps its case unless it is
  // canonicalised to lowercase (UUID, session id).
  const auto c = f.text(Category::call_id, "4HHkVRn12z2Cx-SQ@10.0.0.1");
  CHECK(f.reveal("Call-ID: " + upper(c)) == "Call-ID: 4HHkVRn12z2Cx-SQ@10.0.0.1");
  const auto uu = f.text(Category::uuid, "5F0E8C2A-3B71-4D9E-9A44-2C7B1E6F0D18");
  CHECK(f.reveal("urn:uuid:" + uu) == "urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18");
  CHECK(f.reveal("urn:uuid:" + upper(uu)) == "urn:uuid:5F0E8C2A-3B71-4D9E-9A44-2C7B1E6F0D18");
  // sip_user is case-sensitive.
  const auto u = f.user("alice");
  CHECK(f.reveal("sip:" + upper(u) + "@x") == "sip:" + upper(u) + "@x");
}

TEST_CASE("text categories: render_like pseudonyms match exactly", "[reveal][recognise]") {
  Fixture f;
  const char* const opaque = "imei-35-209900-176148-1";
  const auto o = f.text(Category::opaque, opaque);
  const auto d = f.text(Category::digest, "553f3566e4e9afb84d4eba229af97d50");
  const auto cell = f.text(Category::cell_id, "2600100A1B2C3D4");
  const auto plmn = f.text(Category::plmn, "260001");
  const auto tid = f.text(Category::msrp_tid, "a7Bc9dQ1");
  const auto mid = f.text(Category::msrp_msgid, "msg-41aZ");
  CHECK(f.reveal("instance " + o + ".") == std::string("instance ") + opaque + ".");
  CHECK(f.reveal("response=\"" + d + "\"") == "response=\"553f3566e4e9afb84d4eba229af97d50\"");
  CHECK(f.reveal("utran-cell-id-3gpp=" + cell + ";x") == "utran-cell-id-3gpp=2600100A1B2C3D4;x");
  // A PLMN is 6 digits: a short match, ambiguous by default (FR-015).
  RevealOptions all;
  all.replace_ambiguous = true;
  CHECK(f.reveal("PLMN " + plmn) == "PLMN " + plmn);
  CHECK(f.reveal("PLMN " + plmn, all) == "PLMN 260001");
  CHECK(f.reveal("MSRP " + tid + " SEND") == "MSRP a7Bc9dQ1 SEND");
  CHECK(f.reveal("Message-ID: " + mid) == "Message-ID: msg-41aZ");
  // render_like pseudonyms are case-sensitive: flipping the case of one letter breaks the match.
  std::string flipped = o;
  for (auto& ch : flipped) {
    if (std::isalpha(static_cast<unsigned char>(ch))) {
      ch = std::isupper(static_cast<unsigned char>(ch)) ? static_cast<char>(std::tolower(ch))
                                                        : static_cast<char>(std::toupper(ch));
      break;
    }
  }
  CHECK(f.reveal("flipped " + flipped) == "flipped " + flipped);
}

TEST_CASE("domain chains", "[reveal][recognise]") {
  Fixture f;
  const auto h = f.host("mcx.example.net");
  const auto h2 = f.host("scscf1.mcx.example.net");
  const auto u = f.user("alice");
  CHECK(f.reveal("Host " + h) == "Host mcx.example.net");
  CHECK(f.reveal("Host " + h + ".") == "Host mcx.example.net.");
  CHECK(f.reveal("sip:" + u + "@" + h2 + ":5060;transport=tcp") == "sip:alice@scscf1.mcx.example.net:5060;transport=tcp");
  // A lone label (without .invalid) is revealed to its original as well.
  const auto label = h.substr(0, h.find('.'));
  CHECK(f.reveal("label " + label + " here") == "label mcx.example.net here");
  // Labels of two different hosts glued together are ambiguous.
  const auto other = f.host("ims.operator.org");
  const std::string glued = other.substr(0, other.find('.')) + h.substr(h.find('.'));
  RevealSummary s;
  CHECK(f.reveal("bad " + glued, {}, &s) == "bad " + glued);
  REQUIRE(s.candidates.size() == 1);
  CHECK(s.candidates[0].kind == RevealKind::ambiguous);
  // Upper case: the host is case-insensitive.
  CHECK(f.reveal("HOST " + upper(h)) == "HOST MCX.EXAMPLE.NET");
}

TEST_CASE("addresses: IPv4", "[reveal][recognise]") {
  Fixture f;
  const auto a = dotted(f.ipv4(0x0A0000FE));  // 10.0.0.254
  CHECK(f.reveal("src " + a + " dst") == "src 10.0.0.254 dst");
  CHECK(f.reveal("Via: SIP/2.0/UDP " + a + ":5060;branch") == "Via: SIP/2.0/UDP 10.0.0.254:5060;branch");
  CHECK(f.reveal("net " + a + "/32") == "net 10.0.0.254/32");
  CHECK(f.reveal("1" + a) == "1" + a);    // glued digit
  CHECK(f.reveal(a + ".7") == a + ".7");  // a longer dotted run
  // A prefix that is not a mapped address is neither revealed nor listed.
  RevealSummary s;
  const std::string prefix = a.substr(0, a.rfind('.')) + ".0/24";
  CHECK(f.reveal("route " + prefix, {}, &s) == "route " + prefix);
  CHECK(s.candidates.empty());
}

TEST_CASE("addresses: IPv6 in every text form", "[reveal][recognise]") {
  Fixture f;
  const Ipv6 orig = v6({0xfd12, 0x3456, 0x789a, 0x1, 0, 0, 0, 0x5});
  const Ipv6 p = f.ipv6(orig);
  CHECK(f.reveal("addr " + v6_compressed(p) + " x") == "addr fd12:3456:789a:1::5 x");
  // Eight groups without "::" read as uncompressed only when a zero group is written out;
  // otherwise the text is also the RFC 5952 form.
  if (v6_full(p, false) != v6_compressed(p)) {
    CHECK(f.reveal("addr " + v6_full(p, false)) == "addr fd12:3456:789a:1:0:0:0:5");
  }
  // A pseudonym with zero groups, written out without "::": the original is written the same way.
  const Ipv6 o2 = v6({0xfd12, 0x3456, 0x789a, 0x2, 0, 0, 0, 0x5});
  const Ipv6 p2 = v6({0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0x9});
  REQUIRE(f.mapping.insert(MappingEntry{Category::ipv6, Bytes(o2.begin(), o2.end()), Bytes(p2.begin(), p2.end()), 0, 0})
              .has_value());
  CHECK(f.reveal("addr " + v6_full(p2, false)) == "addr fd12:3456:789a:2:0:0:0:5");
  CHECK(f.reveal("addr " + v6_compressed(p2)) == "addr fd12:3456:789a:2::5");
  CHECK(f.reveal("addr " + v6_full(p, true)) == "addr fd12:3456:789a:0001:0000:0000:0000:0005");
  CHECK(f.reveal("addr " + upper(v6_compressed(p))) == "addr FD12:3456:789A:1::5");
  CHECK(f.reveal("[" + v6_compressed(p) + "]:5061") == "[fd12:3456:789a:1::5]:5061");
  CHECK(f.reveal(v6_compressed(p) + "%eth0") == "fd12:3456:789a:1::5%eth0");
  CHECK(f.reveal(v6_compressed(p) + "/64") == "fd12:3456:789a:1::5/64");

  // Link-local: the interface identifier is the mapped component.
  const Ipv6 ll = v6({0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe00, 0x5301});
  const Ipv6 llp = f.ipv6(ll);
  CHECK(f.reveal("Src: " + v6_compressed(llp)) == "Src: fe80::200:5eff:fe00:5301");
  // Solicited-node: the low 24 bits.
  const Ipv6 sn = v6({0xff02, 0, 0, 0, 0, 0x1, 0xff00, 0x5301});
  const Ipv6 snp = f.ipv6(sn);
  CHECK(f.reveal("Dst: " + v6_compressed(snp)) == "Dst: ff02::1:ff00:5301");
  // Embedded IPv4.
  const Ipv6 mapped = v6({0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001});
  const Ipv6 mp = f.ipv6(mapped);
  const auto v4 = static_cast<std::uint32_t>((mp[12] << 24) | (mp[13] << 16) | (mp[14] << 8) | mp[15]);
  CHECK(f.reveal("::ffff:" + dotted(v4)) == "::ffff:10.0.0.1");
}

TEST_CASE("addresses: MAC in three styles", "[reveal][recognise]") {
  Fixture f;
  const Mac m = f.mac(Mac{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01});
  CHECK(f.reveal("Src: " + mac_text(m) + " (" + mac_text(m) + ")") == "Src: 00:00:5e:00:53:01 (00:00:5e:00:53:01)");
  CHECK(f.reveal("hw " + mac_text(m, '-')) == "hw 00-00-5e-00-53-01");
  CHECK(f.reveal("hw " + upper(mac_text(m, '-'))) == "hw 00-00-5E-00-53-01");
  CHECK(f.reveal("hw " + mac_text(m, 0)) == "hw 00005e005301");
}

TEST_CASE("numbers: 32-bit values in decimal and hex", "[reveal][recognise]") {
  Fixture f;
  const auto ss = f.ssrc(0x3C3C3C07);
  CHECK(f.reveal("Synchronization Source identifier: " + hex32(ss) + " (" + std::to_string(ss) + ")") ==
        "Synchronization Source identifier: 0x3c3c3c07 (1010580487)");
  CHECK(f.reveal("ssrc=" + hex32(ss, false)) == "ssrc=3c3c3c07");
  CHECK(f.reveal("SSRC " + upper(hex32(ss, false))) == "SSRC 3C3C3C07");
  auto spi = f.p.spi(123788461);
  REQUIRE(spi.has_value());
  CHECK(f.reveal("spi-c=" + std::to_string(*spi) + ";") == "spi-c=123788461;");
  const auto eci = f.binary(Category::eci, 10597059);
  CHECK(f.reveal("ECI " + std::to_string(eci)) == "ECI 10597059");
  // A value that is a pseudonym in two families with different originals is ambiguous.
  REQUIRE(f.mapping.insert(MappingEntry{Category::fc_ref, Bytes{0, 0, 0x30, 0x39},
                                        Bytes{static_cast<std::uint8_t>(ss >> 24), static_cast<std::uint8_t>(ss >> 16),
                                              static_cast<std::uint8_t>(ss >> 8), static_cast<std::uint8_t>(ss)},
                                        0, 0})
              .has_value());
  RevealSummary s;
  CHECK(f.reveal(std::to_string(ss), {}, &s) == std::to_string(ss));
  REQUIRE(s.candidates.size() == 1);
  CHECK(s.candidates[0].ambiguity == "overlap");
}

TEST_CASE("numbers: telephone numbers, IMEIs and SDP session ids", "[reveal][recognise]") {
  Fixture f;
  const auto t = f.tel("+48601234567");
  CHECK(f.reveal("tel:" + t + ";phone-context=x") == "tel:+48601234567;phone-context=x");
  // Visual separators of the match are kept and filled with the original digits.
  std::string sep = t.substr(0, 3) + "-" + t.substr(3, 3) + "." + t.substr(6, 3) + "(" + t.substr(9) + ")";
  CHECK(f.reveal("call " + sep) == "call +48-601.234(567)");
  const auto imei = f.text(Category::imei, "35209900176148");
  REQUIRE(imei.size() == 15);
  const std::string orig15 = std::string("35209900176148") + luhn_digit("35209900176148");
  CHECK(f.reveal("imei " + imei) == "imei " + orig15);
  const auto sess = f.text(Category::sdp_sess, "3735928559");
  CHECK(f.reveal("o=- " + sess + " 2 IN IP4") == "o=- 3735928559 2 IN IP4");
}

TEST_CASE("Call-ID local@host: the host pseudonym after the Call-ID is part of the match", "[reveal][recognise]") {
  Fixture f;
  // Feature 002 maps the whole value as a Call-ID and writes "@" + the host pseudonym.
  const auto local = f.text(Category::call_id, "abcDEF123@mcx.example.net");
  const auto host = f.host("mcx.example.net");
  CHECK(f.reveal("Call-ID: " + local + "@" + host + "\r\n") == "Call-ID: abcDEF123@mcx.example.net\r\n");
  const auto local2 = f.text(Category::call_id, "xyz987@10.0.0.254");
  const auto ip = dotted(f.ipv4(0x0A0000FE));
  CHECK(f.reveal("i: " + local2 + "@" + ip + ".") == "i: xyz987@10.0.0.254.");
  // Quoted alone, the Call-ID pseudonym gives the whole original.
  CHECK(f.reveal("id " + local) == "id abcDEF123@mcx.example.net");
}

TEST_CASE("multicast MACs follow the IP group", "[reveal][recognise]") {
  Fixture f;
  const Ipv6 sn = v6({0xff02, 0, 0, 0, 0, 0x1, 0xff00, 0x5301});
  const Ipv6 snp = f.ipv6(sn);
  char mac[32];
  std::snprintf(mac, sizeof mac, "33:33:ff:%02x:%02x:%02x", snp[13], snp[14], snp[15]);
  CHECK(f.reveal(std::string("Dst: ") + mac) == "Dst: 33:33:ff:00:53:01");
  const auto g = f.ipv4(0xEF010203);  // 239.1.2.3
  std::snprintf(mac, sizeof mac, "01:00:5e:%02x:%02x:%02x", (g >> 16) & 0x7f, (g >> 8) & 0xff, g & 0xff);
  CHECK(f.reveal(std::string("Dst: ") + mac) == "Dst: 01:00:5e:01:02:03");
}
