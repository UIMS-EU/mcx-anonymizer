// SPDX-License-Identifier: GPL-3.0-or-later
//
// Rule-by-rule outcomes of the SIP rewriter with the embedded rule set (FR-005 to FR-017,
// FR-024).
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/message.hpp"
#include "sip/render.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <regex>
#include <string>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 7 + 3);
  return s;
}

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  SipCounters counters;
  Context ctx{rules, mapper, {}, counters};

  SipRewriteResult run(const std::string& msg, Transport t = Transport::datagram) {
    auto r = rewrite_message(msg, t, ctx);
    REQUIRE(r.has_value());
    return *r;
  }
  std::string out(const std::string& msg) { return run(msg).bytes; }
  std::string user(const char* u) { return *p.text(Category::sip_user, u); }
  std::string dom(const char* d) { return *p.domain(d); }
  std::string ip(const char* a) { return **map_address_text(a, mapper); }
};

std::string msg(const std::string& start, std::initializer_list<const char*> headers, const std::string& body = "") {
  std::string m = start + "\r\n";
  for (const char* h : headers) m += std::string(h) + "\r\n";
  m += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  return m;
}

const std::initializer_list<const char*> kDialog = {
    "Via: SIP/2.0/UDP 10.1.1.1:5060;branch=z9hG4bK776asdhds",
    "From: \"Alice Nowak\" <sip:alice.nowak@mcx.example.net>;tag=1928301774",
    "To: <sip:bob@mcx.example.net>", "Call-ID: a84b4c76e66710@10.1.1.1", "CSeq: 314159 OPTIONS"};

bool contains(const std::string& s, const std::string& x) { return s.find(x) != std::string::npos; }

std::string header(const std::string& m, const std::string& name) {
  const auto at = m.find("\r\n" + name + ":");
  if (at == std::string::npos) return {};
  const auto end = m.find("\r\n", at + 2);
  return m.substr(at + 2, end - at - 2);
}
}  // namespace

TEST_CASE("URIs are pseudonymised wherever they occur (FR-009)", "[sip][rewrite][uri]") {
  Fixture f;
  const auto o = f.out(msg("INVITE sip:bob@mcx.example.net;transport=udp SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1:5060;branch=z9hG4bK1",
                            "From: <sip:alice:secret@mcx.example.net?subject=hi>;tag=1",
                            "To: <sip:bob@mcx.example.net>", "Call-ID: c1", "CSeq: 1 INVITE",
                            "Contact: <sip:alice@10.1.1.1:5060;ob;x-vendor=1>",
                            "P-Asserted-Identity: <sip:+48601234567@ims.example.net;user=phone>, <tel:+48-601-234-567>",
                            "Route: <sip:pcscf.mcx.example.net;lr>"}));
  const std::string bob = f.user("bob");
  const std::string mcx = f.dom("mcx.example.net");
  CHECK(o.starts_with("INVITE sip:" + bob + "@" + mcx + ";transport=udp SIP/2.0\r\n"));
  CHECK(header(o, "From") == "From: <sip:" + f.user("alice") + "@" + mcx + ">;tag=" + *f.p.text(Category::tag, "1"));
  CHECK_FALSE(contains(o, "secret"));   // password removed
  CHECK_FALSE(contains(o, "subject"));  // URI headers removed
  CHECK(header(o, "Contact") == "Contact: <sip:" + f.user("alice") + "@" + f.ip("10.1.1.1") + ":5060;ob>");
  CHECK(f.counters.removed_unknown["sip-param"]["x-vendor"] == 1);
  // user=phone and tel: share the telephone mapping (FR-033).
  const auto pai = header(o, "P-Asserted-Identity");
  const std::string tel = *f.p.tel("+48601234567");
  CHECK(contains(pai, "<sip:" + tel + "@" + f.dom("ims.example.net") + ";user=phone>"));
  CHECK(contains(pai, "<tel:" + *f.p.tel("+48-601-234-567") + ">"));
  CHECK(header(o, "Route") == "Route: <sip:" + f.dom("pcscf.mcx.example.net") + ";lr>");
  CHECK_FALSE(contains(o, "example.net"));
}

TEST_CASE("display names get their own mapping, always quoted (FR-010)", "[sip][rewrite]") {
  Fixture f;
  const auto o = f.out(msg("MESSAGE sip:x@example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK2", "From: Alice <sip:a@example.net>;tag=2",
                            "To: \"Alice\" <sip:b@example.net>", "Call-ID: c2", "CSeq: 1 MESSAGE"}));
  const std::string n = *f.p.text(Category::display_name, "Alice");
  CHECK(header(o, "From").starts_with("From: \"" + n + "\" <sip:"));
  CHECK(header(o, "To").starts_with("To: \"" + n + "\" <sip:"));  // same name, same pseudonym
}

TEST_CASE("dialog identifiers, also embedded in other headers (FR-011)", "[sip][rewrite]") {
  Fixture f;
  const auto o = f.out(msg("INVITE sip:x@example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK776asdhds",
                            "From: <sip:a@example.net>;tag=1928301774", "To: <sip:b@example.net>;tag=a6c85cf",
                            "Call-ID: a84b4c76e66710@pc33.example.com", "CSeq: 314159 INVITE",
                            "Replaces: a84b4c76e66710@pc33.example.com;to-tag=a6c85cf;from-tag=1928301774",
                            "Target-Dialog: a84b4c76e66710@pc33.example.com;local-tag=a6c85cf;remote-tag=1928301774",
                            "In-Reply-To: 70710@saturn.example.com, 17320@saturn.example.com",
                            "Session-ID: ab30317f1a784dc48ff824d0d3715d86;remote=00000000000000000000000000000000",
                            "SIP-If-Match: dx200xyz"}));
  const auto cid = *f.p.text(Category::call_id, "a84b4c76e66710@pc33.example.com") + "@" + f.dom("pc33.example.com");
  const auto t1 = *f.p.text(Category::tag, "1928301774");
  const auto t2 = *f.p.text(Category::tag, "a6c85cf");
  CHECK(header(o, "Call-ID") == "Call-ID: " + cid);
  CHECK(header(o, "Replaces") == "Replaces: " + cid + ";to-tag=" + t2 + ";from-tag=" + t1);
  CHECK(header(o, "Target-Dialog") == "Target-Dialog: " + cid + ";local-tag=" + t2 + ";remote-tag=" + t1);
  CHECK(std::regex_match(header(o, "Via"), std::regex("Via: SIP/2.0/UDP [0-9.]+;branch=z9hG4bKb-[0-9a-f]{12}")));
  CHECK(std::regex_match(header(o, "In-Reply-To"), std::regex("In-Reply-To: c-[0-9a-f]{16}@\\S+, c-[0-9a-f]{16}@\\S+")));
  CHECK(std::regex_match(header(o, "Session-ID"),
                         std::regex("Session-ID: [0-9a-f]{32};remote=0{32}")));  // nil kept
  CHECK(std::regex_match(header(o, "SIP-If-Match"), std::regex("SIP-If-Match: e-[0-9a-f]{12}")));
}

TEST_CASE("instance identifiers keep their format (FR-012)", "[sip][rewrite][instance]") {
  Fixture f;
  const auto o = f.out(msg("REGISTER sip:ims.example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK3", "From: <sip:a@ims.example.net>;tag=3",
                            "To: <sip:a@ims.example.net>", "Call-ID: c3", "CSeq: 1 REGISTER",
                            "Contact: <sip:a@10.1.1.1;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>;"
                            "+sip.instance=\"<urn:gsma:imei:35209900-176148-1>\";+g.3gpp.mcptt;expires=600;"
                            "+g.3gpp.registration-token=\"1234567\";+g.vendor.secret=\"x\""}));
  const auto contact = header(o, "Contact");
  CHECK(std::regex_search(contact, std::regex("gr=urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}>")));
  std::smatch m;
  REQUIRE(std::regex_search(contact, m, std::regex("\\+sip\\.instance=\"<urn:gsma:imei:([0-9]{8})-([0-9]{6})-([0-9])>\"")));
  const std::string imei = m[1].str() + m[2].str() + m[3].str();
  CHECK(imei.substr(0, 14) != "35209900176148");
  CHECK(imei == *f.p.text(Category::imei, "35209900176148"));  // Luhn check digit recomputed
  CHECK(contains(contact, ";+g.3gpp.mcptt;expires=600;"));
  CHECK(std::regex_search(contact, std::regex("\\+g\\.3gpp\\.registration-token=\"rt-[0-9a-f]{8}\"")));
  CHECK_FALSE(contains(contact, "vendor"));
}

TEST_CASE("credentials: IMPI binds to the user and domain mappings (FR-012, FR-013, D5)", "[sip][rewrite][auth]") {
  Fixture f;
  const auto o = f.out(msg("REGISTER sip:ims.example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK4", "From: <sip:alice@ims.example.net>;tag=4",
                            "To: <sip:alice@ims.example.net>", "Call-ID: c4", "CSeq: 2 REGISTER",
                            "Authorization: Digest username=\"alice@ims.example.net\", realm=\"ims.example.net\", "
                            "nonce=\"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==\", uri=\"sip:ims.example.net\", "
                            "response=\"6629fae49393a05397450978507c4ef1\", algorithm=AKAv1-MD5, qop=auth, "
                            "nc=00000001, cnonce=\"0a4f113b\", x-secret=\"y\""}));
  const auto a = header(o, "Authorization");
  const auto ims = f.dom("ims.example.net");
  CHECK(contains(a, "Digest username=\"" + f.user("alice") + "@" + ims + "\", realm=\"" + ims + "\""));
  CHECK(contains(a, "uri=\"sip:" + ims + "\""));
  CHECK(contains(a, "algorithm=AKAv1-MD5, qop=auth, nc=00000001"));
  CHECK(std::regex_search(a, std::regex("nonce=\"[A-Za-z0-9+/]{30}==\"")));
  CHECK(std::regex_search(a, std::regex("response=\"[0-9a-f]{32}\"")));
  CHECK_FALSE(contains(a, "6629fae49393a05397450978507c4ef1"));
  CHECK_FALSE(contains(a, "x-secret"));
  const auto c = f.out(msg("SIP/2.0 401 Unauthorized",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK4", "From: <sip:alice@ims.example.net>;tag=4",
                            "To: <sip:alice@ims.example.net>;tag=9", "Call-ID: c4", "CSeq: 2 REGISTER",
                            "WWW-Authenticate: Digest realm=\"ims.example.net\", nonce=\"abcd\", algorithm=AKAv1-MD5, "
                            "ik=\"00112233445566778899aabbccddeeff\", ck=\"ffeeddccbbaa99887766554433221100\""}));
  const auto w = header(c, "WWW-Authenticate");
  CHECK_FALSE(contains(w, "ik="));
  CHECK_FALSE(contains(w, "ck="));
  CHECK_FALSE(contains(c, "00112233445566778899aabbccddeeff"));
}

TEST_CASE("Security-* and P-Access-Network-Info (FR-014, FR-015)", "[sip][rewrite]") {
  Fixture f;
  const auto o = f.out(msg("REGISTER sip:ims.example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK5", "From: <sip:a@ims.example.net>;tag=5",
                            "To: <sip:a@ims.example.net>", "Call-ID: c5", "CSeq: 1 REGISTER",
                            "Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=23456789; spi-s=12345678; "
                            "port-c=2468; port-s=1357",
                            "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234151D0FCE11; "
                            "network-provided; x-loc=\"secret\"",
                            "P-Visited-Network-ID: \"Visited Network Number 1\""}));
  CHECK(header(o, "Security-Client") == "Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;spi-c=" +
                                            std::to_string(*f.p.spi(23456789)) + ";spi-s=" +
                                            std::to_string(*f.p.spi(12345678)) + ";port-c=2468;port-s=1357");
  CHECK(std::regex_match(header(o, "P-Access-Network-Info"),
                         std::regex("P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=[0-9A-F]{13};network-provided")));
  CHECK(std::regex_match(header(o, "P-Visited-Network-ID"),
                         std::regex("P-Visited-Network-ID: \"d-[0-9a-f]{8}\\.invalid\"")));
}

TEST_CASE("free text: removed headers, Warning (D2), Reason, reason phrases (FR-016)", "[sip][rewrite][text]") {
  Fixture f;
  const auto o = f.out(msg("SIP/2.0 486 Alice is in a meeting",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK6", "From: <sip:a@example.net>;tag=6",
                            "To: <sip:b@example.net>;tag=7", "Call-ID: c6", "CSeq: 1 INVITE",
                            "User-Agent: Acme Softphone 4.2 (serial 0042)", "Server: Acme",
                            "Organization: Example Ltd", "Subject: Lunch with Bob", "s: Lunch again",
                            "Warning: 399 pcscf.example.net \"Bob's phone is broken\"",
                            "Warning: 399 pcscf.example.net \"110 MCPTT group is not affiliated\"",
                            "Reason: SIP;cause=486;text=\"Bob said no\"",
                            "X-Vendor-Id: 12345"}));
  CHECK(o.starts_with("SIP/2.0 486 Busy Here\r\n"));
  for (const char* x : {"Acme", "Example Ltd", "Lunch", "Bob", "meeting", "X-Vendor", "12345"}) {
    INFO(x);
    CHECK_FALSE(contains(o, x));
  }
  CHECK(contains(o, "\r\nWarning: 399 " + f.dom("pcscf.example.net") + " \"\"\r\n"));
  CHECK(contains(o, "\r\nWarning: 399 " + f.dom("pcscf.example.net") + " \"110\"\r\n"));
  CHECK(header(o, "Reason") == "Reason: SIP;cause=486");
  CHECK(f.counters.headers["User-Agent"]["remove"] == 1);
  CHECK(f.counters.headers["Subject"]["remove"] == 2);
  CHECK(f.counters.removed_unknown["sip-header"]["X-Vendor-Id"] == 1);
  // A code without an RFC 3261 default phrase gets the neutral phrase.
  CHECK(f.out(msg("SIP/2.0 199 Something Private", kDialog)).starts_with("SIP/2.0 199 -\r\n"));
}

TEST_CASE("Date follows --time-shift (FR-017)", "[sip][rewrite]") {
  Fixture f;
  f.ctx.options.time_shift_s = -86400 * 30;
  auto d = std::initializer_list<const char*>{"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK7", "From: <sip:a@example.net>;tag=8",
                                              "To: <sip:b@example.net>", "Call-ID: c7", "CSeq: 1 OPTIONS",
                                              "Date: Sat, 13 Nov 2010 23:29:00 GMT"};
  CHECK(header(f.out(msg("OPTIONS sip:x@example.net SIP/2.0", d)), "Date") == "Date: Thu, 14 Oct 2010 23:29:00 GMT");
  Fixture g;
  CHECK(header(g.out(msg("OPTIONS sip:x@example.net SIP/2.0", d)), "Date") == "Date: Sat, 13 Nov 2010 23:29:00 GMT");
}

TEST_CASE("compact names stay compact, spelling and order are kept (FR-006)", "[sip][rewrite]") {
  Fixture f;
  const std::string in =
      "MESSAGE sip:x@example.net SIP/2.0\r\nv: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK8\r\n"
      "X-First: drop me\r\nf: <sip:a@example.net>;tag=9\r\nTO: <sip:b@example.net>\r\ni: c8\r\n"
      "cseq: 1 MESSAGE\r\nMax-Forwards: 70\r\nl: 0\r\n\r\n";
  const auto o = f.out(in);
  const auto pos = [&](const char* h) { return o.find(std::string("\r\n") + h); };
  CHECK(pos("v: ") < pos("f: "));
  CHECK(pos("f: ") < pos("TO: "));
  CHECK(pos("TO: ") < pos("i: "));
  CHECK(pos("i: ") < pos("cseq: "));
  CHECK(pos("cseq: ") < pos("Max-Forwards: 70"));
  CHECK(pos("Max-Forwards: 70") < pos("l: 0"));
  CHECK_FALSE(contains(o, "X-First"));
}

TEST_CASE("kept feature tags and ICSI values survive (FR-008)", "[sip][rewrite][tags]") {
  Fixture f;
  const auto o = f.out(msg("INVITE sip:x@example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK9", "From: <sip:a@example.net>;tag=10",
                            "To: <sip:b@example.net>", "Call-ID: c9", "CSeq: 1 INVITE",
                            "Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt,"
                            "urn%3Aurn-7%3A3gpp-service.ims.icsi.vendor\";+g.3gpp.mcptt;require;explicit",
                            "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt",
                            "P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel"}));
  CHECK(header(o, "Accept-Contact") ==
        "Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";+g.3gpp.mcptt;require;explicit");
  CHECK(header(o, "P-Preferred-Service") == "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt");
  CHECK(header(o, "P-Asserted-Service").empty());  // the mmtel ICSI has no indexed source
}

TEST_CASE("Content-Length is rewritten; the offset map is monotone and complete", "[sip][rewrite][length]") {
  Fixture f;
  const std::string body = "v=0\r\no=alice 2890844526 2890842807 IN IP4 10.1.1.1\r\ns=Talk\r\nt=0 0\r\n";
  const std::string in = msg("INVITE sip:bob@mcx.example.net SIP/2.0",
                             {"Via: SIP/2.0/UDP 10.1.1.1:5060;branch=z9hG4bK10", "From: <sip:a@example.net>;tag=11",
                              "To: <sip:b@example.net>", "Call-ID: c10", "CSeq: 1 INVITE",
                              "Content-Type: application/sdp"},
                             body);
  const auto r = f.run(in);
  auto parsed = parse_message(r.bytes, Transport::datagram);
  REQUIRE(parsed.has_value());
  REQUIRE(parsed->content_length.has_value());
  CHECK(*parsed->content_length == parsed->body.len);
  CHECK(r.bytes.substr(parsed->body.off).starts_with("v=0\r\no=u-"));
  REQUIRE_FALSE(r.offset_map.empty());
  CHECK(r.offset_map.front().orig == 0);
  CHECK(r.offset_map.front().out == 0);
  for (std::size_t i = 1; i < r.offset_map.size(); ++i) {
    CHECK(r.offset_map[i].orig == r.offset_map[i - 1].orig + r.offset_map[i - 1].orig_len);
    CHECK(r.offset_map[i].out == r.offset_map[i - 1].out + r.offset_map[i - 1].out_len);
  }
  const auto& last = r.offset_map.back();
  CHECK(last.orig + last.orig_len == in.size());
  CHECK(last.out + last.out_len == r.bytes.size());
  // map_offset: unchanged spans map linearly; offsets inside a replaced span map to its end.
  CHECK(map_offset(r.offset_map, 0) == 0);
  CHECK(map_offset(r.offset_map, in.size()) == r.bytes.size());
}

TEST_CASE("bodies: unknown and MCX types are emptied, the part kept (FR-023)", "[sip][rewrite][body]") {
  Fixture f;
  const auto o = f.out(msg("MESSAGE sip:x@example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK11", "From: <sip:a@example.net>;tag=12",
                            "To: <sip:b@example.net>", "Call-ID: c11", "CSeq: 1 MESSAGE",
                            "Content-Type: application/vnd.3gpp.mcptt-info+xml"},
                           "<mcptt-info><mcpttURI>sip:secret@example.net</mcpttURI></mcptt-info>"));
  CHECK(header(o, "Content-Type") == "Content-Type: application/vnd.3gpp.mcptt-info+xml");
  CHECK(header(o, "Content-Length") == "Content-Length: 0");
  CHECK(o.ends_with("\r\n\r\n"));
  CHECK(f.counters.bodies["application/vnd.3gpp.mcptt-info+xml"]["emptied"] == 1);
  Fixture g;
  const auto u = g.out(msg("MESSAGE sip:x@example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK12", "From: <sip:a@example.net>;tag=13",
                            "To: <sip:b@example.net>", "Call-ID: c12", "CSeq: 1 MESSAGE",
                            "Content-Type: application/x-vendor", "Content-Encoding: gzip"},
                           "secret-binary"));
  CHECK_FALSE(contains(u, "secret-binary"));
  CHECK(g.counters.removed_unknown["content-type"]["application/x-vendor"] == 1);
}

TEST_CASE("malformed messages and headers are isolated (FR-029)", "[sip][rewrite][malformed]") {
  Fixture f;
  // A broken dialog-defining header zeroes the whole message.
  const std::string bad = msg("INVITE sip:x@example.net SIP/2.0",
                              {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK13", "From: broken <<",
                               "To: <sip:b@example.net>", "Call-ID: c13", "CSeq: 1 INVITE"});
  const auto r = f.run(bad);
  CHECK(r.malformed == Malformed::message);
  CHECK(r.bytes == std::string(bad.size(), '\0'));
  // A broken other header is removed alone.
  const std::string one = msg("INVITE sip:x@example.net SIP/2.0",
                              {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK14", "From: <sip:a@example.net>;tag=14",
                               "To: <sip:b@example.net>", "Call-ID: c14", "CSeq: 1 INVITE",
                               "P-Asserted-Identity: <sip:alice@[bad>"});
  const auto s = f.run(one);
  CHECK(s.malformed == Malformed::header);
  CHECK_FALSE(contains(s.bytes, "P-Asserted-Identity"));
  CHECK(f.counters.malformed_headers["P-Asserted-Identity"] == 1);
  // A broken start line or Request-URI.
  CHECK(f.run(msg("INVITE sip:a@[::1 SIP/2.0", kDialog)).malformed == Malformed::message);
}

TEST_CASE("an extension method is not understood: the message is zeroed", "[sip][rewrite][malformed]") {
  Fixture f;
  // Fourteen methods are kept (TS 24.229 annex A.2.1.4).
  for (const char* m : {"ACK", "BYE", "CANCEL", "INFO", "INVITE", "MESSAGE", "NOTIFY", "OPTIONS", "PRACK",
                        "PUBLISH", "REFER", "REGISTER", "SUBSCRIBE", "UPDATE"}) {
    INFO(m);
    const std::string cseq = std::string("CSeq: 1 ") + m;
    const auto r = f.run(msg(std::string(m) + " sip:x@example.net SIP/2.0",
                             {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK21", "From: <sip:a@example.net>;tag=21",
                              "To: <sip:b@example.net>", "Call-ID: c21", cseq.c_str()}));
    CHECK(r.malformed == Malformed::none);
    CHECK(r.method == m);
  }
  // Any other token (here one that carries text) zeroes the message; the report never shows it.
  const std::string x = msg("SECRETSTUFF sip:x@example.net SIP/2.0",
                            {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK22", "From: <sip:a@example.net>;tag=22",
                             "To: <sip:b@example.net>", "Call-ID: c22", "CSeq: 1 SECRETSTUFF"});
  const auto r = f.run(x);
  CHECK(r.malformed == Malformed::message);
  CHECK(r.bytes == std::string(x.size(), '\0'));
  CHECK(r.method == "(invalid-name)");
  // Methods are case-sensitive (RFC 3261 §7.1).
  CHECK(f.run(msg("invite sip:x@example.net SIP/2.0", kDialog)).malformed == Malformed::message);
  // A response whose CSeq names an extension method: CSeq is dialog-defining, so zeroed too.
  const auto s = f.run(msg("SIP/2.0 200 OK", {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK23",
                                              "From: <sip:a@example.net>;tag=23", "To: <sip:b@example.net>;tag=9",
                                              "Call-ID: c23", "CSeq: 7 SECRETSTUFF"}));
  CHECK(s.malformed == Malformed::message);
}

TEST_CASE("the items of a zeroed message are counted as zeroed (FR-036)", "[sip][rewrite][malformed][report]") {
  Fixture f;
  // From fails after Via was rewritten; the body was counted before the headers.
  const std::string bad = msg("INVITE sip:x@example.net SIP/2.0",
                              {"Via: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK31;x-vendor=1", "From: broken <<",
                               "To: <sip:b@example.net>", "Call-ID: c31", "CSeq: 1 INVITE",
                               "X-Vendor-Id: v31", "Content-Type: application/sdp"},
                              "v=0\r\no=- 1 1 IN IP4 10.1.1.1\r\ns=-\r\nc=IN IP4 10.1.1.1\r\nt=0 0\r\n");
  CHECK(f.run(bad).malformed == Malformed::message);
  using M = std::map<std::string, std::uint64_t>;
  for (const char* h : {"Via", "From", "To", "Call-ID", "CSeq", "Content-Type", "Content-Length"}) {
    INFO(h);
    CHECK(f.counters.headers[h] == M{{"zero", 1}});
  }
  CHECK(f.counters.sdp.empty());
  CHECK(f.counters.bodies.empty());
  CHECK(f.counters.removed_unknown["sip-header"] == M{{"X-Vendor-Id", 1}});
  CHECK(f.counters.removed_unknown["sip-param"].empty());
  // An extension method: the same.
  Fixture g;
  CHECK(g.run(msg("SECRETSTUFF sip:x@example.net SIP/2.0", kDialog)).malformed == Malformed::message);
  CHECK(g.counters.headers["Via"] == M{{"zero", 1}});
  CHECK(g.counters.headers["CSeq"] == M{{"zero", 1}});
  // A message that is rewritten counts every item once, by its action.
  Fixture h;
  CHECK(h.run(msg("OPTIONS sip:x@example.net SIP/2.0", kDialog)).malformed == Malformed::none);
  CHECK(h.counters.headers["Via"] == M{{"pseudonymise", 1}});
  CHECK(h.counters.headers["CSeq"] == M{{"keep", 1}});
}

// R22: the removed values are scan tokens; a value removed from every message of a capture is
// kept once, in the order first seen, instead of once per message.
TEST_CASE("a removed value is one scan token however often it is removed", "[sip][rewrite][counters]") {
  SipCounters run;
  for (int i = 0; i < 3; ++i) {
    SipCounters msg;
    msg.removed("agent-x/1.0");
    msg.removed("Free text");
    run.merge(std::move(msg), i != 1);
  }
  run.removed("Free text");
  run.removed("");
  REQUIRE(run.removed_values.size() == 2);
  CHECK(run.removed_values[0].second == "agent-x/1.0");
  CHECK(run.removed_values[1].second == "Free text");
}

// FR-036: removed_unknown counts what has no rule. A feature tag that a rule removes (RFC 3840
// `description`) is removed and its value becomes a scan token, but it is not unknown.
TEST_CASE("a feature tag removed by its rule is not counted as unknown", "[sip][rewrite][counters]") {
  Fixture f;
  const auto o = f.out(msg("OPTIONS sip:bob@mcx.example.net SIP/2.0",
                           {"Via: SIP/2.0/UDP 10.1.1.1:5060;branch=z9hG4bK776asdhds",
                            "From: <sip:alice@mcx.example.net>;tag=1", "To: <sip:bob@mcx.example.net>",
                            "Call-ID: c1@10.1.1.1", "CSeq: 1 OPTIONS",
                            "Contact: <sip:alice@10.1.1.1>;description=\"Desk phone 7\";+g.vendor.x"}));
  CHECK_FALSE(contains(o, "Desk phone"));
  CHECK_FALSE(contains(o, "vendor"));
  CHECK(f.counters.removed_unknown["sip-param"].count("description") == 0);
  CHECK(f.counters.removed_unknown["sip-param"]["+g.vendor.x"] == 1);
  CHECK(std::any_of(f.counters.removed_values.begin(), f.counters.removed_values.end(),
                    [](const auto& v) { return v.second == "Desk phone 7"; }));
}
