// SPDX-License-Identifier: GPL-3.0-or-later
//
// One parser per header value grammar of the SIP rule set.
#include "sip/header_values.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon::sip;

TEST_CASE("lists split at commas outside quotes, brackets and comments", "[sip][values]") {
  auto l = split_list("\"Doe, John\" <sip:j@example.net>, <sip:a@b.example.net;x=1,2>, x (a,b)");
  REQUIRE(l.has_value());
  REQUIRE(l->size() == 3);
  CHECK((*l)[0] == "\"Doe, John\" <sip:j@example.net>");
  CHECK((*l)[2] == "x (a,b)");
  CHECK_FALSE(split_list("a, , b").has_value());       // empty element
  CHECK_FALSE(split_list("\"unterminated, x").has_value());
  CHECK_FALSE(split_list("<sip:a@b, c").has_value());
}

TEST_CASE("name-addr lists", "[sip][values][name-addr]") {
  auto r = parse_name_addr_list("<sip:p1.example.com;lr>, \"Bob\" <sip:bob@example.net>;q=0.7");
  REQUIRE(r.has_value());
  REQUIRE(r->size() == 2);
  CHECK((*r)[0].uri.host == "p1.example.com");
  CHECK((*r)[1].display == "Bob");
  CHECK((*r)[1].params[0].name == "q");
  CHECK(parse_name_addr_list("*")->size() == 1);  // Contact: * (RFC 3261 §20.10)
  CHECK(parse_name_addr_list("*")->front().uri.opaque == "*");
  CHECK_FALSE(parse_name_addr_list("<sip:a@b>, <oops").has_value());
}

TEST_CASE("Via: sent-protocol, sent-by and parameters (RFC 3261 §20.42)", "[sip][values][via]") {
  auto v = parse_via("SIP/2.0/UDP pc33.atlanta.example.com:5066;branch=z9hG4bK776asdhds;rport, "
                     "SIP / 2.0 / TCP [2001:db8::9]:5060 ;received=192.0.2.1");
  REQUIRE(v.has_value());
  REQUIRE(v->size() == 2);
  CHECK((*v)[0].protocol == "SIP/2.0/UDP");
  CHECK((*v)[0].host == "pc33.atlanta.example.com");
  CHECK((*v)[0].port == "5066");
  CHECK((*v)[0].params.size() == 2);
  CHECK((*v)[1].protocol == "SIP/2.0/TCP");  // LWS around "/" removed (SLASH = SWS "/" SWS)
  CHECK((*v)[1].host == "[2001:db8::9]");
  CHECK((*v)[1].host_kind == HostKind::ipv6);
  CHECK(render_via((*v)[0]) == "SIP/2.0/UDP pc33.atlanta.example.com:5066;branch=z9hG4bK776asdhds;rport");
  CHECK_FALSE(parse_via("SIP/2.0 pc33.example.com").has_value());
  CHECK_FALSE(parse_via("SIP/2.0/UDP").has_value());
  CHECK_FALSE(parse_via("SIP/2.0/UDP host:99999").has_value());
}

TEST_CASE("Call-ID and CSeq", "[sip][values]") {
  CHECK(parse_call_id("a84b4c76e66710@pc33.atlanta.example.com") ==
        "a84b4c76e66710@pc33.atlanta.example.com");
  CHECK(parse_call_id("f81d4fae-7dec-11d0-a765-00a0c91e6bf6") == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
  CHECK_FALSE(parse_call_id("a b").has_value());
  CHECK_FALSE(parse_call_id("a@b@c").has_value());
  CHECK_FALSE(parse_call_id("").has_value());
  auto c = parse_cseq("314159 INVITE");
  REQUIRE(c.has_value());
  CHECK(c->number == "314159");
  CHECK(c->method == "INVITE");
  CHECK_FALSE(parse_cseq("INVITE 1").has_value());
  CHECK_FALSE(parse_cseq("12345678901 INVITE").has_value());  // > 2^31 (RFC 3261 §8.1.1.5)
}

TEST_CASE("credentials and challenges (RFC 3261 §20.7, RFC 7616, RFC 3310)", "[sip][values][auth]") {
  auto a = parse_auth("Digest username=\"alice@ims.example.net\", realm=\"ims.example.net\", "
                      "nonce=\"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==\", uri=\"sip:ims.example.net\", "
                      "response=\"6629fae49393a05397450978507c4ef1\", algorithm=AKAv1-MD5, "
                      "qop=auth, nc=00000001, cnonce=\"0a4f113b\"");
  REQUIRE(a.has_value());
  CHECK(a->scheme == "Digest");
  REQUIRE(a->params.size() == 9);
  CHECK(a->params[0].name == "username");
  CHECK(a->params[0].quoted);
  CHECK(a->params[0].value == "alice@ims.example.net");
  CHECK(a->params[5].name == "algorithm");
  CHECK_FALSE(a->params[5].quoted);
  CHECK(render_auth(*a).starts_with("Digest username=\"alice@ims.example.net\", realm="));
  auto ch = parse_auth("Digest realm=\"ims.example.net\", nonce=\"abc\", qop=\"auth,auth-int\", "
                       "algorithm=AKAv1-MD5, ik=\"00112233445566778899aabbccddeeff\"");
  REQUIRE(ch.has_value());
  CHECK(ch->params[2].value == "auth,auth-int");
  CHECK_FALSE(parse_auth("Digest").has_value());
  CHECK_FALSE(parse_auth("Digest realm=").has_value());
  CHECK_FALSE(parse_auth("Digest realm=\"x\" nonce=\"y\"").has_value());  // missing comma
}

TEST_CASE("security mechanisms (RFC 3329 §2.2)", "[sip][values][security]") {
  auto s = parse_items("ipsec-3gpp; alg=hmac-sha-1-96; spi-c=23456789; spi-s=12345678; "
                       "port-c=2468; port-s=1357, digest;d-alg=md5;q=0.1",
                       HeadKind::token, true);
  REQUIRE(s.has_value());
  REQUIRE(s->size() == 2);
  CHECK((*s)[0].value == "ipsec-3gpp");
  CHECK((*s)[0].params.size() == 5);
  CHECK((*s)[0].params[1].name == "spi-c");
  CHECK((*s)[0].params[1].value == "23456789");
  CHECK(render_item((*s)[1]) == "digest;d-alg=md5;q=0.1");
}

TEST_CASE("P-Access-Network-Info (RFC 7315 §5.4)", "[sip][values][pani]") {
  auto p = parse_items("3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234151D0FCE11; network-provided",
                       HeadKind::token, true);
  REQUIRE(p.has_value());
  REQUIRE(p->size() == 1);
  CHECK((*p)[0].value == "3GPP-E-UTRAN-FDD");
  CHECK((*p)[0].params[0].value == "234151D0FCE11");
  CHECK_FALSE((*p)[0].params[1].value.has_value());
  auto q = parse_items("IEEE-802.11; i-wlan-node-id=\"ffeeddccbbaa\"", HeadKind::token, true);
  REQUIRE(q.has_value());
  CHECK((*q)[0].params[0].quoted);
}

TEST_CASE("Warning (RFC 3261 §20.43)", "[sip][values][warning]") {
  auto w = parse_warning("307 isi.edu \"Session parameter 'foo' not understood\", "
                         "301 [2001:db8::1]:5060 \"x\", 399 pseudo \"\"");
  REQUIRE(w.has_value());
  REQUIRE(w->size() == 3);
  CHECK((*w)[0].code == "307");
  CHECK((*w)[0].agent == "isi.edu");
  CHECK((*w)[0].text == "Session parameter 'foo' not understood");
  CHECK((*w)[1].agent == "[2001:db8::1]:5060");
  CHECK(render_warning((*w)[2]) == "399 pseudo \"\"");
  CHECK_FALSE(parse_warning("30 a \"b\"").has_value());
  CHECK_FALSE(parse_warning("307 a b").has_value());
}

TEST_CASE("Reason (RFC 3326 §2)", "[sip][values][reason]") {
  auto r = parse_items("SIP ;cause=200 ;text=\"Call completed elsewhere\", Q.850;cause=16",
                       HeadKind::token, true);
  REQUIRE(r.has_value());
  REQUIRE(r->size() == 2);
  CHECK((*r)[0].value == "SIP");
  CHECK((*r)[0].params[1].name == "text");
  CHECK((*r)[1].value == "Q.850");
}

TEST_CASE("Date (RFC 3261 §20.17, rfc1123-date)", "[sip][values][date]") {
  auto d = parse_date("Sat, 13 Nov 2010 23:29:00 GMT");
  REQUIRE(d.has_value());
  CHECK(*d == 1289690940);
  CHECK(render_date(*d) == "Sat, 13 Nov 2010 23:29:00 GMT");
  CHECK(render_date(*d - 86400 * 30) == "Thu, 14 Oct 2010 23:29:00 GMT");
  CHECK_FALSE(parse_date("Sat, 13 Nov 2010 23:29:00 CET").has_value());
  CHECK_FALSE(parse_date("Sat, 31 Feb 2010 23:29:00 GMT").has_value());
  CHECK_FALSE(parse_date("13 Nov 2010 23:29:00 GMT").has_value());
}

TEST_CASE("Event, media types, numbers, session ids and token lists", "[sip][values]") {
  auto e = parse_items("conference;id=8d2a", HeadKind::token, false);
  REQUIRE(e.has_value());
  CHECK((*e)[0].value == "conference");
  CHECK(parse_items("poc.settings", HeadKind::token, false).has_value());
  auto m = parse_items("multipart/mixed;boundary=\"unique-boundary-1\"", HeadKind::media_type, false);
  REQUIRE(m.has_value());
  CHECK((*m)[0].value == "multipart/mixed");
  CHECK((*m)[0].params[0].value == "unique-boundary-1");
  CHECK_FALSE(parse_items("multipart", HeadKind::media_type, false).has_value());
  auto n = parse_items("1800;refresher=uac", HeadKind::number, false);
  REQUIRE(n.has_value());
  CHECK((*n)[0].value == "1800");
  CHECK_FALSE(parse_items("12a", HeadKind::number, false).has_value());
  auto s = parse_items("ab30317f1a784dc48ff824d0d3715d86;remote=00000000000000000000000000000000",
                       HeadKind::session_id, false);
  REQUIRE(s.has_value());
  CHECK_FALSE(parse_items("AB30317F1A784DC48FF824D0D3715D86", HeadKind::session_id, false).has_value());
  auto t = parse_items("100rel, timer ,replaces", HeadKind::token, true);
  REQUIRE(t.has_value());
  CHECK(t->size() == 3);
  CHECK_FALSE(parse_items("a, b", HeadKind::token, false).has_value());  // not a list header
  CHECK(parse_items("", HeadKind::token, true)->empty());  // e.g. an empty Supported
}

TEST_CASE("Retry-After (RFC 3261 §20.33)", "[sip][values]") {
  auto r = parse_retry_after("120 (I'm in a (long) meeting);duration=3600");
  REQUIRE(r.has_value());
  CHECK(r->seconds == "120");
  CHECK(r->comment == "I'm in a (long) meeting");
  CHECK(r->params.size() == 1);
  CHECK_FALSE(parse_retry_after("soon").has_value());
  CHECK_FALSE(parse_retry_after("120 (unbalanced").has_value());
}
