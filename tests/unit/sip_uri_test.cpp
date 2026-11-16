// SPDX-License-Identifier: GPL-3.0-or-later
//
// SIP, SIPS and tel URIs (RFC 3261 §19.1, §25.1; RFC 3966 §3) and name-addr.
#include "sip/uri.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon::sip;

TEST_CASE("a SIP URI is split into its components", "[sip][uri]") {
  auto u = parse_uri("sip:alice:secret@atlanta.example.com:5060;transport=tcp;lr?subject=project");
  REQUIRE(u.has_value());
  CHECK(u->kind == Scheme::sip);
  CHECK(u->user == "alice");
  CHECK(u->had_password);
  CHECK(u->host == "atlanta.example.com");
  CHECK(u->host_kind == HostKind::domain);
  CHECK(u->port == "5060");
  REQUIRE(u->params.size() == 2);
  CHECK(u->params[0].name == "transport");
  CHECK(u->params[0].value == "tcp");
  CHECK(u->params[1].name == "lr");
  CHECK_FALSE(u->params[1].value.has_value());
  CHECK(u->headers == "subject=project");
  // Rendering drops nothing by itself; the rewriter clears password and headers.
  Uri v = *u;
  v.had_password = false;
  v.headers.reset();
  CHECK(render_uri(v) == "sip:alice@atlanta.example.com:5060;transport=tcp;lr");
}

TEST_CASE("hosts: domain, IPv4 and bracketed IPv6", "[sip][uri]") {
  auto a = parse_uri("sips:[2001:db8::10]:5061");
  REQUIRE(a.has_value());
  CHECK(a->kind == Scheme::sips);
  CHECK(a->host == "[2001:db8::10]");
  CHECK(a->host_kind == HostKind::ipv6);
  CHECK(a->port == "5061");
  CHECK_FALSE(a->user.has_value());
  auto b = parse_uri("sip:bob@192.0.2.4");
  REQUIRE(b.has_value());
  CHECK(b->host_kind == HostKind::ipv4);
  auto c = parse_uri("SIP:Bob@Biloxi.Example.COM");  // scheme and host case-insensitive
  REQUIRE(c.has_value());
  CHECK(c->kind == Scheme::sip);
  CHECK(c->scheme == "SIP");
  CHECK(c->host == "Biloxi.Example.COM");
  CHECK(render_uri(*c) == "SIP:Bob@Biloxi.Example.COM");
  // RFC 3261 §25.1: a toplabel starts with ALPHA, so "1.2.3" is neither a host name nor an
  // IPv4 address; an octet above 255 is no IPv4 address either.
  CHECK_FALSE(parse_uri("sip:a@1.2.3").has_value());
  CHECK_FALSE(parse_uri("sip:a@10.0.0.256").has_value());
  CHECK(parse_uri("sip:a@pcscf1.ims.example.net.")->host_kind == HostKind::domain);
}

TEST_CASE("escaped user parts are kept as written and can be decoded", "[sip][uri]") {
  auto u = parse_uri("sip:%61lice%20n@example.net");
  REQUIRE(u.has_value());
  CHECK(u->user == "%61lice%20n");
  CHECK(percent_decode("%61lice%20n") == "alice n");
  CHECK(percent_decode("a%2") == "a%2");  // incomplete escape stays as is
  CHECK(percent_decode("%ff%00") == std::string("\xff\x00", 2));
}

TEST_CASE("telephone numbers in SIP and tel URIs", "[sip][uri][tel]") {
  auto s = parse_uri("sip:+48-601-234-567@ims.example.net;user=phone");
  REQUIRE(s.has_value());
  CHECK(s->user == "+48-601-234-567");
  REQUIRE(s->params.size() == 1);
  CHECK(s->params[0].name == "user");
  CHECK(s->params[0].value == "phone");
  auto g = parse_uri("tel:+48-601-234-567;verstat=TN-Validation-Passed");
  REQUIRE(g.has_value());
  CHECK(g->kind == Scheme::tel);
  CHECK(g->user == "+48-601-234-567");
  CHECK(g->host.empty());
  REQUIRE(g->params.size() == 1);
  CHECK(g->params[0].name == "verstat");
  auto l = parse_uri("tel:5550199;phone-context=ims.mnc001.mcc260.3gppnetwork.org");
  REQUIRE(l.has_value());
  CHECK(l->user == "5550199");
  CHECK(l->params[0].name == "phone-context");
  CHECK(render_uri(*l) == "tel:5550199;phone-context=ims.mnc001.mcc260.3gppnetwork.org");
  CHECK_FALSE(parse_uri("tel:;phone-context=x").has_value());
  CHECK_FALSE(parse_uri("tel:abc").has_value());
}

TEST_CASE("other schemes are recognised but not decomposed", "[sip][uri]") {
  auto u = parse_uri("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
  REQUIRE(u.has_value());
  CHECK(u->kind == Scheme::other);
  CHECK(u->scheme == "urn");
  CHECK(render_uri(*u) == "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
}

TEST_CASE("invalid URIs are rejected", "[sip][uri]") {
  for (const char* bad : {"", "sip:", "sip:a@", "sip:@example.net", "sip:[::1", "sip:a b@c",
                          "sip:a@b:port", "sip:a@b:99999999", "sip:a@b;=x", "sip:a@b;x=\"q\"",
                          "nocolon", "1sip:a@b", "sip:a@b>", "sip:a@-b-.example.net."}) {
    INFO(bad);
    CHECK_FALSE(parse_uri(bad).has_value());
  }
}

TEST_CASE("name-addr with quoted and token display names", "[sip][uri][name-addr]") {
  auto a = parse_name_addr("\"Alice Nowak\" <sip:alice@example.net>;tag=1928301774");
  REQUIRE(a.has_value());
  CHECK(a->display == "Alice Nowak");
  CHECK(a->display_quoted);
  CHECK(a->angle);
  CHECK(a->uri.user == "alice");
  REQUIRE(a->params.size() == 1);
  CHECK(a->params[0].name == "tag");
  CHECK(a->params[0].value == "1928301774");
  CHECK(render_name_addr(*a) == "\"Alice Nowak\" <sip:alice@example.net>;tag=1928301774");

  auto b = parse_name_addr("Alice  Nowak <sip:alice@example.net>");
  REQUIRE(b.has_value());
  CHECK(b->display == "Alice Nowak");  // token display name, linear whitespace folded
  CHECK_FALSE(b->display_quoted);

  auto c = parse_name_addr("<sip:alice@example.net;lr>");
  REQUIRE(c.has_value());
  CHECK_FALSE(c->display.has_value());
  CHECK(c->uri.params.size() == 1);
  CHECK(c->params.empty());

  // addr-spec without brackets: the parameters belong to the header (RFC 3261 §20.10).
  auto d = parse_name_addr("sip:alice@example.net;tag=88sja8x");
  REQUIRE(d.has_value());
  CHECK_FALSE(d->angle);
  CHECK(d->uri.params.empty());
  REQUIRE(d->params.size() == 1);
  CHECK(d->params[0].name == "tag");
  CHECK(render_name_addr(*d) == "sip:alice@example.net;tag=88sja8x");

  // Escapes inside a quoted display name (RFC 3261 §25.1 quoted-pair).
  auto e = parse_name_addr("\"A \\\"B\\\" \\\\C\" <sip:a@example.net>");
  REQUIRE(e.has_value());
  CHECK(e->display == "A \"B\" \\C");
  NameAddr f = *e;
  CHECK(render_name_addr(f) == "\"A \\\"B\\\" \\\\C\" <sip:a@example.net>");

  // Quoted header parameter values are unquoted, and re-quoted when rendered.
  auto g = parse_name_addr("<sip:a@example.net>;+sip.instance=\"<urn:gsma:imei:35209900-176148-0>\"");
  REQUIRE(g.has_value());
  REQUIRE(g->params.size() == 1);
  CHECK(g->params[0].quoted);
  CHECK(g->params[0].value == "<urn:gsma:imei:35209900-176148-0>");
  CHECK(render_name_addr(*g) ==
        "<sip:a@example.net>;+sip.instance=\"<urn:gsma:imei:35209900-176148-0>\"");
}

TEST_CASE("invalid name-addr is rejected", "[sip][uri][name-addr]") {
  for (const char* bad : {"<sip:a@example.net", "\"unterminated <sip:a@example.net>",
                          "Alice sip:a@example.net", "<>", "<sip:a@example.net> junk",
                          "<sip:a@example.net>;", "<sip:a@example.net>;tag=\"x"}) {
    INFO(bad);
    CHECK_FALSE(parse_name_addr(bad).has_value());
  }
}
