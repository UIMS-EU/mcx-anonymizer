// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP/1.1 heads and body framing (RFC 9112 §2-§7; feature 007).
#include "http/message.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon::http;

TEST_CASE("http message: start lines", "[http][message]") {
  CHECK(is_start("GET / HTTP/1.1\r\n") == true);
  CHECK(is_start("HTTP/1.1 200 OK\r\n") == true);
  CHECK(is_start("HTTP/1.1 204\r\n") == true);
  CHECK(is_start("INVITE sip:a@b SIP/2.0\r\n") == false);
  CHECK(is_start("SIP/2.0 200 OK\r\n") == false);
  CHECK(is_start("\x16\x03\x01") == false);
  CHECK_FALSE(is_start("GET /x HT").has_value());
  CHECK(is_start("PRI * HTTP/2.0\r\n") == false);
  CHECK(is_preface("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nxx") == true);
  CHECK_FALSE(is_preface("PRI * H").has_value());
}

TEST_CASE("http message: heads parse strictly", "[http][message]") {
  Head h;
  REQUIRE(parse_head("GET /a HTTP/1.1\r\nHost: x\r\nX: y \r\n\r\nbody", h) == Parse::ok);
  CHECK(h.request);
  CHECK(h.method == "GET");
  CHECK(h.fields.size() == 2);
  CHECK(h.fields[1].value == "y");
  CHECK(h.length == 35);
  CHECK(parse_head("GET /a HTTP/1.1\r\nHost: x\r\n", h) == Parse::more);
  CHECK(parse_head("GET /a HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", h) == Parse::bad);
  CHECK(parse_head("GET /a HTTP/1.1\nHost: x\n\n", h) == Parse::bad);
  CHECK(parse_head("GET /a HTTP/1.1\r\nBad Name: x\r\n\r\n", h) == Parse::bad);
  CHECK(parse_head("HTTP/1.1 599 X\r\n\r\n", h) == Parse::ok);
  CHECK(parse_head("HTTP/1.1 999 X\r\n\r\n", h) == Parse::bad);
  CHECK(parse_head("HTTP/1.1 099 X\r\n\r\n", h) == Parse::bad);
}

TEST_CASE("http message: body length by RFC 9112 §6.3", "[http][message]") {
  Head h;
  REQUIRE(parse_head("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "GET").kind == BodyPlan::Kind::length);
  CHECK(plan_body(h, "HEAD").kind == BodyPlan::Kind::none);
  REQUIRE(parse_head("HTTP/1.1 200 OK\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "GET").kind == BodyPlan::Kind::to_close);
  CHECK(plan_body(h, "CONNECT").connect_tunnel);
  REQUIRE(parse_head("HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "GET").kind == BodyPlan::Kind::none);
  REQUIRE(parse_head("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "").kind == BodyPlan::Kind::chunked);
  REQUIRE(parse_head("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "").kind == BodyPlan::Kind::bad);
  REQUIRE(parse_head("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "").kind == BodyPlan::Kind::bad);
  REQUIRE(parse_head("POST / HTTP/1.1\r\n\r\n", h) == Parse::ok);
  CHECK(plan_body(h, "").kind == BodyPlan::Kind::none);
}

TEST_CASE("http message: chunked bodies", "[http][message]") {
  const auto d = dechunk("5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\nNEXT", 1000);
  REQUIRE(d.kind == Dechunked::Kind::done);
  CHECK(d.data == "hello world");
  CHECK(d.encoded == 40);
  CHECK(dechunk("5\r\nhel", 1000).kind == Dechunked::Kind::more);
  CHECK(dechunk("5\r\nhelloXX0\r\n\r\n", 1000).kind == Dechunked::Kind::bad);
  CHECK(dechunk("zz\r\n", 1000).kind == Dechunked::Kind::bad);
  CHECK(dechunk("fffff\r\n", 1000).kind == Dechunked::Kind::over);
  const auto c = chunk_at("10\r\n");
  CHECK(c.kind == Chunk::Kind::data);
  CHECK(c.size == 16);
  CHECK(reason_phrase(404) == "Not Found");
  CHECK(reason_phrase(599).empty());
}
