// SPDX-License-Identifier: GPL-3.0-or-later
//
// SIP message recognition and framing (RFC 3261 §7, §18.3, §25).
#include "sip/limits.hpp"
#include "sip/message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
std::string_view at(std::string_view msg, Span s) { return msg.substr(s.off, s.len); }

const std::string kInvite =
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: Bob <sip:bob@biloxi.example.com>\r\n"
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 4\r\n"
    "\r\n"
    "v=0\n";
}  // namespace

TEST_CASE("request and status lines are recognised on any content", "[sip][message]") {
  CHECK(is_start_line(kInvite));
  CHECK(is_start_line("SIP/2.0 200 OK\r\n"));
  CHECK(is_start_line("SIP/2.0 100 \r\n"));                        // empty reason phrase
  CHECK(is_start_line("FOOBAR sip:x@example.net SIP/2.0\r\n"));  // any token method (§7.1)
  CHECK(is_start_line("REGISTER sips:example.net SIP/2.0\r\n"));
  CHECK_FALSE(is_start_line("GET / HTTP/1.1\r\n"));
  CHECK_FALSE(is_start_line("INVITE sip:x SIP/3.0\r\n"));
  CHECK_FALSE(is_start_line("SIP/2.0 20 OK\r\n"));
  CHECK_FALSE(is_start_line("SIP/2.0 2000 OK\r\n"));
  CHECK_FALSE(is_start_line("INVITE  sip:x SIP/2.0\r\n"));  // two spaces
  CHECK_FALSE(is_start_line("INV(TE sip:x SIP/2.0\r\n"));   // not a token
  CHECK_FALSE(is_start_line(std::string("\x00\x01\x02\x03", 4)));
  CHECK_FALSE(is_start_line(""));
}

TEST_CASE("a request is parsed into start line, headers and body", "[sip][message]") {
  auto m = parse_message(kInvite, Transport::datagram);
  REQUIRE(m.has_value());
  CHECK(m->kind == MessageKind::request);
  CHECK(at(kInvite, m->method) == "INVITE");
  CHECK(at(kInvite, m->request_uri) == "sip:bob@biloxi.example.com");
  CHECK(at(kInvite, m->start_line) == "INVITE sip:bob@biloxi.example.com SIP/2.0");
  REQUIRE(m->headers.size() == 8);
  CHECK(at(kInvite, m->headers[0].name) == "Via");
  CHECK(at(kInvite, m->headers[0].value) ==
        "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds");
  CHECK(at(kInvite, m->headers[0].line) ==
        "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n");
  CHECK(at(kInvite, m->headers[7].name) == "Content-Length");
  CHECK(at(kInvite, m->body) == "v=0\n");
  CHECK(m->trailing.len == 0);
}

TEST_CASE("a response is parsed with its status code and reason", "[sip][message]") {
  const std::string r = "SIP/2.0 486 Busy Here\r\nCall-ID: x\r\nContent-Length: 0\r\n\r\n";
  auto m = parse_message(r, Transport::datagram);
  REQUIRE(m.has_value());
  CHECK(m->kind == MessageKind::response);
  CHECK(m->status_code == 486);
  CHECK(at(r, m->reason) == "Busy Here");
  CHECK(m->body.len == 0);
}

TEST_CASE("header framing: folding, spacing, repeated and compact headers", "[sip][message]") {
  // §7.3.1: a header may be folded onto continuation lines starting with whitespace, and
  // whitespace around the colon is allowed.
  const std::string msg =
      "OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n"
      "Subject:   I know you're there,\r\n"
      "   pick up the phone\r\n"
      "\t and talk to me!\r\n"
      "v: SIP/2.0/UDP a.example.com;branch=z9hG4bK1\r\n"
      "Route  : <sip:p1.example.com;lr>\r\n"
      "Route: <sip:p2.example.com;lr>, <sip:p3.example.com;lr>\r\n"
      "l: 0\r\n"
      "\r\n";
  auto m = parse_message(msg, Transport::datagram);
  REQUIRE(m.has_value());
  REQUIRE(m->headers.size() == 5);
  CHECK(at(msg, m->headers[0].name) == "Subject");
  CHECK(m->headers[0].unfolded == "I know you're there, pick up the phone and talk to me!");
  CHECK(at(msg, m->headers[0].line).ends_with("talk to me!\r\n"));
  CHECK(at(msg, m->headers[1].name) == "v");  // compact form, spelling kept
  CHECK(at(msg, m->headers[2].name) == "Route");
  CHECK(m->headers[2].unfolded == "<sip:p1.example.com;lr>");
  CHECK(m->headers[3].unfolded == "<sip:p2.example.com;lr>, <sip:p3.example.com;lr>");
  CHECK(at(msg, m->headers[4].name) == "l");
  CHECK(m->content_length == 0);
}

TEST_CASE("the body is framed by Content-Length, also in compact form", "[sip][message]") {
  const std::string msg = "MESSAGE sip:x@example.net SIP/2.0\r\nl: 5\r\n\r\nhello";
  auto m = parse_message(msg, Transport::datagram);
  REQUIRE(m.has_value());
  CHECK(at(msg, m->body) == "hello");
  // RFC 3261 §18.3 (UDP): without Content-Length the body runs to the end of the datagram.
  const std::string no_cl = "MESSAGE sip:x@example.net SIP/2.0\r\nCall-ID: a\r\n\r\nhello";
  auto n = parse_message(no_cl, Transport::datagram);
  REQUIRE(n.has_value());
  CHECK(at(no_cl, n->body) == "hello");
  CHECK_FALSE(n->content_length.has_value());
}

TEST_CASE("UDP bytes after the body are reported as trailing", "[sip][message]") {
  // §18.3: "additional bytes in the transport packet beyond the end of the body ... MUST be
  // discarded".
  const std::string msg = "MESSAGE sip:x@example.net SIP/2.0\r\nContent-Length: 2\r\n\r\nhiEXTRA";
  auto m = parse_message(msg, Transport::datagram);
  REQUIRE(m.has_value());
  CHECK(at(msg, m->body) == "hi");
  CHECK(at(msg, m->trailing) == "EXTRA");
}

TEST_CASE("a Content-Length beyond the available bytes is malformed", "[sip][message]") {
  const std::string msg = "MESSAGE sip:x@example.net SIP/2.0\r\nContent-Length: 50\r\n\r\nhi";
  auto m = parse_message(msg, Transport::datagram);
  REQUIRE_FALSE(m.has_value());
  CHECK(m.error().kind == Failure::malformed);
  // On a stream it is incomplete: more bytes may follow.
  auto s = parse_message(msg, Transport::stream);
  REQUIRE_FALSE(s.has_value());
  CHECK(s.error().kind == Failure::incomplete);
}

TEST_CASE("broken framing and broken Content-Length are malformed", "[sip][message]") {
  for (const std::string& bad : {
           std::string("INVITE sip:x SIP/2.0\r\nVia: a\r\n"),                    // no empty line
           std::string("INVITE sip:x SIP/2.0\r\nNoColonHere\r\n\r\n"),           // no colon
           std::string("INVITE sip:x SIP/2.0\r\nBad Name: x\r\n\r\n"),           // not a token
           std::string("INVITE sip:x SIP/2.0\r\n: empty-name\r\n\r\n"),
           std::string("INVITE sip:x SIP/2.0\r\n continuation-first: x\r\n\r\n"),
           std::string("INVITE sip:x SIP/2.0\r\nContent-Length: abc\r\n\r\n"),
           std::string("INVITE sip:x SIP/2.0\r\nContent-Length: 1\r\nl: 2\r\n\r\nab"),
           std::string("INVITE sip:x SIP/2.0\r\nVia: a\nCall-ID: b\r\n\r\n"),   // bare LF
           std::string("INVITE sip:x SIP/2.0\r\nContent-Length: 99999999999999999999\r\n\r\n"),
       }) {
    INFO(bad);
    auto m = parse_message(bad, Transport::datagram);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().kind == Failure::malformed);
  }
  auto not_sip = parse_message("HTTP/1.1 200 OK\r\n\r\n", Transport::datagram);
  REQUIRE_FALSE(not_sip.has_value());
  CHECK(not_sip.error().kind == Failure::not_sip);
}

TEST_CASE("every bound of limits.hpp is enforced", "[sip][message][bounds]") {
  const std::string start = "MESSAGE sip:x@example.net SIP/2.0\r\n";
  SECTION("message size") {
    const std::string body(kMaxMessageBytes, 'x');
    const std::string msg = start + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    auto m = parse_message(msg, Transport::datagram);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().kind == Failure::malformed);
  }
  SECTION("header line length") {
    const std::string msg = start + "Subject: " + std::string(kMaxHeaderLineBytes, 'a') + "\r\n\r\n";
    auto m = parse_message(msg, Transport::datagram);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().kind == Failure::malformed);
  }
  SECTION("header count") {
    std::string msg = start;
    for (std::size_t i = 0; i <= kMaxHeaders; ++i) msg += "Max-Forwards: 70\r\n";
    msg += "\r\n";
    auto m = parse_message(msg, Transport::datagram);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().kind == Failure::malformed);
    // One fewer is fine.
    std::string ok = start;
    for (std::size_t i = 0; i < kMaxHeaders; ++i) ok += "Max-Forwards: 70\r\n";
    ok += "\r\n";
    CHECK(parse_message(ok, Transport::datagram).has_value());
  }
  SECTION("stream message without Content-Length cannot be framed") {
    auto m = parse_message(start + "Call-ID: a\r\n\r\n", Transport::stream);
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().kind == Failure::malformed);
  }
  CHECK(kMaxParamsPerHeader == 1024);
  CHECK(kMaxQuotedBytes == 8 * 1024);
  CHECK(kMaxMultipartDepth == 4);
  CHECK(kMaxParts == 64);
}

TEST_CASE("stream framing finds message boundaries", "[sip][message][stream]") {
  const std::string a = "OPTIONS sip:x@example.net SIP/2.0\r\nContent-Length: 3\r\n\r\nabc";
  const std::string b = "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
  auto f = frame_stream(a + b);
  REQUIRE(f.has_value());
  CHECK(*f == a.size());
  auto partial = frame_stream(a.substr(0, 20));
  REQUIRE(partial.has_value());
  CHECK(*partial == 0);  // need more bytes
  auto body_partial = frame_stream(a.substr(0, a.size() - 1));
  REQUIRE(body_partial.has_value());
  CHECK(*body_partial == 0);
  auto junk = frame_stream("\x16\x03\x01\x02\x00 binary");
  REQUIRE_FALSE(junk.has_value());
}
