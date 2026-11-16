// SPDX-License-Identifier: GPL-3.0-or-later
//
// Multipart bodies (RFC 2046 §5.1.1; FR-022, FR-023).
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/limits.hpp"
#include "sip/message.hpp"
#include "sip/multipart.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <regex>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 5 + 9);
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
};

const std::string kSdp = "v=0\r\no=alice 2890844526 2890842807 IN IP4 10.1.1.1\r\ns=-\r\nt=0 0\r\n"
                         "m=audio 5000 RTP/AVP 0\r\nc=IN IP4 10.1.1.1\r\n";
const std::string kXml = "<mcptt-info><mcpttURI>sip:secret.user@example.net</mcpttURI></mcptt-info>";

std::string invite(const std::string& content_type, const std::string& body) {
  return "INVITE sip:x@example.net SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK1\r\n"
         "From: <sip:a@example.net>;tag=1\r\nTo: <sip:b@example.net>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n"
         "Content-Type: " + content_type + "\r\nContent-Length: " + std::to_string(body.size()) +
         "\r\n\r\n" + body;
}

std::string two_parts(const std::string& b, const std::string& preamble = "", const std::string& epilogue = "") {
  return preamble + "--" + b + "\r\nContent-Type: application/sdp\r\n\r\n" + kSdp + "\r\n--" + b +
         "\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\nContent-Disposition: render;handling=optional\r\n"
         "X-Part-Secret: CANARY\r\n\r\n" + kXml + "\r\n--" + b + "--\r\n" + epilogue;
}
}  // namespace

TEST_CASE("multipart parsing per RFC 2046 §5.1.1", "[sip][multipart]") {
  const std::string body = two_parts("unique-boundary-1", "This is a preamble.\r\n", "epilogue text");
  auto m = parse_multipart(body, "unique-boundary-1");
  REQUIRE(m.has_value());
  REQUIRE(m->parts.size() == 2);
  CHECK(m->parts[0].headers.size() == 1);
  CHECK(m->parts[0].body == kSdp);
  CHECK(m->parts[1].headers.size() == 3);
  CHECK(m->parts[1].body == kXml);
  CHECK(m->preamble);
  CHECK(m->epilogue);
  CHECK_FALSE(parse_multipart(body, "other-boundary").has_value());
  CHECK_FALSE(parse_multipart("--b\r\nContent-Type: text/plain\r\n\r\nno close", "b").has_value());
  CHECK_FALSE(parse_multipart(body, std::string(71, 'x')).has_value());  // boundary of 1 to 70
  CHECK(is_boundary("unique-boundary-1"));
  CHECK(is_boundary("a b'c(d)+_,-./:=?"));
  CHECK_FALSE(is_boundary("ends with space "));
  CHECK_FALSE(is_boundary(""));
}

TEST_CASE("SDP parts are rewritten, other parts emptied with their headers kept", "[sip][multipart]") {
  Fixture f;
  const std::string in = invite("multipart/mixed;boundary=unique-boundary-1",
                                two_parts("unique-boundary-1", "preamble with secret.user\r\n", "epilogue secret.user"));
  auto r = rewrite_message(in, Transport::datagram, f.ctx);
  REQUIRE(r.has_value());
  const auto& o = r->bytes;
  CHECK(o.find("secret.user") == std::string::npos);  // preamble, epilogue and XML content gone
  CHECK(o.find("unique-boundary-1") == std::string::npos);
  CHECK(o.find("CANARY") == std::string::npos);           // unknown part header removed
  CHECK(o.find("10.1.1.1") == std::string::npos);
  std::smatch m;
  REQUIRE(std::regex_search(o, m, std::regex("Content-Type: multipart/mixed;boundary=(mcxb-[0-9a-f]{24})")));
  const std::string b = m[1].str();
  CHECK(b == *f.p.text(Category::boundary, "unique-boundary-1"));
  auto msg = parse_message(o, Transport::datagram);
  REQUIRE(msg.has_value());
  CHECK(*msg->content_length == msg->body.len);
  const std::string body = o.substr(msg->body.off);
  CHECK(body.starts_with("--" + b + "\r\nContent-Type: application/sdp\r\n\r\nv=0\r\no=u-"));
  CHECK(body.find("--" + b + "\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n"
                  "Content-Disposition: render;handling=optional\r\n\r\n\r\n\r\n--" + b + "--\r\n") !=
        std::string::npos);  // an emptied part keeps one CRLF (no content; FR-040)
  CHECK(body.ends_with("--" + b + "--\r\n"));
  auto parts = parse_multipart(body, b);
  REQUIRE(parts.has_value());
  CHECK(parts->parts.size() == 2);
  CHECK(parts->parts[1].body == "\r\n");
  CHECK(f.counters.bodies["multipart/mixed"]["multipart"] == 1);
  CHECK(f.counters.bodies["application/sdp"]["sdp"] == 1);
  CHECK(f.counters.bodies["application/vnd.3gpp.mcptt-info+xml"]["emptied"] == 1);
  // The same boundary in another message gets the same pseudonym.
  auto again = rewrite_message(in, Transport::datagram, f.ctx);
  REQUIRE(again.has_value());
  CHECK(again->bytes == o);
}

TEST_CASE("nested multipart up to the depth bound", "[sip][multipart]") {
  Fixture f;
  std::string body = kSdp;
  std::string type = "application/sdp";
  for (std::size_t depth = 0; depth < kMaxMultipartDepth; ++depth) {
    const std::string b = "b" + std::to_string(depth);
    body = "--" + b + "\r\nContent-Type: " + type + "\r\n\r\n" + body + "\r\n--" + b + "--\r\n";
    type = "multipart/mixed;boundary=" + b;
  }
  auto ok = rewrite_message(invite(type, body), Transport::datagram, f.ctx);
  REQUIRE(ok.has_value());
  CHECK(ok->malformed == Malformed::none);
  // One level deeper is malformed: the whole message is zeroed (FR-029).
  const std::string deeper = "--bx\r\nContent-Type: " + type + "\r\n\r\n" + body + "\r\n--bx--\r\n";
  auto bad = rewrite_message(invite("multipart/mixed;boundary=bx", deeper), Transport::datagram, f.ctx);
  REQUIRE(bad.has_value());
  CHECK(bad->malformed == Malformed::message);
}

TEST_CASE("part Content-Length is recomputed; too many parts are malformed", "[sip][multipart]") {
  Fixture f;
  const std::string body = "--b\r\nContent-Type: application/sdp\r\nContent-Length: " + std::to_string(kSdp.size()) +
                           "\r\n\r\n" + kSdp + "\r\n--b--\r\n";
  auto r = rewrite_message(invite("multipart/mixed;boundary=b", body), Transport::datagram, f.ctx);
  REQUIRE(r.has_value());
  std::smatch m;
  REQUIRE(std::regex_search(r->bytes, m, std::regex("\r\nContent-Length: ([0-9]+)\r\n\r\nv=0")));
  const auto at = r->bytes.find("\r\n\r\nv=0") + 4;
  const auto end = r->bytes.find("\r\n--", at);
  CHECK(std::stoul(m[1].str()) == end - at);
  std::string many;
  for (std::size_t i = 0; i <= kMaxParts; ++i) many += "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n";
  many += "--b--\r\n";
  auto t = rewrite_message(invite("multipart/mixed;boundary=b", many), Transport::datagram, f.ctx);
  REQUIRE(t.has_value());
  CHECK(t->malformed == Malformed::message);
}
