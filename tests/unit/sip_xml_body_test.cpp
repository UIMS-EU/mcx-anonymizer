// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SIP side of feature 003: bodies with handling `xml` go through
// Context::xml; without it they are emptied as in 002; multipart framing and Content-Length
// follow the rewritten bytes; an emptied XML part keeps the 002 I2 CRLF body.
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 3 + 1);
  return s;
}

SipRuleSet xml_rules() {
  auto rs = *load_embedded_sip_ruleset();
  for (auto& b : rs.bodies) {
    if (b.content_type == "application/vnd.3gpp.mcptt-info+xml") b.handling = BodyHandling::xml;
  }
  return rs;
}

struct Stub : XmlBodies {
  bool empty = false;
  std::string seen_charset, seen_type;
  std::size_t calls = 0;
  Result<XmlOutcome> rewrite(std::string_view ct, std::string_view charset, std::string_view, std::size_t,
                             Context&) override {
    ++calls;
    seen_charset = charset;
    seen_type = ct;
    if (empty) return XmlOutcome{false, {}, "malformed"};
    return XmlOutcome{true, "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>", {}};
  }
};

struct Fixture {
  SipRuleSet rules = xml_rules();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  SipCounters counters;
  Stub stub;
  Context ctx{rules, mapper, {}, counters};
};

const std::string kXml = "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><x>CANARY-XML</x></mcpttinfo>";
const std::string kSdp = "v=0\r\no=- 1 1 IN IP4 10.1.1.1\r\ns=-\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\nc=IN IP4 10.1.1.1\r\n";

std::string message(const std::string& ct, const std::string& body) {
  return "MESSAGE sip:x@example.net SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK1\r\n"
         "From: <sip:a@example.net>;tag=1\r\nTo: <sip:b@example.net>\r\nCall-ID: c1\r\nCSeq: 1 MESSAGE\r\n"
         "Content-Type: " + ct + "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

std::string body_of(const std::string& m) { return m.substr(m.find("\r\n\r\n") + 4); }

std::size_t content_length(const std::string& m) {
  const auto at = m.find("Content-Length: ");
  return std::stoul(m.substr(at + 16));
}
}  // namespace

TEST_CASE("an xml body without an attached rewriter is emptied as in 002", "[sip][xml]") {
  Fixture f;
  auto r = rewrite_message(message("application/vnd.3gpp.mcptt-info+xml", kXml), Transport::datagram, f.ctx);
  REQUIRE(r.has_value());
  CHECK(r->malformed == Malformed::none);
  CHECK(body_of(r->bytes).empty());
  CHECK(f.counters.bodies.at("application/vnd.3gpp.mcptt-info+xml").at("emptied") == 1);
}

TEST_CASE("an xml body goes through Context::xml with its charset", "[sip][xml]") {
  Fixture f;
  f.ctx.xml = &f.stub;
  auto r = rewrite_message(message("application/vnd.3gpp.mcptt-info+xml;charset=UTF-8", kXml), Transport::datagram, f.ctx);
  REQUIRE(r.has_value());
  CHECK(f.stub.calls == 1);
  CHECK(f.stub.seen_charset == "UTF-8");
  CHECK(f.stub.seen_type == "application/vnd.3gpp.mcptt-info+xml");
  const auto b = body_of(r->bytes);
  CHECK(b == "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>");
  CHECK(content_length(r->bytes) == b.size());
  CHECK(f.counters.bodies.at("application/vnd.3gpp.mcptt-info+xml").at("xml") == 1);
}

TEST_CASE("an emptied xml body leaves the message valid", "[sip][xml]") {
  Fixture f;
  f.ctx.xml = &f.stub;
  f.stub.empty = true;
  auto r = rewrite_message(message("application/vnd.3gpp.mcptt-info+xml", kXml), Transport::datagram, f.ctx);
  REQUIRE(r.has_value());
  CHECK(r->malformed == Malformed::none);
  CHECK(body_of(r->bytes).empty());
  CHECK(content_length(r->bytes) == 0);
  CHECK(f.counters.bodies.at("application/vnd.3gpp.mcptt-info+xml").at("emptied") == 1);
}

TEST_CASE("an xml multipart part is rewritten or emptied with the CRLF rule", "[sip][xml]") {
  const std::string mp = "--b1\r\nContent-Type: application/sdp\r\n\r\n" + kSdp + "\r\n--b1\r\n"
                         "Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + kXml + "\r\n--b1--\r\n";
  for (bool empty : {false, true}) {
    Fixture f;
    f.ctx.xml = &f.stub;
    f.stub.empty = empty;
    auto r = rewrite_message(message("multipart/mixed;boundary=b1", mp), Transport::datagram, f.ctx);
    REQUIRE(r.has_value());
    CHECK(r->malformed == Malformed::none);
    const auto b = body_of(r->bytes);
    CHECK(content_length(r->bytes) == b.size());
    CHECK(b.find("CANARY-XML") == std::string::npos);
    if (empty) {
      CHECK(b.find("mcptt-info+xml\r\n\r\n\r\n\r\n--") != std::string::npos);  // CRLF body (002 I2)
    } else {
      CHECK(b.find("<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>\r\n--") != std::string::npos);
    }
  }
}

