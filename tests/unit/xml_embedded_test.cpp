// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bodies embedded in a resource-lists entry URI (FR-014a, data-model § Embedded
// bodies, X7, P6): the hname "body" is URL-decoded, rewritten by the SIP body rewriter with the
// type of the Content-Type URI header (depth 1) and re-encoded; that header is rewritten by the
// 002 Content-Type rule, so a multipart boundary maps like the one in the body. Every failure
// removes the body and its Content-Type header and names the reason.
#include "pipeline/mapper_adapter.hpp"
#include "policy/xml_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"
#include "sip/uri.hpp"
#include "xml/counters.hpp"
#include "xml/sip_bodies.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 11 + 5);
  return s;
}

// RFC 3261 §25.1 hvalue escaping of everything but unreserved characters.
std::string esc(std::string_view v) {
  std::string out;
  const char* hex = "0123456789ABCDEF";
  for (const char ch : v) {
    const auto c = static_cast<unsigned char>(ch);
    if (std::isalnum(c) || std::string_view("-_.!~*'()").find(ch) != std::string_view::npos) {
      out.push_back(ch);
    } else {
      out += '%';
      out += hex[c >> 4];
      out += hex[c & 15];
    }
  }
  return out;
}

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  XmlRuleSet xml_rules = *load_embedded_xml_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters counters;
  xml::Counters xml_counters;
  xml::SipXmlBodies bodies{xml_rules, xml_counters};
  sip::Context ctx{rules, mapper, {}, counters, nullptr, &bodies};

  sip::EmbeddedUri entry(std::string_view v, std::size_t depth = 0) {
    auto r = sip::rewrite_entry_uri(v, ctx, depth);
    REQUIRE(r.has_value());
    return *r;
  }
  std::string uri(std::string_view v) { return **sip::rewrite_uri_text(v, ctx); }

  // The decoded value of hname `name` in the URI headers of `u`, or nullopt.
  static std::optional<std::string> hvalue(const std::string& u, std::string_view name) {
    const auto q = u.find('?');
    if (q == std::string::npos) return std::nullopt;
    std::string_view h = std::string_view(u).substr(q + 1);
    while (!h.empty()) {
      const auto amp = h.find('&');
      const auto item = h.substr(0, amp);
      const auto eq = item.find('=');
      if (eq != std::string_view::npos && item.substr(0, eq) == name) return sip::percent_decode(item.substr(eq + 1));
      if (amp == std::string_view::npos) break;
      h.remove_prefix(amp + 1);
    }
    return std::nullopt;
  }
};

const std::string kInfo =
    "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params><mcptt-calling-user-id type=\"Normal\">"
    "<mcpttURI>sip:alice@fire.example.net</mcpttURI></mcptt-calling-user-id></mcptt-Params></mcpttinfo>";
const std::string kSdp = "v=0\r\no=alice 2890844526 1 IN IP4 10.1.2.3\r\ns=-\r\nc=IN IP4 10.1.2.3\r\nt=0 0\r\n"
                         "m=audio 49170 RTP/AVP 0\r\n";
}  // namespace

TEST_CASE("an embedded mcptt-info body is rewritten and re-encoded", "[xml][embedded]") {
  Fixture f;
  const auto in = "sip:grp@fire.example.net?Content-Type=" + esc("application/vnd.3gpp.mcptt-info+xml") +
                  "&body=" + esc(kInfo);
  const auto e = f.entry(in);
  REQUIRE(e.uri.has_value());
  CHECK(e.outcome == "rewritten");
  CHECK(e.uri->starts_with(f.uri("sip:grp@fire.example.net") + "?"));
  CHECK(Fixture::hvalue(*e.uri, "Content-Type") == "application/vnd.3gpp.mcptt-info+xml");
  const auto body = Fixture::hvalue(*e.uri, "body");
  REQUIRE(body.has_value());
  CHECK(body->find(f.uri("sip:alice@fire.example.net")) != std::string::npos);
  CHECK(body->find("alice") == std::string::npos);
  CHECK(e.uri->find("alice") == std::string::npos);
}

TEST_CASE("an embedded SDP body and a multipart body keep one boundary pseudonym", "[xml][embedded]") {
  Fixture f;
  const auto sdp = f.entry("sip:grp@fire.example.net?Content-Type=application%2Fsdp&body=" + esc(kSdp));
  CHECK(sdp.outcome == "rewritten");
  const auto sbody = Fixture::hvalue(*sdp.uri, "body");
  REQUIRE(sbody.has_value());
  CHECK(sbody->find("o=alice") == std::string::npos);
  CHECK(sbody->starts_with("v=0\r\n"));

  const std::string mp = "--bnd42\r\nContent-Type: application/sdp\r\n\r\n" + kSdp +
                         "\r\n--bnd42\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n" + kInfo +
                         "\r\n--bnd42--\r\n";
  const auto m = f.entry("sip:grp@fire.example.net?Content-Type=" + esc("multipart/mixed;boundary=bnd42") +
                         "&body=" + esc(mp));
  CHECK(m.outcome == "rewritten");
  const auto ct = Fixture::hvalue(*m.uri, "Content-Type");
  const auto mb = Fixture::hvalue(*m.uri, "body");
  REQUIRE(ct.has_value());
  REQUIRE(mb.has_value());
  const auto bpos = ct->find("boundary=");
  REQUIRE(bpos != std::string::npos);
  const auto boundary = ct->substr(bpos + 9);
  CHECK(boundary != "bnd42");
  CHECK(mb->starts_with("--" + boundary + "\r\n"));
}

TEST_CASE("every embedded-body failure removes the body and its Content-Type", "[xml][embedded]") {
  Fixture f;
  const auto grp = f.uri("sip:grp@fire.example.net");
  struct Case {
    std::string headers;
    std::size_t depth;
    const char* outcome;
  };
  const std::string ct = "Content-Type=" + esc("application/vnd.3gpp.mcptt-info+xml");
  for (const Case& c : {Case{ct + "&body=%3Cmcpttinfo%G1", 0, "undecodable"},
                        Case{"body=" + esc(kInfo), 0, "unknown-type"},
                        Case{"Content-Type=application%2Fx-vendor&body=" + esc(kInfo), 0, "unknown-type"},
                        Case{ct + "&body=" + esc(kInfo), 1, "nested"},
                        Case{ct + "&body=" + esc("<mcpttinfo"), 0, "malformed"},
                        Case{ct + "&body=" + std::string(1048577, 'x'), 0, "limit"}}) {
    INFO(c.outcome);
    const auto e = f.entry("sip:grp@fire.example.net?" + c.headers, c.depth);
    CHECK(e.outcome == c.outcome);
    REQUIRE(e.uri.has_value());
    CHECK(*e.uri == grp);  // no URI header survives
  }
}

TEST_CASE("other URI headers follow 002 and a URI without body is a plain URI", "[xml][embedded]") {
  Fixture f;
  const auto grp = f.uri("sip:grp@fire.example.net");
  const auto e = f.entry("sip:grp@fire.example.net?Subject=secret&Content-Type=application%2Fsdp&body=" + esc(kSdp));
  CHECK(e.outcome == "rewritten");
  CHECK(e.uri->find("Subject") == std::string::npos);
  CHECK(e.uri->find("secret") == std::string::npos);
  const auto plain = f.entry("sip:grp@fire.example.net");
  CHECK(plain.outcome.empty());
  CHECK(*plain.uri == grp);
}
