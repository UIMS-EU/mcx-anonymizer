// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sip::rewrite_header_value renders a header value as the SIP rewriter does inside a message
// (feature 007 reuses it for the 002 grammars of the HTTP rule set).
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

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
  sip::SipCounters counters;
  sip::Context ctx{rules, mapper, {}, counters};
  std::string message_value(const std::string& header) {
    const std::string msg = "REGISTER sip:example.org SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
                            "From: <sip:alice@example.org>;tag=1\r\nTo: <sip:alice@example.org>\r\nCall-ID: c1\r\n"
                            "CSeq: 1 REGISTER\r\n" + header + "\r\nContent-Length: 0\r\n\r\n";
    auto r = sip::rewrite_message(msg, sip::Transport::datagram, ctx);
    REQUIRE(r.has_value());
    const auto at = r->bytes.find(header.substr(0, header.find(':') + 2));
    REQUIRE(at != std::string::npos);
    const auto start = at + header.find(':') + 2;
    return r->bytes.substr(start, r->bytes.find("\r\n", start) - start);
  }
};

}  // namespace

TEST_CASE("rewrite_header_value matches the in-message rewriting", "[http][sip]") {
  Fixture f;
  const std::string v = "Digest username=\"alice@example.org\", realm=\"example.org\", nonce=\"abc123\", "
                        "uri=\"sip:example.org\", response=\"0123456789abcdef0123456789abcdef\", algorithm=MD5";
  const auto in_message = f.message_value("Authorization: " + v);
  auto alone = sip::rewrite_header_value(*f.rules.find_header("Authorization"), v, f.ctx);
  REQUIRE(alone.has_value());
  REQUIRE(alone->has_value());
  CHECK(**alone == in_message);
  CHECK((*alone)->find("abc123") == std::string::npos);
  CHECK((*alone)->find("alice") == std::string::npos);
}

TEST_CASE("rewrite_header_value removes HTTP grammars in the SIP rewriter", "[http][sip]") {
  Fixture f;
  SipHeaderRule r;
  r.name = "Cookie";
  r.grammar = SipGrammar::cookie;
  auto v = sip::rewrite_header_value(r, "a=b", f.ctx);
  REQUIRE(v.has_value());
  CHECK_FALSE(v->has_value());
}
