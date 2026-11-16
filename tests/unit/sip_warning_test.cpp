// SPDX-License-Identifier: GPL-3.0-or-later
//
// Feature 008 (FR-006): the warn-text of an MCX Warning (warn-code 399, TS 24.379 §4.4.1,
// TS 24.281 §4.4.1, TS 24.282 §4.9.1) is kept verbatim when it is exactly an entry of the
// warning-text tables (TS 24.379 §4.4.2, TS 24.281 §4.4.2, TS 24.282 §4.9.2); any other text is
// blanked to its 3-digit code as before (002 D2). The warn-agent is pseudonymised either way.
#include "pipeline/mapper_adapter.hpp"
#include "policy/sip_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 5 + 1);
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

  std::string warning(const std::string& value) {
    const std::string m = "SIP/2.0 403 Forbidden\r\nVia: SIP/2.0/UDP 10.1.1.1;branch=z9hG4bK1\r\n"
                          "From: <sip:a@example.net>;tag=1\r\nTo: <sip:b@example.net>;tag=2\r\nCall-ID: c1\r\n"
                          "CSeq: 1 MESSAGE\r\nWarning: " + value + "\r\nContent-Length: 0\r\n\r\n";
    auto r = rewrite_message(m, Transport::datagram, ctx);
    REQUIRE(r.has_value());
    const auto at = r->bytes.find("\r\nWarning: ");
    REQUIRE(at != std::string::npos);
    const auto end = r->bytes.find("\r\n", at + 2);
    return r->bytes.substr(at + 11, end - at - 11);
  }
  std::string dom(const char* d) { return *p.domain(d); }
  bool removed(const std::string& v) const {
    return std::any_of(counters.removed_values.begin(), counters.removed_values.end(),
                       [&](const auto& x) { return x.second == v; });
  }
};
}  // namespace

TEST_CASE("a table text of each standard is kept verbatim after warn-code 399", "[sip][warning]") {
  Fixture f;
  const std::string agent = f.dom("mcdata-server.example.net");
  for (const auto& text : {std::string("200 user not authorised to transmit data"),                    // TS 24.282
                                 std::string("229 one-to-one MCData communication not authorised to the targeted user"),
                                 std::string("106 user not authorised to join chat group"),                  // TS 24.379
                                 std::string("200 user not authorised to trigger an emergency remote floor request"),
                                 std::string("100 function not allowed due to group definition"),            // expanded
                                 std::string("100 function not allowed due to pre-established session not supported")}) {
    INFO(text);
    CHECK(f.warning("399 mcdata-server.example.net \"" + text + "\"") == "399 " + agent + " \"" + text + "\"");
    CHECK_FALSE(f.removed(text));
  }
}

TEST_CASE("any other warn-text is blanked to its code, and is a removed value", "[sip][warning]") {
  Fixture f;
  const std::string agent = f.dom("pcscf.example.net");
  for (const auto& text : {std::string("200 user not authorised to transmit data at site CANARY-A1"),
                                 std::string("200 User not authorised to transmit data"),     // not exact
                                 std::string("110 MCPTT group is not affiliated"),           // another text
                                 std::string("301 interworking value without a text"),       // 301-350: no entry
                                 std::string("100 function not allowed due to CANARY-reason"),  // free reason
                                 std::string("200  user not authorised to transmit data")}) {   // two spaces
    INFO(text);
    CHECK(f.warning("399 pcscf.example.net \"" + text + "\"") == "399 " + agent + " \"" + text.substr(0, 3) + "\"");
    CHECK(f.removed(text));
  }
  // Free text without a code is blanked entirely, as before.
  CHECK(f.warning("399 pcscf.example.net \"Bob's phone is broken\"") == "399 " + agent + " \"\"");
}

TEST_CASE("a table text after another warn-code is blanked", "[sip][warning]") {
  Fixture f;
  const std::string agent = f.dom("pcscf.example.net");
  CHECK(f.warning("307 pcscf.example.net \"200 user not authorised to transmit data\"") ==
        "307 " + agent + " \"200\"");
}

TEST_CASE("the warning_texts rule data is validated", "[sip][warning][rules]") {
  const auto load = [](const std::string& entries) {
    const std::string text = "ruleset: mcxanon-sip\nversion: 1.0.0\nwarning_texts:\n" + entries;
    std::vector<RuleFile> files{RuleFile{"sip-warning-texts.yaml", text}};
    return load_sip_ruleset(files);
  };
  const std::string src = R"(source: {spec: TS 24.282, version: "19.6.0", clause: "4.9.2"})";
  auto ok = load("  - {warn_code: 399, text: \"200 user not authorised to transmit data\", " + src + "}\n");
  REQUIRE(ok.has_value());
  CHECK(ok->kept_warning_text("399", "200 user not authorised to transmit data"));
  CHECK_FALSE(ok->kept_warning_text("399", "200 user not authorised"));
  CHECK_FALSE(ok->kept_warning_text("307", "200 user not authorised to transmit data"));
  CHECK_FALSE(load("  - {warn_code: 39, text: \"200 x\", " + src + "}\n").has_value());            // code
  CHECK_FALSE(load("  - {warn_code: 399, text: \"20 x\", " + src + "}\n").has_value());            // text code
  CHECK_FALSE(load("  - {warn_code: 399, text: \"200\", " + src + "}\n").has_value());             // no text
  CHECK_FALSE(load("  - {warn_code: 399, text: \"200 x\"}\n").has_value());                        // source
  CHECK_FALSE(load("  - {warn_code: 399, text: \"200 x\", " + src + "}\n  - {warn_code: 399, text: \"200 x\", " +
                   src + "}\n").has_value());                                                       // duplicate
  CHECK_FALSE(load("  - {warn_code: 399, text: \"200 x\", note: y, " + src + "}\n").has_value());  // key
}
