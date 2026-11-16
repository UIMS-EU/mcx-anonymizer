// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SDP attribute a=key-mgmt (RFC 4567 §3.1) with the MIKEY rewriter attached (spec
// FR-004 a).
#include "bytes/base64.hpp"
#include "mikey/decode.hpp"
#include "mikey/rewriter.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/mikey_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"
#include "sip/sdp.hpp"

#include "mikey_build.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>
#include <vector>

using namespace mcxanon;
using namespace mikey_test;

namespace {

Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 13 + 1);
  return s;
}

struct Fixture {
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  MikeyRuleSet rules = *load_embedded_mikey_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters sip_counters;
  mikey::Counters counters;
  mikey::Rewriter rewriter{rules, {}, counters};
  sip::Context ctx{sip_rules, mapper, {}, sip_counters, nullptr, nullptr, &rewriter};

  std::string sdp(const std::string& session_attr, const std::string& media_attr) {
    std::string s = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n";
    if (!session_attr.empty()) s += session_attr + "\r\n";
    s += "m=audio 4000 RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n";
    if (!media_attr.empty()) s += media_attr + "\r\n";
    return s;
  }
  std::string run(const std::string& body) {
    auto r = sip::rewrite_sdp(body, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
};

std::vector<std::string> key_mgmt_lines(const std::string& sdp) {
  std::vector<std::string> out;
  std::size_t p = 0;
  while ((p = sdp.find("a=key-mgmt:", p)) != std::string::npos) {
    const auto e = sdp.find("\r\n", p);
    out.push_back(sdp.substr(p, e - p));
    p = e;
  }
  return out;
}

std::string b64(const Bytes& b) { return base64::encode(b); }

}  // namespace

TEST_CASE("sdp key-mgmt: the mikey attribute is rewritten at session and media level", "[mikey][sdp]") {
  Fixture f;
  const std::string m = b64(private_call());
  const auto out = f.run(f.sdp("a=key-mgmt:mikey " + m, "a=key-mgmt: mikey " + m));
  const auto lines = key_mgmt_lines(out);
  REQUIRE(lines.size() == 2);
  CHECK(lines[0].rfind("a=key-mgmt:mikey ", 0) == 0);
  CHECK(lines[1].rfind("a=key-mgmt: mikey ", 0) == 0);  // 0*1SP preserved
  CHECK(out.find("a=key-mgmt:mikey") < out.find("m=audio"));
  CHECK(out.find("a=key-mgmt: mikey") > out.find("m=audio"));
  const auto value = lines[0].substr(std::string("a=key-mgmt:mikey ").size());
  auto dec = base64::decode(value);
  REQUIRE(dec.has_value());
  auto d = mikey::decode(dec->bytes, f.rules);
  REQUIRE(d.verdict == mikey::Verdict::sakke);
  const auto& i = std::get<mikey::Idr>(d.message->payloads[2].v);
  CHECK(std::string(i.data.begin(), i.data.end()) == **sip::rewrite_uri_text("sip:alice@example.org", f.ctx));
  CHECK(out.find("alice") == std::string::npos);
  CHECK(f.counters.carriers["sdp"].rewritten == 2);
  CHECK(f.sip_counters.sdp["a=key-mgmt"]["pseudonymise"] == 2);
}

TEST_CASE("sdp key-mgmt: other protocol identifiers and fallbacks are removed as in 002", "[mikey][sdp]") {
  Fixture f;
  const auto out = f.run(f.sdp("a=key-mgmt:other-proto AAAA", "a=key-mgmt:mikey not*base64"));
  CHECK(key_mgmt_lines(out).empty());
  CHECK(f.counters.carriers["sdp"].fallback["encoding"] == 1);
  CHECK(f.sip_counters.sdp["a=key-mgmt"]["remove"] == 2);
  // Valid base64 of something that is not MIKEY-SAKKE.
  Fixture g;
  Header h;
  h.data_type = 2;
  const Bytes pk = message(h, {t(1), sign(Bytes(16, 1), 0)});
  const auto out2 = g.run(g.sdp("a=key-mgmt:mikey " + b64(pk), ""));
  CHECK(key_mgmt_lines(out2).empty());
  CHECK(g.counters.carriers["sdp"].fallback["not-sakke"] == 1);
}

TEST_CASE("sdp key-mgmt: base64 padding style is reproduced", "[mikey][sdp]") {
  Fixture f;
  // A message whose length is not a multiple of 3 needs padding; the output keeps it.
  Bytes msg;
  for (std::size_t n = 273; msg.empty() || msg.size() % 3 == 0; ++n) {
    msg = message(Header{}, {t(1), rand(Bytes(16, 1)), idr(1, 1, text("sip:alice@example.org")),
                             sakke(Bytes(n, 0x53)), sign(Bytes(129, 1))});
  }
  const auto out = f.run(f.sdp("a=key-mgmt:mikey " + b64(msg), ""));
  const auto lines = key_mgmt_lines(out);
  REQUIRE(lines.size() == 1);
  const auto value = lines[0].substr(std::string("a=key-mgmt:mikey ").size());
  auto dec = base64::decode(value);
  REQUIRE(dec.has_value());
  CHECK(dec->layout.padded);
  CHECK((value.back() == '=') == (dec->bytes.size() % 3 != 0));
}
