// SPDX-License-Identifier: GPL-3.0-or-later
//
// SDP rewriting with the embedded rule set (FR-018 to FR-021).
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/render.hpp"
#include "sip/sdp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <regex>
#include <sstream>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 13 + 2);
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

  std::string rewrite(const std::string& body) {
    auto r = rewrite_sdp(body, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
  std::vector<std::string> lines(const std::string& body) {
    std::vector<std::string> out;
    std::istringstream in(rewrite(body));
    for (std::string l; std::getline(in, l);) {
      if (!l.empty() && l.back() == '\r') l.pop_back();
      out.push_back(l);
    }
    return out;
  }
  std::string ip(const char* v4) { return **map_address_text(v4, mapper); }
};

std::string sdp(std::initializer_list<const char*> ls) {
  std::string s;
  for (const char* l : ls) s += std::string(l) + "\r\n";
  return s;
}

bool has(const std::vector<std::string>& v, const std::string& x) {
  return std::find(v.begin(), v.end(), x) != v.end();
}
bool any_starts(const std::vector<std::string>& v, const std::string& prefix) {
  return std::any_of(v.begin(), v.end(), [&](const std::string& l) { return l.starts_with(prefix); });
}
}  // namespace

TEST_CASE("SDP line rules (FR-018, D1)", "[sip][sdp]") {
  Fixture f;
  const auto out = f.lines(sdp({"v=0", "o=alice 2890844526 2890842807 IN IP4 10.47.16.5",
                                "s=Alice's private call", "i=speech", "u=http://www.example.com/a",
                                "e=alice@example.com", "p=+1 617 555-6011", "c=IN IP4 10.47.16.5",
                                "b=AS:64", "t=0 0", "k=clear:secret", "m=audio 49170 RTP/AVP 0 97",
                                "i=Alice's microphone", "a=rtpmap:97 AMR-WB/16000"}));
  CHECK(out[0] == "v=0");
  CHECK(std::regex_match(out[1], std::regex("o=u-[0-9a-f]{8} [1-9][0-9]{9} [0-9]{10} IN IP4 "
                                            "[0-9.]+")));
  CHECK(out[1].ends_with(" " + f.ip("10.47.16.5")));
  CHECK(has(out, "s=-"));
  CHECK(has(out, "i=speech"));
  CHECK_FALSE(any_starts(out, "i=Alice"));
  CHECK_FALSE(any_starts(out, "u="));
  CHECK_FALSE(any_starts(out, "e="));
  CHECK_FALSE(any_starts(out, "p="));
  CHECK_FALSE(any_starts(out, "k="));
  CHECK(has(out, "c=IN IP4 " + f.ip("10.47.16.5")));
  CHECK(has(out, "b=AS:64"));
  CHECK(has(out, "t=0 0"));
  CHECK(has(out, "m=audio 49170 RTP/AVP 0 97"));  // ports kept by default (FR-020)
  CHECK(has(out, "a=rtpmap:97 AMR-WB/16000"));
  CHECK(f.counters.sdp["o="]["pseudonymise"] == 1);
  CHECK(f.counters.sdp["s="]["blank"] == 1);
  CHECK(f.counters.sdp["i="]["keep"] == 1);
  CHECK(f.counters.sdp["i="]["remove"] == 1);
  CHECK(f.counters.sdp["k="]["remove"] == 1);
  CHECK(f.counters.sdp["m="]["pseudonymise"] == 1);
  // The fixed MCVideo values are kept too.
  CHECK(has(f.lines(sdp({"v=0", "o=- 1 1 IN IP4 0.0.0.0", "s=-", "t=0 0", "m=video 1 RTP/AVP 96",
                         "i=video component of MCVideo"})),
            "i=video component of MCVideo"));
}

TEST_CASE("o= keeps '-', and the version keeps its +1 steps (RFC 3264 §8)", "[sip][sdp]") {
  Fixture f;
  const auto offer = f.lines(sdp({"v=0", "o=- 2890844526 2890842807 IN IP4 10.0.0.1", "s=-", "t=0 0"}));
  const auto update = f.lines(sdp({"v=0", "o=- 2890844526 2890842808 IN IP4 10.0.0.1", "s=-", "t=0 0"}));
  CHECK(offer[1].starts_with("o=- "));
  const auto v = [](const std::string& o) {
    std::istringstream in(o);
    std::string a, id, ver;
    in >> a >> id >> ver;
    return std::stoull(ver);
  };
  CHECK(v(update[1]) == (v(offer[1]) + 1) % 10000000000ull);
  CHECK(offer[1].substr(0, 15) == update[1].substr(0, 15));  // same sess-id pseudonym
  // An FQDN in o= uses the domain mapping.
  const auto fq = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 pc33.atlanta.example.com", "s=-", "t=0 0"}));
  CHECK(fq[1].ends_with(".invalid"));
}

TEST_CASE("c= at session and media level, with /ttl and /n suffixes", "[sip][sdp]") {
  Fixture f;
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4 10.0.0.2", "t=0 0",
                                "m=audio 5000 RTP/AVP 0", "c=IN IP4 239.1.2.3/127/3",
                                "m=video 5002 RTP/AVP 96", "c=IN IP6 [::1]", "c=IN IP6 ff15::101/3"}));
  CHECK(has(out, "c=IN IP4 " + f.ip("10.0.0.2")));
  const auto mc = std::find_if(out.begin(), out.end(), [](auto& l) { return l.ends_with("/127/3"); });
  REQUIRE(mc != out.end());
  CHECK(*mc != "c=IN IP4 239.1.2.3/127/3");
  CHECK(mc->starts_with("c=IN IP4 2"));  // multicast stays multicast
  CHECK(std::any_of(out.begin(), out.end(),
                    [](auto& l) { return l.starts_with("c=IN IP6 ff15:") && l.ends_with("/3"); }));
  CHECK(f.counters.sdp["c="]["pseudonymise"] == 4);
}

TEST_CASE("sentinels: hold addresses, .invalid hosts, ports 0 and 9", "[sip][sdp]") {
  Fixture f;
  f.ctx.options.pseudonymise_ports = true;
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 0.0.0.0", "s=-", "c=IN IP4 0.0.0.0", "t=0 0",
                                "m=audio 0 RTP/AVP 0", "c=IN IP6 ::", "m=audio 9 RTP/AVP 0",
                                "c=IN IP4 mbms.invalid", "a=rtcp:9"}));
  CHECK(has(out, "o=- 1 1 IN IP4 0.0.0.0") == false);  // the sess-id is still pseudonymised
  CHECK(out[1].ends_with(" IN IP4 0.0.0.0"));
  CHECK(has(out, "c=IN IP4 0.0.0.0"));
  CHECK(has(out, "c=IN IP6 ::"));
  CHECK(has(out, "c=IN IP4 mbms.invalid"));  // TS 24.379 §14.2.2.2
  CHECK(has(out, "m=audio 0 RTP/AVP 0"));      // RFC 3264 §8.2
  CHECK(has(out, "m=audio 9 RTP/AVP 0"));
  CHECK(has(out, "a=rtcp:9"));
}

TEST_CASE("a=rtcp, a=ssrc and a=candidate", "[sip][sdp]") {
  Fixture f;
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "t=0 0", "m=audio 5000 RTP/AVP 0",
                                "a=rtcp:5001 IN IP4 10.0.0.9", "a=ssrc:3735928559 cname:bob@10.0.0.9",
                                "a=ssrc:3735928559 cname:a1b2c3d4e5", "a=ssrc:3735928559 previous-ssrc:42",
                                "a=ssrc:3735928559 mystery:1",
                                "a=ssrc-group:FID 3735928559 42",
                                "a=candidate:1 1 UDP 2130706431 10.0.0.9 8998 typ host",
                                "a=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.0.9 rport 8998",
                                "a=candidate:3 1 UDP 1694498815 192.0.2.3 45665 typ srflx raddr 0.0.0.0 rport 9"}));
  const auto ip9 = f.ip("10.0.0.9");
  CHECK(has(out, "a=rtcp:5001 IN IP4 " + ip9));
  const std::string ssrc = std::to_string(*f.p.ssrc(3735928559u));
  CHECK(std::regex_match(out[6], std::regex("a=ssrc:" + ssrc + " cname:u-[0-9a-f]{8}@" +
                                            std::regex_replace(ip9, std::regex("\\."), "\\."))));
  CHECK(std::regex_match(out[7], std::regex("a=ssrc:" + ssrc + " cname:cn-[0-9a-f]{12}")));
  CHECK(out[8] == "a=ssrc:" + ssrc + " previous-ssrc:" + std::to_string(*f.p.ssrc(42)));
  CHECK_FALSE(any_starts(out, "a=ssrc:" + ssrc + " mystery"));
  CHECK(has(out, "a=ssrc-group:FID " + ssrc + " " + std::to_string(*f.p.ssrc(42))));
  CHECK(has(out, "a=candidate:1 1 UDP 2130706431 " + ip9 + " 8998 typ host"));
  CHECK(has(out, "a=candidate:2 1 UDP 1694498815 " + f.ip("192.0.2.3") + " 45664 typ srflx raddr " +
                     ip9 + " rport 8998"));
  CHECK(has(out, "a=candidate:3 1 UDP 1694498815 " + f.ip("192.0.2.3") +
                     " 45665 typ srflx raddr 0.0.0.0 rport 9"));  // RFC 8839 §9.1
}

TEST_CASE("a=fmtp:MCPTT with ';' and ':' separators (D3), MCVideo and MCDATA (D4)", "[sip][sdp]") {
  Fixture f;
  const std::string fl = std::to_string(*f.p.ssrc(12345678u));
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "t=0 0",
                                "m=application 1235 udp MCPTT",
                                "a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted;mc_floor_ssrc=12345678",
                                "a=fmtp:MCPTT mc_queueing:mc_ssrc=12345678:mc_vendor_x=1",
                                "a=fmtp:MCPTT mc_queueing;",
                                "m=application 1236 udp mcptt", "a=fmtp:mcptt mc_floor_ssrc=12345678",
                                "m=application 1237 udp MCVideo",
                                "a=fmtp:MCVideo mc_queueing;mc_video_ssrc=12345678;mc_transmission_ssrc=12345678",
                                "m=application 1238 udp MCDATA", "a=fmtp:MCDATA mcdata-ipconn-s-port=40000",
                                "a=fmtp:MCSOMETHING mc_ssrc=12345678"}));
  CHECK(has(out, "a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted;mc_floor_ssrc=" + fl));
  CHECK(has(out, "a=fmtp:MCPTT mc_queueing:mc_ssrc=" + fl));  // unknown parameter removed
  CHECK(has(out, "a=fmtp:MCPTT mc_queueing;"));
  CHECK(has(out, "a=fmtp:mcptt mc_floor_ssrc=" + fl));  // format matched case-insensitively
  CHECK(has(out, "a=fmtp:MCVideo mc_queueing;mc_video_ssrc=" + fl + ";mc_transmission_ssrc=" + fl));
  CHECK(has(out, "a=fmtp:MCDATA mcdata-ipconn-s-port=40000"));
  CHECK_FALSE(any_starts(out, "a=fmtp:MCSOMETHING"));  // a non-numeric format without a rule
  CHECK(has(out, "m=application 1236 udp mcptt"));
  CHECK(f.counters.removed_unknown["sip-param"]["mc_vendor_x"] == 1);
  CHECK(f.counters.sdp["a=fmtp:MCPTT"]["pseudonymise"] == 4);
}

TEST_CASE("a=path: every MSRP URI is pseudonymised (RFC 4975 §8.2, D4)", "[sip][sdp][msrp]") {
  Fixture f;
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "t=0 0",
                                "m=message 2855 TCP/MSRP *",
                                "a=path:msrp://10.0.0.1:12763/kjhd37s2s20w2a;tcp "
                                "msrp://alice@mcdata.example.net:2855/9di4eae923wzd;tcp"}));
  const auto path = std::find_if(out.begin(), out.end(), [](auto& l) { return l.starts_with("a=path:"); });
  REQUIRE(path != out.end());
  CHECK(path->find("kjhd37s2s20w2a") == std::string::npos);
  CHECK(path->find("9di4eae923wzd") == std::string::npos);
  CHECK(path->find("alice") == std::string::npos);
  CHECK(path->find("example.net") == std::string::npos);
  CHECK(std::regex_match(*path, std::regex("a=path:msrp://[0-9.]+:12763/ms-[0-9a-f]{20};tcp "
                                           "msrp://u-[0-9a-f]{8}@d-[0-9a-f]{8}\\.d-[0-9a-f]{8}\\."
                                           "invalid:2855/ms-[0-9a-f]{20};tcp")));
}

TEST_CASE("keying, ICE credentials and unknown attributes are removed and counted", "[sip][sdp]") {
  Fixture f;
  const auto out = f.lines(sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "t=0 0", "m=audio 5000 RTP/SAVP 0",
                                "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
                                "a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyO",
                                "a=ice-ufrag:8hhY", "a=ice-pwd:asd88fgpdd777uzjYhagZg",
                                "a=fingerprint:sha-256 4A:AD:B9:B1:3F", "a=x-vendor-secret:CANARY",
                                "a=sendrecv"}));
  for (const char* a : {"a=crypto", "a=key-mgmt", "a=ice-ufrag", "a=ice-pwd", "a=fingerprint", "a=x-vendor"}) {
    INFO(a);
    CHECK_FALSE(any_starts(out, a));
  }
  CHECK(has(out, "a=sendrecv"));
  CHECK(f.counters.sdp["a=crypto"]["remove"] == 1);
  CHECK(f.counters.sdp["a=ice-pwd"]["remove"] == 1);
  CHECK(f.counters.removed_unknown["sdp-attribute"]["x-vendor-secret"] == 1);
  // Removed key material becomes an in-memory scan token.
  CHECK(std::any_of(f.counters.removed_values.begin(), f.counters.removed_values.end(),
                    [](auto& v) { return v.second.find("asd88fgpdd777uzjYhagZg") != std::string::npos; }));
}

TEST_CASE("malformed SDP makes the body malformed", "[sip][sdp]") {
  Fixture f;
  for (const std::string& bad : {sdp({"v=0", "garbage"}), sdp({"o=- 1 1 IN IP4 10.0.0.1", "v=0"}),
                                 sdp({"v=0", "o=- 1 IN IP4 10.0.0.1", "s=-"}),
                                 sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "c=IN IP4"}),
                                 sdp({"v=0", "o=- 1 1 IN IP4 10.0.0.1", "s=-", "m=audio port RTP/AVP 0"}),
                                 std::string("v=0\r\nx\r\n"), std::string(""), std::string("v=0\r\n\x01=\r\n")}) {
    INFO(bad);
    auto r = rewrite_sdp(bad, f.ctx);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->has_value());
  }
}

TEST_CASE("line ends are kept: CRLF stays CRLF, LF stays LF", "[sip][sdp]") {
  Fixture f;
  const auto crlf = f.rewrite("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
  CHECK(crlf.find("\r\n") != std::string::npos);
  CHECK(crlf.ends_with("t=0 0\r\n"));
  const auto lf = f.rewrite("v=0\no=- 1 1 IN IP4 0.0.0.0\ns=-\nt=0 0\n");
  CHECK(lf.find('\r') == std::string::npos);
  CHECK(lf.ends_with("t=0 0\n"));
}
