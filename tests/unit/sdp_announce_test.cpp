// SPDX-License-Identifier: GPL-3.0-or-later
//
// Media announcements from the SDP rewriter: the announced endpoints carry the
// original values while the rewritten SDP carries pseudonyms, and media::from_sdp turns them
// into endpoint-table announcements.
#include "media/endpoints.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/sdp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <variant>
#include <vector>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 11 + 5);
  return s;
}

struct Recorder : MediaSink {
  std::vector<SdpMedia> seen;
  void announce(const SdpMedia& m) override { seen.push_back(m); }
};

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  SipCounters counters;
  Recorder rec;
  Context ctx{rules, mapper, {}, counters, &rec};

  std::string rewrite(const std::string& body) {
    auto r = rewrite_sdp(body, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
};

std::string sdp(std::initializer_list<const char*> ls) {
  std::string s;
  for (const char* l : ls) s += std::string(l) + "\r\n";
  return s;
}

const std::string kOffer = sdp({"v=0", "o=- 11 11 IN IP4 10.0.0.1", "s=-", "c=IN IP4 10.0.0.1", "t=0 0",
                                "m=audio 40000 RTP/AVP 96", "a=rtpmap:96 AMR-WB/16000", "a=rtcp:40101",
                                "m=video 40010 RTP/SAVPF 100", "c=IN IP4 10.0.0.9", "a=rtcp-mux",
                                "m=application 40002 udp MCPTT", "a=fmtp:MCPTT mc_queueing;mc_floor_ssrc=1234",
                                "m=application 40004 udp MCVideo",
                                "m=message 7000 TCP/MSRP *", "a=path:msrp://10.0.0.1:7000/s7000;tcp",
                                "m=message 7002 TCP/TLS/MSRP *", "a=path:msrps://10.0.0.1:7002/s7002;tcp",
                                "m=audio 0 RTP/AVP 0"});
}  // namespace

TEST_CASE("the SDP rewriter announces every media section with its original values", "[media][sdp]") {
  Fixture f;
  const auto out = f.rewrite(kOffer);
  REQUIRE(f.rec.seen.size() == 7);
  const auto& a = f.rec.seen[0];
  CHECK(a.media == "audio");
  CHECK(a.addrtype == "IP4");
  CHECK(a.address == "10.0.0.1");  // the original, not the pseudonym
  CHECK(a.port == 40000);
  CHECK(a.proto == "RTP/AVP");
  REQUIRE(a.rtcp_port.has_value());
  CHECK(*a.rtcp_port == 40101);
  CHECK_FALSE(a.rtcp_mux);
  const auto& v = f.rec.seen[1];
  CHECK(v.address == "10.0.0.9");  // media-level c= overrides the session level
  CHECK(v.rtcp_mux);
  CHECK(v.proto == "RTP/SAVPF");
  CHECK(f.rec.seen[2].fmt == "MCPTT");
  CHECK(f.rec.seen[3].fmt == "MCVideo");
  REQUIRE(f.rec.seen[4].paths.size() == 1);
  CHECK(f.rec.seen[4].paths[0] == "msrp://10.0.0.1:7000/s7000;tcp");
  CHECK(f.rec.seen[6].port == 0);
  // The rewritten text carries pseudonyms.
  CHECK(out.find("10.0.0.1") == std::string::npos);
}

TEST_CASE("no sink, no announcements, and the rewritten SDP is unchanged", "[media][sdp]") {
  Fixture with, without;
  without.ctx.media = nullptr;
  CHECK(with.rewrite(kOffer) == without.rewrite(kOffer));
  CHECK(without.rec.seen.empty());
}

TEST_CASE("a malformed SDP announces nothing", "[media][sdp]") {
  Fixture f;
  auto r = rewrite_sdp(sdp({"v=0", "o=- 11 11 IN IP4 10.0.0.1", "s=-", "c=IN IP4", "t=0 0",
                            "m=audio 40000 RTP/AVP 96"}),
                       f.ctx);
  REQUIRE(r.has_value());
  CHECK_FALSE(r->has_value());
  CHECK(f.rec.seen.empty());
}

TEST_CASE("from_sdp turns SDP media into endpoint announcements", "[media][sdp]") {
  Fixture f;
  f.rewrite(kOffer);
  using media::Role;
  auto first = media::from_sdp(f.rec.seen[0]);
  REQUIRE(std::holds_alternative<std::vector<media::Announcement>>(first));
  const auto& a = std::get<std::vector<media::Announcement>>(first);
  REQUIRE(a.size() == 1);
  CHECK(a[0].role == Role::rtp);
  CHECK(a[0].address == media::Address::v4({10, 0, 0, 1}));
  CHECK(*a[0].rtcp_port == 40101);
  CHECK_FALSE(a[0].secure);
  auto video = std::get<std::vector<media::Announcement>>(media::from_sdp(f.rec.seen[1]));
  CHECK(video[0].secure);
  CHECK(video[0].rtcp_mux);
  CHECK(std::get<std::vector<media::Announcement>>(media::from_sdp(f.rec.seen[2]))[0].role == Role::fc);
  CHECK(std::get<std::vector<media::Announcement>>(media::from_sdp(f.rec.seen[3]))[0].role == Role::tc);
  auto msrp = std::get<std::vector<media::Announcement>>(media::from_sdp(f.rec.seen[4]));
  REQUIRE(msrp.size() == 1);  // the a=path authority equals c= and m=: one endpoint
  CHECK(msrp[0].role == Role::msrp);
  CHECK(msrp[0].transport == media::Transport::tcp);
  CHECK(std::get<media::SkipReason>(media::from_sdp(f.rec.seen[5])) == media::SkipReason::tls);
  CHECK(std::get<media::SkipReason>(media::from_sdp(f.rec.seen[6])) == media::SkipReason::rejected);
}

TEST_CASE("an MSRP path naming another address adds a second endpoint", "[media][sdp]") {
  sip::SdpMedia m;
  m.media = "message";
  m.addrtype = "IP4";
  m.address = "10.0.0.1";
  m.port = 7000;
  m.proto = "TCP/MSRP";
  m.fmt = "*";
  m.paths = {"msrp://10.0.0.5:7100/abc;tcp"};
  auto a = std::get<std::vector<media::Announcement>>(media::from_sdp(m));
  REQUIRE(a.size() == 2);
  CHECK(a[1].address == media::Address::v4({10, 0, 0, 5}));
  CHECK(a[1].port == 7100);
}

TEST_CASE("unsupported media and protos are skipped", "[media][sdp]") {
  sip::SdpMedia m;
  m.media = "audio";
  m.addrtype = "IP4";
  m.address = "10.0.0.1";
  m.port = 40000;
  m.proto = "UDP/BFCP";
  m.fmt = "*";
  CHECK(std::get<media::SkipReason>(media::from_sdp(m)) == media::SkipReason::unsupported);
  m.proto = "RTP/AVP";
  m.address = "media.example.net";
  CHECK(std::get<media::SkipReason>(media::from_sdp(m)) == media::SkipReason::fqdn);
}
