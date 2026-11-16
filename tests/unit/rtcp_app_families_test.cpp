// SPDX-License-Identifier: GPL-3.0-or-later
//
// The other MCX APP families (FR-014 to FR-022): MCPC, MCMC, MCNC, MCSC, MCV0-MCV5 and MCDM.
#include "media_env.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
Bytes run(MediaEnv& e, const Bytes& in) {
  auto r = media::rewrite_rtcp(in, false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  return **r;
}
Bytes u16(std::uint16_t v) { return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)}; }
Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}
Bytes w32(std::uint32_t v) {
  Bytes b;
  put32(b, v);
  return b;
}
std::vector<std::pair<std::uint8_t, Bytes>> fields(MediaEnv& e, const Bytes& in) { return fields_of(run(e, in)); }
const Bytes* value(const std::vector<std::pair<std::uint8_t, Bytes>>& f, std::uint8_t id) {
  for (const auto& [i, v] : f) {
    if (i == id) return &v;
  }
  return nullptr;
}
const std::string kGroup = "sip:fire-brigade-west@mcx.example.net";
const std::string kUser = "sip:bob.zielinski@mcx.example.net";
}  // namespace

TEST_CASE("MCPC Connect: session identity, group, inviting user; Warning Text and PCK", "[media][app][mcpc]") {
  MediaEnv e;
  Bytes sess{3};  // prearranged
  const Bytes s = str("sip:sess-1234@mcx.example.net");
  sess.insert(sess.end(), s.begin(), s.end());
  const auto f = fields(e, app("MCPC", 0, 1,
                               {field(0, u16(0x0102)), field(1, sess), field(3, str(kGroup)), field(4, u16(1)),
                                field(5, str(kUser)), field(2, str("107 CANARY-WARNING")),
                                field(192, Bytes(37, 0xAB))}));
  REQUIRE(value(f, 0) != nullptr);
  CHECK(*value(f, 0) == u16(0x0102));
  const Bytes& so = *value(f, 1);
  CHECK(so[0] == 3);
  CHECK(Bytes(so.begin() + 1, so.end()) == str(e.uri("sip:sess-1234@mcx.example.net")));
  CHECK(*value(f, 3) == str(e.uri(kGroup)));
  CHECK(*value(f, 5) == str(e.uri(kUser)));
  CHECK(value(f, 2) == nullptr);  // Warning Text removed (FR-021)
  REQUIRE(value(f, 192) != nullptr);
  CHECK(*value(f, 192) == Bytes(37, 0));  // PCK I_MESSAGE zeroed, length kept
  CHECK(std::any_of(e.counters.removed_values.begin(), e.counters.removed_values.end(),
                    [](const auto& x) { return x.second == "107 CANARY-WARNING"; }));
}

TEST_CASE("MCMC Map Group To Bearer: subchannel address and ports, TMGI zeroed (A8, A9)", "[media][app][mbms]") {
  MediaEnv e;
  // Audio m-line 1, floor m-line 2; IPv4; floor port 49200, media port 49202, 10.9.8.7.
  const Bytes sub = cat({Bytes{0x12, 0x00}, w32(49200), w32(49202), Bytes{10, 9, 8, 7}});
  const Bytes tmgi{0x00, 0x00, 0x01, 0x62, 0xF2, 0x10};
  const auto f = fields(e, app("MCMC", 0, 1, {field(2, str(kGroup)), field(1, tmgi), field(0, sub)}));
  const Bytes& s = *value(f, 0);
  REQUIRE(s.size() == sub.size());
  CHECK(s[0] == 0x12);
  CHECK(s[1] == 0x00);
  CHECK(get32(s, 2) == 49200);  // ports keep the 001 policy (kept by default)
  CHECK(get32(s, 6) == 49202);
  CHECK(get32(s, 10) == *e.mapper.ipv4(0x0A090807));
  CHECK(*value(f, 1) == Bytes(tmgi.size(), 0));
  CHECK(*value(f, 2) == str(e.uri(kGroup)));
  // Without a floor m-line there is no floor port; IPv6 has 16 octets.
  Bytes six = cat({Bytes{0x10, 0x10}, w32(40000)});
  for (int i = 0; i < 16; ++i) six.push_back(static_cast<std::uint8_t>(0xFD - (i == 0 ? 0 : 0xFD) + (i == 15 ? 1 : 0)));
  const auto g = fields(e, app("MCMC", 0, 1, {field(0, six)}));
  const Bytes& s6 = *value(g, 0);
  CHECK(get32(s6, 2) == 40000);
  Ipv6Addr orig{};
  std::copy(six.begin() + 6, six.end(), orig.begin());
  CHECK(Bytes(s6.begin() + 6, s6.end()) == [&] {
    const auto m = *e.mapper.ipv6(orig);
    return Bytes(m.begin(), m.end());
  }());
}

TEST_CASE("subchannel ports with high bits set, or a wrong address size, zero the value", "[media][app][mbms]") {
  MediaEnv e;
  const Bytes bad_port = cat({Bytes{0x10, 0x00}, w32(0x00010000 | 4000), Bytes{10, 1, 1, 1}});
  const Bytes bad_size = cat({Bytes{0x10, 0x00}, w32(4000), Bytes{10, 1, 1}});
  for (const Bytes& v : {bad_port, bad_size}) {
    const auto f = fields(e, app("MCMC", 0, 1, {field(0, v)}));
    CHECK(*value(f, 0) == Bytes(v.size(), 0));
  }
}

TEST_CASE("MCSC: the MBS subchannel floor control SSRC uses the SSRC mapping", "[media][app][mbs]") {
  MediaEnv e;
  // Audio 1, floor 2; IPv4; floor port, floor control SSRC, media port, address.
  const Bytes sub = cat({Bytes{0x12, 0x00}, w32(50100), w32(0xFEED0101), w32(50102), Bytes{10, 2, 3, 4}});
  const auto f = fields(e, app("MCSC", 0, 1, {field(0, sub), field(1, Bytes{1, 2, 3, 4, 5, 6})}));
  const Bytes& s = *value(f, 0);
  CHECK(get32(s, 6) == e.ssrc(0xFEED0101));
  CHECK(get32(s, 14) == *e.mapper.ipv4(0x0A020304));
  CHECK(*value(f, 1) == Bytes(6, 0));  // MBS Session ID zeroed (A9)
}

TEST_CASE("MCNC Group Dynamic Data Notify; a Status longer than 2 octets keeps 2 (A11)", "[media][app][mcnc]") {
  MediaEnv e;
  const auto f = fields(e, app("MCNC", 0, 1,
                               {field(0, cat({u16(1), str("sip:x@y.z")})), field(1, str(kUser)), field(2, Bytes{1}),
                                field(3, str(kGroup)), field(4, str("sip:regroup-7@mcx.example.net"))}));
  REQUIRE(value(f, 0) != nullptr);
  CHECK(Bytes(value(f, 0)->begin(), value(f, 0)->begin() + 2) == u16(1));
  CHECK(std::all_of(value(f, 0)->begin() + 2, value(f, 0)->end(), [](std::uint8_t b) { return b == 0; }));
  CHECK(*value(f, 1) == str(e.uri(kUser)));
  CHECK(*value(f, 2) == Bytes{1});
  CHECK(*value(f, 3) == str(e.uri(kGroup)));
}

TEST_CASE("MCVideo transmission control: MCV0, MCV1, MCV2 share one field table (B1)", "[media][app][mcvideo]") {
  MediaEnv e;
  // MCV1 Transmission Granted (subtype 0) with Duration, Audio SSRC, Video SSRC under ID 24,
  // User ID and Message Name.
  const Bytes ssrc6 = cat({w32(0xBEEF0001), Bytes{0, 0}});
  const Bytes vssrc6 = cat({w32(0xBEEF0002), Bytes{0, 0}});
  const auto f = fields(e, app("MCV1", 0, 0x0C0C0C0C,
                               {field(1, u16(30)), field(14, ssrc6), field(24, vssrc6), field(6, str(kUser)),
                                field(16, cat({str("MCV0"), Bytes{0, 0}}))}));
  CHECK(*value(f, 1) == u16(30));
  CHECK(get32(*value(f, 14), 0) == e.ssrc(0xBEEF0001));
  CHECK(get32(*value(f, 24), 0) == e.ssrc(0xBEEF0002));
  CHECK(*value(f, 6) == str(e.uri(kUser)));
  // ID 016 is Message Name in MCVideo, never a list of SSRCs.
  CHECK(Bytes(value(f, 16)->begin(), value(f, 16)->begin() + 4) == str("MCV0"));
  // The Video SSRC is also accepted under ID 23 (B2).
  const auto g = fields(e, app("MCV1", 0, 1, {field(23, vssrc6)}));
  CHECK(get32(*value(g, 23), 0) == e.ssrc(0xBEEF0002));
  // A Message Name the rules do not know is zeroed.
  const auto h = fields(e, app("MCV2", 4, 1, {field(16, cat({str("ZZZZ"), Bytes{0, 0}}))}));
  CHECK(*value(h, 16) == Bytes(6, 0));
  CHECK(e.counters.app_messages.at("MCV1/0") == 2);
  CHECK(e.counters.app_messages.at("MCV2/4") == 1);
}

TEST_CASE("MCV0 Transmission Request with the ack variant; MCV1 and MCV0 subtypes differ", "[media][app][mcvideo]") {
  MediaEnv e;
  run(e, app("MCV0", 16, 1, {field(0, Bytes{5, 0})}));  // Transmission Request (ack)
  run(e, app("MCV1", 15, 1, {field(8, u16(1))}));       // Transmission idle
  CHECK(e.counters.app_messages.at("MCV0/16") == 1);
  CHECK(e.counters.app_messages.at("MCV1/15") == 1);
  CHECK(e.counters.app_unknown.empty());
  // MCV0 subtype 1 is not assigned.
  run(e, app("MCV0", 1, 1, {field(0, Bytes{5, 0})}));
  CHECK(e.counters.app_unknown.at("subtype") == 1);
}

TEST_CASE("MCV3 and MCV5 subchannels; the placeholder subtypes are unknown (B4)", "[media][app][mcvideo]") {
  MediaEnv e;
  // Video 1, audio 2, control 3, FEC 0; IPv4 (word with IP version); control port, video port,
  // audio port; address.
  const Bytes v3 = cat({Bytes{0x12, 0x30}, Bytes{0x00, 0, 0, 0}, w32(41000), w32(41002), w32(41004), Bytes{10, 5, 5, 5}});
  const auto f = fields(e, app("MCV3", 0, 1, {field(0, v3), field(2, str(kGroup)), field(1, Bytes{1, 2, 3, 4, 5, 6})}));
  const Bytes& s = *value(f, 0);
  CHECK(get32(s, 6) == 41000);
  CHECK(get32(s, 10) == 41002);
  CHECK(get32(s, 14) == 41004);
  CHECK(get32(s, 18) == *e.mapper.ipv4(0x0A050505));
  CHECK(*value(f, 1) == Bytes(6, 0));
  // MCV5: video 1, audio 0, control 2, FEC 0; control port, TC SSRC, video port; address.
  const Bytes v5 = cat({Bytes{0x10, 0x20}, Bytes{0x00, 0, 0, 0}, w32(42000), w32(0xFACE0001), w32(42002), Bytes{10, 6, 6, 6}});
  const auto g = fields(e, app("MCV5", 0, 1, {field(0, v5)}));
  const Bytes& t = *value(g, 0);
  CHECK(get32(t, 10) == e.ssrc(0xFACE0001));
  CHECK(get32(t, 18) == *e.mapper.ipv4(0x0A060606));
  // Bearer Announcement and Session Announcement have no subtype value in V19.1.0.
  run(e, app("MCV3", 3, 1, {field(2, str(kGroup))}));
  CHECK(e.counters.app_unknown.at("subtype") == 1);
}

TEST_CASE("MCV4 notifications and MCDM (P8)", "[media][app][mcvideo][mcdm]") {
  MediaEnv e;
  const auto f = fields(e, app("MCV4", 0, 1, {field(1, str(kUser)), field(3, str(kGroup))}));
  CHECK(*value(f, 1) == str(e.uri(kUser)));
  CHECK(*value(f, 3) == str(e.uri(kGroup)));
  // MCDM: application m-line 1; IPv4; media port; address.
  const Bytes d = cat({Bytes{0x10, 0x00}, w32(43000), Bytes{10, 7, 7, 7}});
  const auto g = fields(e, app("MCDM", 0, 1, {field(0, d), field(2, str(kGroup)), field(3, Bytes{1})}));
  CHECK(get32(*value(g, 0), 2) == 43000);
  CHECK(get32(*value(g, 0), 6) == *e.mapper.ipv4(0x0A070707));
  CHECK(*value(g, 2) == str(e.uri(kGroup)));
  CHECK(*value(g, 3) == Bytes{1});
}
