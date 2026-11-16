// SPDX-License-Identifier: GPL-3.0-or-later
//
// MCX RTCP APP decoding and rewriting, MCPT family (FR-014 to FR-019, FR-021,
// FR-023).
#include "media_env.hpp"

#include <algorithm>

using namespace mcxanon;
using namespace mcxanon::test;

namespace {
Bytes run(MediaEnv& e, const Bytes& in) {
  auto r = media::rewrite_rtcp(in, false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  const Bytes& out = **r;
  // The APP length always matches the packet (FR-023, TS 24.380 §8.1.2).
  REQUIRE(out.size() >= 12);
  CHECK(4 + 4 * ((std::size_t{out[2]} << 8) | out[3]) == out.size());
  CHECK(out.size() % 4 == 0);
  return out;
}

Bytes u16(std::uint16_t v) { return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)}; }
Bytes ssrc6(std::uint32_t v) {
  Bytes b;
  put32(b, v);
  b.push_back(0);
  b.push_back(0);
  return b;
}
const Bytes* value(const std::vector<std::pair<std::uint8_t, Bytes>>& f, std::uint8_t id) {
  for (const auto& [i, v] : f) {
    if (i == id) return &v;
  }
  return nullptr;
}
}  // namespace

TEST_CASE("Floor Granted keeps its numeric fields and maps identities and SSRCs", "[media][app]") {
  MediaEnv e;
  const std::string alice = "sip:alice.kowalska@mcx.example.net";
  const Bytes in = app("MCPT", 1, 0x0A0B0C0D,
                       {field(1, u16(30)), field(0, {0x05, 0x00}), field(8, u16(4)), field(14, ssrc6(0xFEED0001)),
                        field(6, str(alice)), field(3, {0x01, 0x02}), field(7, u16(2)), field(13, u16(0x8000))});
  const auto out = run(e, in);
  CHECK(out[0] == in[0]);
  CHECK(out[1] == 204);
  CHECK(get32(out, 4) == e.ssrc(0x0A0B0C0D));
  CHECK(Bytes(out.begin() + 8, out.begin() + 12) == str("MCPT"));
  const auto f = fields_of(out);
  REQUIRE(f.size() == 8);
  CHECK(*value(f, 1) == u16(30));
  CHECK(*value(f, 0) == Bytes{0x05, 0x00});
  CHECK(*value(f, 8) == u16(4));
  CHECK(get32(*value(f, 14), 0) == e.ssrc(0xFEED0001));
  CHECK(*value(f, 6) == str(e.uri(alice)));
  CHECK(*value(f, 3) == Bytes{0x01, 0x02});
  CHECK(*value(f, 7) == u16(2));
  CHECK(*value(f, 13) == u16(0x8000));
  CHECK(e.counters.app_messages.at("MCPT/1") == 1);
  CHECK(e.counters.app_fields.at("mcpt/6").at("pseudonymise") == 1);
  CHECK(e.counters.app_fields.at("mcpt/1").at("keep") == 1);
}

TEST_CASE("the acknowledgement variant is the same message (x bit, TS 24.380 §8.2.2.1)", "[media][app]") {
  MediaEnv e;
  const auto out = run(e, app("MCPT", 17, 1, {field(8, u16(9))}));
  CHECK((out[0] & 0x1F) == 17);
  CHECK(*value(fields_of(out), 8) == u16(9));
  CHECK(e.counters.app_messages.at("MCPT/17") == 1);
}

TEST_CASE("an unknown subtype zeroes the data, keeping the header with the SSRC mapped", "[media][app]") {
  MediaEnv e;
  const Bytes in = app("MCPT", 12, 0x77, {field(6, str("sip:bob@example.net"))});
  const auto out = run(e, in);
  CHECK(out.size() == in.size());
  CHECK(get32(out, 4) == e.ssrc(0x77));
  CHECK(std::all_of(out.begin() + 12, out.end(), [](std::uint8_t b) { return b == 0; }));
  CHECK(e.counters.app_unknown.at("subtype") == 1);
}

TEST_CASE("an APP packet with a name without rules is removed (FR-014)", "[media][app]") {
  MediaEnv e;
  Bytes two = app("XYZW", 0, 0x77, {field(6, str("sip:bob@example.net"))});
  const Bytes known = app("MCPT", 0, 0x78, {field(8, u16(1))});
  two.insert(two.end(), known.begin(), known.end());
  auto r = media::rewrite_rtcp(two, false, e.env);
  REQUIRE(r.has_value());
  REQUIRE(r->has_value());
  CHECK((*r)->size() == known.size());
  CHECK(Bytes((*r)->begin() + 8, (*r)->begin() + 12) == str("MCPT"));
  CHECK(e.counters.app_unknown.at("name") == 1);
}

TEST_CASE("an unknown field ID is removed; a field that overruns removes the rest", "[media][app]") {
  MediaEnv e;
  const auto out = run(e, app("MCPT", 0, 1, {field(0, {0x04, 0x00}), field(26, str("CANARYDATA")), field(8, u16(1))}));
  const auto f = fields_of(out);
  REQUIRE(f.size() == 2);
  CHECK(f[0].first == 0);
  CHECK(f[1].first == 8);
  CHECK(e.counters.app_unknown.at("field") == 1);
  Bytes bad = app("MCPT", 0, 1, {field(0, {0x04, 0x00}), field(8, u16(1))});
  bad[16 + 1] = 40;  // the second field claims 40 octets
  const auto o2 = run(e, bad);
  const auto f2 = fields_of(o2);
  REQUIRE(f2.size() == 1);
  CHECK(f2[0].first == 0);
  CHECK(e.counters.app_unknown.at("malformed") == 1);
}

TEST_CASE("the Reject Phrase is removed; the cause is kept (A3, P5)", "[media][app]") {
  MediaEnv e;
  Bytes v = u16(3);
  const Bytes phrase = str("CANARY-REJECT-PHRASE");
  v.insert(v.end(), phrase.begin(), phrase.end());
  const auto out = run(e, app("MCPT", 3, 1, {field(2, v)}));
  CHECK(*value(fields_of(out), 2) == u16(3));
  CHECK(std::any_of(e.counters.removed_values.begin(), e.counters.removed_values.end(),
                    [](const auto& x) { return x.second == "CANARY-REJECT-PHRASE"; }));
}

TEST_CASE("Track Info: Participant Type becomes \"unknown\"; references use fc_ref (FR-019, A4)", "[media][app]") {
  MediaEnv e;
  const Bytes pt = str("CANARY-DISPATCHER-OPS");  // 21 octets, padded to 24
  for (bool padded_length : {true, false}) {
    // Value: Queueing Capability, Participant Type Length, Participant Type, padding to 4, refs.
    // The padded convention pads the Participant Type to a multiple of 4 inside the value; the
    // other writes the references right after it.
    Bytes v{0x01, static_cast<std::uint8_t>(pt.size())};
    v.insert(v.end(), pt.begin(), pt.end());
    if (padded_length) {
      while ((v.size() - 2) % 4 != 0) v.push_back(0);
    }
    put32(v, 0xABCD0001);
    put32(v, 0xABCD0002);
    const auto out = run(e, app("MCPT", 0, 1, {field(11, v)}));
    const auto fo = fields_of(out);
    REQUIRE(fo.size() == 1);
    const Bytes& tv = fo[0].second;
    REQUIRE(tv.size() >= 2 + 7);
    CHECK(tv[0] == 0x01);
    CHECK(tv[1] == 7);
    CHECK(Bytes(tv.begin() + 2, tv.begin() + 9) == str("unknown"));
    const std::size_t refs = padded_length ? 2 + 8 : 2 + 7;  // the input's convention is kept
    REQUIRE(tv.size() == refs + 8);
    CHECK(get32(tv, refs) == *e.mapper.binary(Category::fc_ref, 0xABCD0001));
    CHECK(get32(tv, refs + 4) == *e.mapper.binary(Category::fc_ref, 0xABCD0002));
    CHECK(get32(tv, refs) != 0xABCD0001);
  }
}

TEST_CASE("URI lists keep count and order; SSRC lists are mapped", "[media][app]") {
  MediaEnv e;
  const std::string u1 = "sip:u1@mcx.example.net", u2 = "sip:u2@mcx.example.net";
  Bytes list{2, static_cast<std::uint8_t>(u1.size())};
  list.insert(list.end(), u1.begin(), u1.end());
  list.push_back(static_cast<std::uint8_t>(u2.size()));
  list.insert(list.end(), u2.begin(), u2.end());
  Bytes ssrcs{2, 0};
  put32(ssrcs, 0x51000001);
  put32(ssrcs, 0x51000002);
  const auto out = run(e, app("MCPT", 2, 1, {field(15, list), field(16, ssrcs)}));
  const auto f = fields_of(out);
  const Bytes& l = *value(f, 15);
  REQUIRE(l[0] == 2);
  const std::string p1 = e.uri(u1), p2 = e.uri(u2);
  CHECK(l[1] == p1.size());
  CHECK(Bytes(l.begin() + 2, l.begin() + 2 + static_cast<std::ptrdiff_t>(p1.size())) == str(p1));
  const std::size_t o2 = 2 + p1.size();
  CHECK(l[o2] == p2.size());
  CHECK(Bytes(l.begin() + static_cast<std::ptrdiff_t>(o2 + 1), l.end()) == str(p2));
  const Bytes& s = *value(f, 16);
  CHECK(s[0] == 2);
  CHECK(get32(s, 2) == e.ssrc(0x51000001));
  CHECK(get32(s, 6) == e.ssrc(0x51000002));
}

TEST_CASE("List of Queued Users with 2-octet entry lengths is understood (A5)", "[media][app]") {
  MediaEnv e;
  const std::string u = "sip:queued@mcx.example.net";
  Bytes list{1, 0, static_cast<std::uint8_t>(u.size())};
  list.insert(list.end(), u.begin(), u.end());
  const auto out = run(e, app("MCPT", 14, 1, {field(22, list)}));
  const auto f = fields_of(out);
  REQUIRE(value(f, 22) != nullptr);
  const Bytes& l = *value(f, 22);
  const std::string p = e.uri(u);
  REQUIRE(l.size() == 3 + p.size());
  CHECK(l[0] == 1);
  CHECK(((l[1] << 8) | l[2]) == static_cast<int>(p.size()));
  CHECK(Bytes(l.begin() + 3, l.end()) == str(p));
}

TEST_CASE("a value that grows or shrinks is re-padded and every length follows (FR-023)", "[media][app]") {
  MediaEnv e;
  for (const std::string& u : {std::string("sip:a@b.c"), "sip:" + std::string(150, 'x') + "@mcx.example.net"}) {
    const auto in = app("MCPT", 2, 9, {field(4, str(u)), field(8, u16(3))});
    const auto out = run(e, in);
    const auto f = fields_of(out);
    REQUIRE(f.size() == 2);
    CHECK(f[0].second == str(e.uri(u)));
    CHECK(f[1].second == u16(3));
  }
}

TEST_CASE("an unparsable URI value is removed and counted", "[media][app]") {
  MediaEnv e;
  const auto out = run(e, app("MCPT", 2, 9, {field(4, str("not a uri at all")), field(8, u16(3))}));
  const auto f = fields_of(out);
  REQUIRE(f.size() == 1);
  CHECK(f[0].first == 8);
  CHECK(e.counters.app_fields.at("mcpt/4").at("malformed") == 1);
}

TEST_CASE("a fixed-size field longer than its size keeps its defined octets (A11)", "[media][app]") {
  MediaEnv e;
  const auto out = run(e, app("MCPT", 0, 1, {field(8, {0x00, 0x05, 0xC0, 0xFF, 0xEE, 0x11})}));
  CHECK(*value(fields_of(out), 8) == Bytes{0x00, 0x05, 0, 0, 0, 0});
}
