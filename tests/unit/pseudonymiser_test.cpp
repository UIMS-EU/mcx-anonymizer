// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 7);
  return s;
}
Ipv6 v6(std::initializer_list<std::uint16_t> g) {
  Ipv6 a{};
  std::size_t i = 0;
  for (auto x : g) {
    a[i++] = static_cast<std::uint8_t>(x >> 8);
    a[i++] = static_cast<std::uint8_t>(x);
  }
  return a;
}
}  // namespace

TEST_CASE("pseudonyms are consistent and in range", "[pseudo]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto a = p.ipv4(0x0A000001u);
  REQUIRE(a.has_value());
  CHECK((*a >> 28) == 0xFu);
  CHECK(*p.ipv4(0x0A000001u) == *a);
  CHECK(*p.ipv4(0x0A000002u) != *a);
  // A second pseudonymiser on a fresh mapping with the same secret agrees (order-independent).
  Mapping m2;
  Pseudonymiser q(s, m2);
  (void)q.ipv4(0x0A000002u);
  CHECK(*q.ipv4(0x0A000001u) == *a);
  CHECK(p.stats().new_entries.at("ipv4") == 2);
}

TEST_CASE("special addresses are kept, other classes keep their class", "[pseudo]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  CHECK(*p.ipv4(0x7F000001u) == 0x7F000001u);
  CHECK(*p.ipv4(0xFFFFFFFFu) == 0xFFFFFFFFu);
  CHECK(*p.ipv4(0xE00000FBu) == 0xE00000FBu);
  CHECK((*p.ipv4(0xEF010203u) & 0xFFFFFF00u) == 0xE9FC0000u);  // other multicast

  const auto ll = *p.ipv6(v6({0xfe80, 0, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455}));
  CHECK(ll[0] == 0xfe);
  CHECK(ll[1] == 0x80);
  CHECK(ll[8] != 0x02);  // the EUI-64 identifier is gone
  const auto g = *p.ipv6(v6({0x2a00, 0x1450, 0, 0, 0, 0, 0, 0x200e}));
  CHECK(g[0] == 0x20);
  CHECK(g[1] == 0x01);
  CHECK(g[2] == 0x0d);
  CHECK(g[3] == 0xb8);
  const auto mapped = *p.ipv6(v6({0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001}));
  CHECK(mapped[10] == 0xff);
  CHECK(mapped[12] == ((*p.ipv4(0x0A000001u)) >> 24));
  const auto sn = *p.ipv6(v6({0xff02, 0, 0, 0, 0, 1, 0xff12, 0x3456}));
  CHECK(sn[12] == 0xff);
  CHECK(sn[1] == 0x02);
  const auto transient = *p.ipv6(v6({0xff15, 0, 0, 0, 0, 0, 0, 0x1234}));
  CHECK(transient[0] == 0xff);
  CHECK(transient[1] == 0x15);
  CHECK(*p.ipv6(v6({0xff02, 0, 0, 0, 0, 0, 0, 1})) == v6({0xff02, 0, 0, 0, 0, 0, 0, 1}));

  const Mac uni{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  const auto pm = *p.mac(uni);
  CHECK((pm[0] & 0x03) == 0x02);
  const Mac bcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  CHECK(*p.mac(bcast) == bcast);
  const Mac stp{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
  CHECK(*p.mac(stp) == stp);
  CHECK(*p.vlan(0) == 0);
  CHECK(*p.port(5060) == 5060);
  const auto eph = *p.port(50000);
  CHECK(eph >= 49152);
}

TEST_CASE("an original equal to an issued pseudonym is a collision", "[pseudo][collision]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  const auto issued = *p.ipv4(0x0A000001u);
  auto r = p.ipv4(issued);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::collision);
  CHECK(r.error().message.find("240.") == std::string::npos);
  CHECK(r.error().message.find("10.0.0.1") == std::string::npos);
}

TEST_CASE("runs_seen counts each run once", "[pseudo]") {
  const auto s = secret();
  Mapping m;
  {
    Pseudonymiser p(s, m);
    (void)p.ipv4(0x0A000001u);
    (void)p.ipv4(0x0A000001u);
    p.finish_run();
  }
  {
    Pseudonymiser p(s, m);
    (void)p.ipv4(0x0A000001u);
    p.finish_run();
    CHECK(p.stats().reused_entries.at("ipv4") == 1);
  }
  const Bytes orig{10, 0, 0, 1};
  CHECK(m.find(Category::ipv4, orig)->runs_seen == 2);
}
