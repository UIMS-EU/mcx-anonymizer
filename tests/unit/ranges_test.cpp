// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/ranges.hpp"
#include "pseudo/special_addresses.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <array>

using namespace mcxanon;

namespace {
Digest32 digest_with(std::initializer_list<std::uint8_t> head, std::uint8_t fill = 0x5A) {
  Digest32 d{};
  d.fill(fill);
  std::size_t i = 0;
  for (auto v : head) d[i++] = v;
  return d;
}
Ipv6 v6(std::initializer_list<std::uint16_t> groups) {
  Ipv6 a{};
  std::size_t i = 0;
  for (auto g : groups) {
    a[i++] = static_cast<std::uint8_t>(g >> 8);
    a[i++] = static_cast<std::uint8_t>(g & 0xFF);
  }
  return a;
}
}  // namespace

TEST_CASE("IPv4 candidates land in 240.0.0.0/4 and never on the limited broadcast", "[ranges]") {
  auto p = place_ipv4(digest_with({0x12, 0x34, 0x56, 0x78}));
  REQUIRE(p.has_value());
  CHECK(*p == 0xF2345678u);
  auto q = place_ipv4(digest_with({0x00, 0x00, 0x00, 0x00}));
  REQUIRE(q.has_value());
  CHECK(*q == 0xF0000000u);
  CHECK_FALSE(place_ipv4(digest_with({0xFF, 0xFF, 0xFF, 0xFF})).has_value());
  CHECK_FALSE(place_ipv4(digest_with({0x0F, 0xFF, 0xFF, 0xFF})).has_value());
}

TEST_CASE("IPv6 candidates land in 2001:db8::/32", "[ranges]") {
  const Ipv6 p = place_ipv6(digest_with({0xAA, 0xBB}));
  CHECK(p[0] == 0x20);
  CHECK(p[1] == 0x01);
  CHECK(p[2] == 0x0d);
  CHECK(p[3] == 0xb8);
  CHECK(p[4] == 0xAA);
  CHECK(p[5] == 0xBB);
}

TEST_CASE("MAC candidates are locally administered and keep the I/G bit", "[ranges]") {
  const auto d = digest_with({0xFD, 0x11, 0x22, 0x33, 0x44, 0x55});
  const Mac uni = place_mac(d, 0x00);
  CHECK((uni[0] & 0x02) == 0x02);
  CHECK((uni[0] & 0x01) == 0x00);
  const Mac multi = place_mac(d, 0x01);
  CHECK((multi[0] & 0x03) == 0x03);
  CHECK(uni[1] == 0x11);
  CHECK(uni[5] == 0x55);
}

TEST_CASE("VLAN, port, multicast and partial-address candidates stay in range", "[ranges]") {
  for (std::uint8_t b = 0; b < 255; b = static_cast<std::uint8_t>(b + 17)) {
    const auto d = digest_with({b, static_cast<std::uint8_t>(b ^ 0xFF), b, b});
    const auto vlan = place_vlan(d);
    CHECK(vlan >= 1);
    CHECK(vlan <= 4094);
    const auto port = place_port(d, 49152, 65535);
    CHECK(port >= 49152);
    const auto mc = place_ipv4_mcast(d);
    CHECK((mc & 0xFFFFFF00u) == 0xE9FC0000u);  // 233.252.0.0/24
  }
  CHECK_FALSE(place_iid(digest_with({0, 0, 0, 0, 0, 0, 0, 0}, 0x00)).has_value());
  CHECK_FALSE(place_iid(digest_with({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})).has_value());
  CHECK(place_iid(digest_with({1, 2, 3, 4, 5, 6, 7, 8})).has_value());
  const auto sn = place_sn24(digest_with({0xAB, 0xCD, 0xEF}));
  CHECK(sn == std::array<std::uint8_t, 3>{0xAB, 0xCD, 0xEF});
}

TEST_CASE("IPv4 special-address classification", "[ranges][special]") {
  struct Case { std::uint32_t addr; Ipv4Class cls; };
  auto c = GENERATE(Case{0x00000000u, Ipv4Class::keep},         // 0.0.0.0
                    Case{0xFFFFFFFFu, Ipv4Class::keep},         // 255.255.255.255
                    Case{0x7F000001u, Ipv4Class::keep},         // 127.0.0.1
                    Case{0x7F123456u, Ipv4Class::keep},         // 127/8
                    Case{0xE0000001u, Ipv4Class::keep},         // 224.0.0.1
                    Case{0xE00000FBu, Ipv4Class::keep},         // 224.0.0.251
                    Case{0xE0000101u, Ipv4Class::keep},         // 224.0.1.1
                    Case{0xE0000201u, Ipv4Class::multicast},    // 224.0.2.1
                    Case{0xEFFFFFFAu, Ipv4Class::multicast},    // 239.255.255.250
                    Case{0x0A000001u, Ipv4Class::unicast},      // 10.0.0.1
                    Case{0xC0A80001u, Ipv4Class::unicast},      // 192.168.0.1
                    Case{0x64400001u, Ipv4Class::unicast},      // 100.64.0.1
                    Case{0xA9FE0001u, Ipv4Class::unicast},      // 169.254.0.1
                    Case{0xF0000001u, Ipv4Class::unicast});     // 240.0.0.1
  CHECK(classify_ipv4(c.addr) == c.cls);
}

TEST_CASE("IPv6 special-address classification", "[ranges][special]") {
  CHECK(classify_ipv6(v6({0, 0, 0, 0, 0, 0, 0, 0})) == Ipv6Class::keep);          // ::
  CHECK(classify_ipv6(v6({0, 0, 0, 0, 0, 0, 0, 1})) == Ipv6Class::keep);          // ::1
  CHECK(classify_ipv6(v6({0xff02, 0, 0, 0, 0, 0, 0, 1})) == Ipv6Class::keep);     // ff02::1
  CHECK(classify_ipv6(v6({0xff02, 0, 0, 0, 0, 0, 0, 0xfb})) == Ipv6Class::keep);  // ff02::fb
  CHECK(classify_ipv6(v6({0xff05, 0, 0, 0, 0, 0, 1, 3})) == Ipv6Class::keep);     // ff05::1:3
  CHECK(classify_ipv6(v6({0xff15, 0, 0, 0, 0, 0, 0, 0x1234})) ==
        Ipv6Class::multicast);  // transient (T flag set)
  CHECK(classify_ipv6(v6({0xff02, 0, 0, 0, 0, 1, 0xff12, 0x3456})) ==
        Ipv6Class::solicited_node);
  CHECK(classify_ipv6(v6({0xfe80, 0, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455})) ==
        Ipv6Class::link_local);
  CHECK(classify_ipv6(v6({0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888})) == Ipv6Class::unicast);
  CHECK(classify_ipv6(v6({0xfd00, 1, 2, 3, 4, 5, 6, 7})) == Ipv6Class::unicast);  // ULA
  CHECK(classify_ipv6(v6({0x2001, 0x0db8, 0, 0, 0, 0, 0, 1})) == Ipv6Class::unicast);
  CHECK(classify_ipv6(v6({0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1})) == Ipv6Class::unicast);  // 6to4
  CHECK(classify_ipv6(v6({0x2001, 0, 1, 2, 3, 4, 5, 6})) == Ipv6Class::unicast);  // Teredo
  CHECK(classify_ipv6(v6({0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001})) ==
        Ipv6Class::embedded_ipv4);  // ::ffff:10.0.0.1
  CHECK(classify_ipv6(v6({0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001})) ==
        Ipv6Class::embedded_ipv4);  // 64:ff9b::10.0.0.1
  CHECK(classify_ipv6(v6({0, 0, 0, 0, 0, 0, 0x0a00, 0x0001})) ==
        Ipv6Class::embedded_ipv4);  // ::10.0.0.1 (IPv4-compatible)
}
