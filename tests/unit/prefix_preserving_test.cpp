// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/prefix_preserving.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <bit>
#include <random>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(0xA0 + i);
  return s;
}
int common_prefix(std::uint32_t a, std::uint32_t b) { return a == b ? 32 : std::countl_zero(a ^ b); }
int common_prefix6(const Ipv6& a, const Ipv6& b) {
  for (int i = 0; i < 128; ++i) {
    const int byte = i / 8;
    const int bit = 7 - i % 8;
    if (((a[static_cast<std::size_t>(byte)] >> bit) & 1) != ((b[static_cast<std::size_t>(byte)] >> bit) & 1)) return i;
  }
  return 128;
}
}  // namespace

TEST_CASE("IPv4: shared prefix length is preserved within the free bits", "[pp]") {
  const auto s = secret();
  std::mt19937 rng(7);
  for (int k = 0; k < 2000; ++k) {
    const auto a = static_cast<std::uint32_t>(rng());
    const int n = 4 + static_cast<int>(rng() % 28);      // shared prefix 4..31
    const std::uint32_t flip = 0x80000000u >> n;          // differ exactly at bit n
    const std::uint32_t mask = n == 0 ? 0 : ~((0xFFFFFFFFu) >> n);
    const std::uint32_t b = (a & mask) | (~a & flip) | (static_cast<std::uint32_t>(rng()) & (flip - 1));
    const std::uint32_t pa = pp_ipv4(s, a);
    const std::uint32_t pb = pp_ipv4(s, b);
    INFO(n);
    CHECK((pa >> 28) == 0xF);
    CHECK((pb >> 28) == 0xF);
    CHECK(common_prefix(pa, pb) == n);
  }
}

TEST_CASE("IPv4: deterministic per secret", "[pp]") {
  auto s = secret();
  const std::uint32_t a = 0x0A010203u;
  CHECK(pp_ipv4(s, a) == pp_ipv4(s, a));
  auto t = s;
  t[3] ^= 1;
  CHECK(pp_ipv4(s, a) != pp_ipv4(t, a));
}

TEST_CASE("IPv6: shared prefix length is preserved within the free bits", "[pp]") {
  const auto s = secret();
  std::mt19937 rng(9);
  for (int k = 0; k < 200; ++k) {
    Ipv6 a{};
    for (auto& x : a) x = static_cast<std::uint8_t>(rng());
    const int n = 32 + static_cast<int>(rng() % 96);
    Ipv6 b = a;
    b[static_cast<std::size_t>(n / 8)] ^= static_cast<std::uint8_t>(0x80 >> (n % 8));
    const auto pa = pp_ipv6(s, a);
    const auto pb = pp_ipv6(s, b);
    INFO(n);
    CHECK(pa[0] == 0x20);
    CHECK(pa[1] == 0x01);
    CHECK(pa[2] == 0x0d);
    CHECK(pa[3] == 0xb8);
    CHECK(common_prefix6(pa, pb) == n);
  }
}

TEST_CASE("prefix-preserving mode in the pseudonymiser", "[pp]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m, PseudonymiserOptions{true, 49152, 65535});
  const auto a = *p.ipv4(0x0A010203u);
  const auto b = *p.ipv4(0x0A0102FEu);
  CHECK(common_prefix(a, b) == 24);
  CHECK(m.find(Category::ipv4_pp, Bytes{10, 1, 2, 3}) != nullptr);
  CHECK(m.find(Category::ipv4, Bytes{10, 1, 2, 3}) == nullptr);
}
