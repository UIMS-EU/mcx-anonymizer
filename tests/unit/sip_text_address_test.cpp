// SPDX-License-Identifier: GPL-3.0-or-later
//
// IPv4 and IPv6 addresses and ports written as text in SIP and SDP.
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <regex>

using namespace mcxanon;
using namespace mcxanon::sip;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i + 40);
  return s;
}
std::string fmt(std::string_view in) {
  auto a = parse_address_text(in);
  REQUIRE(a.has_value());
  return format_address(*a);
}
}  // namespace

TEST_CASE("text addresses parse per RFC 3986 §3.2.2 and render in their form class",
          "[sip][render]") {
  CHECK(fmt("10.0.0.1") == "10.0.0.1");
  CHECK(fmt("2001:db8::1") == "2001:db8::1");
  CHECK(fmt("[2001:db8::1]") == "[2001:db8::1]");
  CHECK(fmt("2001:DB8::A") == "2001:DB8::A");  // letter case kept
  CHECK(fmt("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:0db8:0000:0000:0000:0000:0000:0001");
  CHECK(fmt("2001:db8:0:0:0:0:0:1") == "2001:db8:0:0:0:0:0:1");  // full, not padded
  CHECK(fmt("::ffff:10.0.0.1") == "::ffff:10.0.0.1");             // mixed
  CHECK(fmt("::") == "::");
  CHECK(fmt("::1") == "::1");
  CHECK(fmt("fe80::") == "fe80::");
  CHECK(fmt("2001:db8:0:1:0:0:0:1") == "2001:db8:0:1:0:0:0:1");
  // Compressed input with a longer zero run elsewhere: the longest run is elided.
  CHECK(fmt("2001:0:0:1::1") == "2001:0:0:1::1");
  CHECK(fmt("2001::1:0:0:0:1") == "2001:0:0:1::1");
  for (const char* bad : {"10.0.0", "10.0.0.256", "1.2.3.4.5", "2001:db8", "2001:db8:::1",
                          ":::", "2001:db8::1::2", "[2001:db8::1", "12345::", "g::1",
                          "1:2:3:4:5:6:7:8:9", "::1.2.3", "1.2.3.4::", ""}) {
    INFO(bad);
    CHECK_FALSE(parse_address_text(bad).has_value());
  }
}

TEST_CASE("a text address has the pseudonym of the same binary address", "[sip][render]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  MapperAdapter mapper(p);
  const auto v4 = map_address_text("10.45.12.34", mapper);
  REQUIRE(v4.has_value());
  REQUIRE(v4->has_value());
  const auto bin = *p.ipv4(0x0A2D0C22u);
  CHECK(**v4 == std::to_string(bin >> 24) + "." + std::to_string((bin >> 16) & 0xFF) + "." +
                    std::to_string((bin >> 8) & 0xFF) + "." + std::to_string(bin & 0xFF));
  // The same IPv6 address in three spellings: one pseudonym, three form classes.
  const auto a = map_address_text("[fd12:3456:789a:20::10]", mapper);
  const auto b = map_address_text("fd12:3456:789a:0020:0000:0000:0000:0010", mapper);
  const auto c = map_address_text("FD12:3456:789A:20::10", mapper);
  REQUIRE((a && *a && b && *b && c && *c));
  CHECK(std::regex_match(**a, std::regex("\\[[0-9a-f:]+\\]")));
  CHECK(std::regex_match(**b, std::regex("([0-9a-f]{4}:){7}[0-9a-f]{4}")));
  CHECK(std::regex_match(**c, std::regex("[0-9A-F:]+")));
  CHECK(parse_address_text(**a)->v6addr == parse_address_text(**b)->v6addr);
  CHECK(parse_address_text(**a)->v6addr == parse_address_text(**c)->v6addr);
  Ipv6Addr orig{0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x10};
  CHECK(parse_address_text(**a)->v6addr == *p.ipv6(orig));
  // Not an address.
  CHECK_FALSE(map_address_text("pc33.example.com", mapper)->has_value());
}

TEST_CASE("special addresses are kept in text as in the headers", "[sip][render]") {
  const auto s = secret();
  Mapping m;
  Pseudonymiser p(s, m);
  MapperAdapter mapper(p);
  CHECK(**map_address_text("0.0.0.0", mapper) == "0.0.0.0");      // RFC 3264 §8.4 hold
  CHECK(**map_address_text("127.0.0.1", mapper) == "127.0.0.1");
  CHECK(**map_address_text("::", mapper) == "::");
  CHECK(**map_address_text("::1", mapper) == "::1");
  CHECK(**map_address_text("[::]", mapper) == "[::]");
  // Multicast stays multicast (feature-001 category rule).
  const auto mc = **map_address_text("239.1.1.1", mapper);
  CHECK(parse_ipv4_text(mc)->v4 >> 28 == 0xEu);
}

TEST_CASE("prefix-preserving and the port policy apply to text as to headers", "[sip][render]") {
  const auto s = secret();
  Mapping m;
  PseudonymiserOptions o;
  o.prefix_preserving = true;
  Pseudonymiser p(s, m, o);
  MapperAdapter mapper(p);
  const auto a = **map_address_text("10.1.2.3", mapper);
  const auto b = **map_address_text("10.1.2.4", mapper);
  // Same /24 in, same /24 out.
  CHECK(a.substr(0, a.rfind('.')) == b.substr(0, b.rfind('.')));
  CHECK(parse_ipv4_text(a)->v4 == *p.ipv4(0x0A010203u));
  // Ports: kept unless the ephemeral-port option is on; then the feature-001 mapping.
  CHECK(**map_port_text("50000", mapper, false) == "50000");
  CHECK(**map_port_text("5060", mapper, true) == "5060");  // not ephemeral
  const auto eph = **map_port_text("50000", mapper, true);
  CHECK(eph == std::to_string(*p.port(50000)));
  CHECK_FALSE(map_port_text("65536", mapper, true)->has_value());
  CHECK_FALSE(map_port_text("50a", mapper, true)->has_value());
}
