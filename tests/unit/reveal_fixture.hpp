// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared fixture of the reveal unit tests: a mapping filled through the real pseudonymiser, and
// helpers that render pseudonyms the way the anonymiser writes them.
#pragma once

#include "pseudo/mapping.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "reveal/engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <string>
#include <string_view>

namespace reveal_test {

using namespace mcxanon;

inline Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 11 + 5);
  return s;
}

inline std::string dotted(std::uint32_t v) {
  char b[16];
  std::snprintf(b, sizeof b, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
  return b;
}

inline std::string mac_text(const Mac& m, char sep = ':') {
  std::string o;
  char b[4];
  for (std::size_t i = 0; i < 6; ++i) {
    if (i && sep) o.push_back(sep);
    std::snprintf(b, sizeof b, "%02x", m[i]);
    o += b;
  }
  return o;
}

inline std::string hex32(std::uint32_t v, bool prefix = true) {
  char b[16];
  std::snprintf(b, sizeof b, prefix ? "0x%08x" : "%08x", v);
  return b;
}

struct Fixture {
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};

  std::string text(Category c, std::string_view v) {
    auto r = p.text(c, v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::string user(std::string_view v) { return text(Category::sip_user, v); }
  std::string host(std::string_view v) {
    auto r = p.domain(v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::string tel(std::string_view v) {
    auto r = p.tel(v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::uint32_t ipv4(std::uint32_t v) {
    auto r = p.ipv4(v);
    REQUIRE(r.has_value());
    return *r;
  }
  Ipv6 ipv6(const Ipv6& v) {
    auto r = p.ipv6(v);
    REQUIRE(r.has_value());
    return *r;
  }
  Mac mac(const Mac& v) {
    auto r = p.mac(v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::uint32_t ssrc(std::uint32_t v) {
    auto r = p.ssrc(v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::uint32_t binary(Category c, std::uint32_t v) {
    auto r = p.binary(c, v);
    REQUIRE(r.has_value());
    return *r;
  }
  std::uint64_t binary64(Category c, std::uint64_t v) {
    auto r = p.binary64(c, v);
    REQUIRE(r.has_value());
    return *r;
  }

  std::string reveal(std::string_view in, RevealOptions o = {}, RevealSummary* s = nullptr) {
    auto r = reveal::reveal_string(mapping, in, o, s);
    REQUIRE(r.has_value());
    return *r;
  }
};

}  // namespace reveal_test
