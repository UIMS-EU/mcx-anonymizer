// SPDX-License-Identifier: GPL-3.0-or-later
// Shared fixture for the media-plane unit tests: the embedded SIP and media rule sets, a
// project mapping and the SIP context the media layer uses for URIs.
#pragma once

#include "media/rtcp.hpp"
#include "pipeline/mapper_adapter.hpp"
#include "policy/media_rules.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <string>

namespace mcxanon::test {

inline Secret media_secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 23 + 4);
  return s;
}

struct MediaEnv {
  SipRuleSet sip_rules = *load_embedded_sip_ruleset();
  MediaRuleSet rules = *load_embedded_media_ruleset();
  Secret key = media_secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters sip_counters;
  sip::Context sip{sip_rules, mapper, {}, sip_counters};
  media::MediaCounters counters;
  media::RtcpEnv env{rules, mapper, sip, counters};

  std::uint32_t ssrc(std::uint32_t v) { return *mapper.ssrc(v); }
  std::string uri(std::string_view u) {
    auto r = sip::rewrite_uri_text(u, sip);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
};

inline void put16(Bytes& b, std::uint16_t v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v));
}
inline void put32(Bytes& b, std::uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) b.push_back(static_cast<std::uint8_t>(v >> s));
}
inline std::uint32_t get32(const Bytes& b, std::size_t off) {
  return (std::uint32_t{b[off]} << 24) | (std::uint32_t{b[off + 1]} << 16) | (std::uint32_t{b[off + 2]} << 8) |
         b[off + 3];
}
inline Bytes str(std::string_view s) { return Bytes(s.begin(), s.end()); }

// One application specific data field (TS 24.380 §8.1.3): ID, 1-octet length (2 octets from
// ID 192), value, zero padding to a multiple of 4 octets.
inline Bytes field(std::uint8_t id, const Bytes& value) {
  Bytes f{id};
  if (id < 192) {
    f.push_back(static_cast<std::uint8_t>(value.size()));
  } else {
    put16(f, static_cast<std::uint16_t>(value.size()));
  }
  f.insert(f.end(), value.begin(), value.end());
  while (f.size() % 4 != 0) f.push_back(0);
  return f;
}

// An RTCP APP packet (TS 24.380 §8.1.2): V=2, P=0, subtype, PT=204, length, SSRC, name, fields.
inline Bytes app(std::string_view name, std::uint8_t subtype, std::uint32_t ssrc, std::initializer_list<Bytes> fields) {
  Bytes body;
  put32(body, ssrc);
  body.insert(body.end(), name.begin(), name.end());
  for (const auto& f : fields) body.insert(body.end(), f.begin(), f.end());
  Bytes p{static_cast<std::uint8_t>(0x80 | subtype), 204};
  put16(p, static_cast<std::uint16_t>(body.size() / 4));
  p.insert(p.end(), body.begin(), body.end());
  return p;
}

// A generic RTCP packet with the given PT, count and body (a multiple of 4 octets).
inline Bytes rtcp(std::uint8_t pt, std::uint8_t count, const Bytes& body) {
  Bytes p{static_cast<std::uint8_t>(0x80 | count), pt};
  put16(p, static_cast<std::uint16_t>(body.size() / 4));
  p.insert(p.end(), body.begin(), body.end());
  return p;
}

// The fields of an APP packet after the 12-octet header, as (id, value) pairs.
inline std::vector<std::pair<std::uint8_t, Bytes>> fields_of(const Bytes& p) {
  std::vector<std::pair<std::uint8_t, Bytes>> out;
  std::size_t i = 12;
  const std::size_t end = 4 + 4 * ((std::size_t{p[2]} << 8) | p[3]);
  while (i + 2 <= end) {
    const std::uint8_t id = p[i];
    std::size_t len = 0, h = 2;
    if (id < 192) {
      len = p[i + 1];
    } else {
      len = (std::size_t{p[i + 1]} << 8) | p[i + 2];
      h = 3;
    }
    if (i + h + len > end) break;
    out.emplace_back(id, Bytes(p.begin() + static_cast<std::ptrdiff_t>(i + h),
                               p.begin() + static_cast<std::ptrdiff_t>(i + h + len)));
    i += (h + len + 3) / 4 * 4;
  }
  return out;
}

}  // namespace mcxanon::test
