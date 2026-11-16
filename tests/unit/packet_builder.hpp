// SPDX-License-Identifier: GPL-3.0-or-later
// Packet builders for unit tests: correct lengths and checksums.
#pragma once

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"
#include "dissect/packet.hpp"
#include "rewrite/checksum.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace mcxanon::test {

using Mac6 = std::array<std::uint8_t, 6>;
using V4 = std::array<std::uint8_t, 4>;
using V6 = std::array<std::uint8_t, 16>;

inline Bytes operator+(Bytes a, const Bytes& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}
inline Bytes b16(std::uint16_t v) { return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)}; }
inline Bytes b32(std::uint32_t v) {
  return {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16),
          static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
}
template <std::size_t N>
Bytes raw(const std::array<std::uint8_t, N>& a) { return Bytes(a.begin(), a.end()); }
inline Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

inline const Mac6 kMacA{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
inline const Mac6 kMacB{0x00, 0x66, 0x77, 0x88, 0x99, 0xAA};
inline const V4 kIpA{10, 1, 2, 3};
inline const V4 kIpB{192, 168, 7, 9};
inline const V6 kIp6A{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
inline const V6 kIp6B{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

inline Bytes eth(const Mac6& dst, const Mac6& src, std::uint16_t type, const Bytes& payload) {
  return raw(dst) + raw(src) + b16(type) + payload;
}

inline Bytes ipv4(const V4& src, const V4& dst, std::uint8_t proto, const Bytes& payload,
                  const Bytes& options = {}, std::uint16_t frag = 0x4000) {
  const std::size_t ihl = 20 + options.size();
  Bytes h{static_cast<std::uint8_t>(0x40 | (ihl / 4)), 0};
  h = h + b16(static_cast<std::uint16_t>(ihl + payload.size())) + b16(0x1234) + b16(frag) +
      Bytes{64, proto, 0, 0} + raw(src) + raw(dst) + options;
  store16(h, 10, inet_checksum(h), Endian::big);
  return h + payload;
}

inline Bytes ipv6(const V6& src, const V6& dst, std::uint8_t nh, const Bytes& payload) {
  return Bytes{0x60, 0, 0, 0} + b16(static_cast<std::uint16_t>(payload.size())) +
         Bytes{nh, 64} + raw(src) + raw(dst) + payload;
}

inline std::uint32_t pseudo_sum_v4(const V4& s, const V4& d, std::uint8_t proto, std::size_t len) {
  return inet_accumulate(raw(s) + raw(d) + Bytes{0, proto} + b16(static_cast<std::uint16_t>(len)));
}
inline std::uint32_t pseudo_sum_v6(const V6& s, const V6& d, std::uint8_t nh, std::size_t len) {
  return inet_accumulate(raw(s) + raw(d) + b32(static_cast<std::uint32_t>(len)) + Bytes{0, 0, 0, nh});
}

inline Bytes udp(std::uint16_t sport, std::uint16_t dport, const Bytes& payload,
                 std::uint32_t pseudo = 0) {
  Bytes u = b16(sport) + b16(dport) + b16(static_cast<std::uint16_t>(8 + payload.size())) +
            b16(0) + payload;
  std::uint16_t cs = static_cast<std::uint16_t>(~inet_fold_sum(inet_accumulate(u, pseudo)));
  if (cs == 0) cs = 0xFFFF;
  store16(u, 6, cs, Endian::big);
  return u;
}

inline Bytes tcp(std::uint16_t sport, std::uint16_t dport, std::uint32_t seq, std::uint32_t ack,
                 std::uint8_t flags, const Bytes& options, const Bytes& payload,
                 std::uint32_t pseudo = 0) {
  const std::size_t doff = 20 + options.size();
  Bytes t = b16(sport) + b16(dport) + b32(seq) + b32(ack) +
            Bytes{static_cast<std::uint8_t>((doff / 4) << 4), flags} + b16(65535) + b16(0) +
            b16(0) + options + payload;
  store16(t, 16, static_cast<std::uint16_t>(~inet_fold_sum(inet_accumulate(t, pseudo))),
          Endian::big);
  return t;
}

inline Bytes udp4(const V4& s, const V4& d, std::uint16_t sp, std::uint16_t dp, const Bytes& pl) {
  return ipv4(s, d, 17, udp(sp, dp, pl, pseudo_sum_v4(s, d, 17, 8 + pl.size())));
}
inline Bytes tcp4(const V4& s, const V4& d, std::uint16_t sp, std::uint16_t dp, std::uint32_t seq,
                  std::uint32_t ack, std::uint8_t flags, const Bytes& opts, const Bytes& pl) {
  const std::size_t len = 20 + opts.size() + pl.size();
  return ipv4(s, d, 6, tcp(sp, dp, seq, ack, flags, opts, pl, pseudo_sum_v4(s, d, 6, len)));
}

// SCTP packet: common header + chunks (each already padded); checksum CRC32c (little-endian).
inline Bytes sctp(std::uint16_t sport, std::uint16_t dport, std::uint32_t vtag, const Bytes& chunks) {
  Bytes s = b16(sport) + b16(dport) + b32(vtag) + b32(0) + chunks;
  store32(s, 8, crc32c(s), Endian::little);
  return s;
}
inline Bytes chunk(std::uint8_t type, std::uint8_t flags, const Bytes& value) {
  Bytes c = Bytes{type, flags} + b16(static_cast<std::uint16_t>(4 + value.size())) + value;
  while (c.size() % 4 != 0) c.push_back(0);
  return c;
}
inline Bytes param(std::uint16_t type, const Bytes& value) {
  Bytes p = b16(type) + b16(static_cast<std::uint16_t>(4 + value.size())) + value;
  while (p.size() % 4 != 0) p.push_back(0);
  return p;
}

// Checks that the fields cover the data exactly once, in order.
inline void require_full_coverage(const Dissection& d, std::size_t size) {
  std::size_t at = 0;
  for (const auto& f : d.fields) {
    INFO("field " << field_name(f.id) << " at " << f.offset << " len " << f.length);
    REQUIRE(f.offset == at);
    REQUIRE(f.length > 0);
    at += f.length;
  }
  REQUIRE(at == size);
}

inline const FieldInstance* find(const Dissection& d, Fid id, std::size_t nth = 0) {
  for (const auto& f : d.fields) {
    if (f.id == id && nth-- == 0) return &f;
  }
  return nullptr;
}
inline std::size_t count(const Dissection& d, Fid id) {
  std::size_t n = 0;
  for (const auto& f : d.fields) n += f.id == id ? 1 : 0;
  return n;
}
inline bool has_unknown(const Dissection& d, std::string_view kind, std::uint64_t id) {
  for (const auto& u : d.unknown) {
    if (u.kind == kind && u.id == id) return true;
  }
  return false;
}

inline Dissection dissect_checked(std::uint16_t lt, const Bytes& data, DissectOptions o = {}) {
  Dissection d = dissect(lt, data, o);
  require_full_coverage(d, data.size());
  return d;
}

}  // namespace mcxanon::test
