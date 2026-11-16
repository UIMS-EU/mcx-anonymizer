// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "packet_builder.hpp"
#include "policy/decide.hpp"
#include "rewrite/apply.hpp"
#include "stream/tcp.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>

namespace mcxanon::test {

// A complete rule set built in code: addresses pseudonymised, numerics kept,
// lengths and checksums recomputed, options kept, opaque and payload zeroed.
inline RuleSet default_rules(std::optional<Fid> omit = std::nullopt) {
  RuleSet rs;
  rs.name = "test";
  rs.version = "0";
  for (std::size_t i = 0; i < static_cast<std::size_t>(Fid::count_); ++i) {
    const auto f = static_cast<Fid>(i);
    if (omit && *omit == f) continue;
    Rule r;
    r.field = std::string(field_name(f));
    r.source = {"test", "0", "0"};
    switch (field_kind(f)) {
      case FieldKind::address_mac: r.action = Action::pseudonymise; r.category = "mac"; break;
      case FieldKind::address_ipv4: r.action = Action::pseudonymise; r.category = "ipv4"; break;
      case FieldKind::address_ipv6: r.action = Action::pseudonymise; r.category = "ipv6"; break;
      case FieldKind::vlan:
      case FieldKind::port:
      case FieldKind::numeric: r.action = Action::keep; break;
      case FieldKind::length:
      case FieldKind::checksum: r.action = Action::recompute; break;
      case FieldKind::option: r.action = Action::keep; break;
      case FieldKind::payload:
      case FieldKind::opaque: r.action = Action::zero; break;
      case FieldKind::pcapng_block:
      case FieldKind::pcapng_option: r.action = Action::remove; break;
    }
    if (f == Fid::ipv4_opt_other || f == Fid::ipv6_opt_other || f == Fid::tcp_opt_other) {
      r.action = Action::pad;
    }
    rs.rules.push_back(r);
  }
  return rs;
}

// Deterministic stand-in for the pseudonymiser.
class FakeMapper : public AddressMapper {
 public:
  std::optional<Error> fail_with;
  Result<MacAddr> mac(const MacAddr& a) override {
    if (fail_with) return std::unexpected(*fail_with);
    if (a[0] & 1u) return a;
    MacAddr m = a;
    for (auto& v : m) v = static_cast<std::uint8_t>(v ^ 0xAA);
    m[0] = static_cast<std::uint8_t>((m[0] & 0xFC) | 0x02);
    return m;
  }
  Result<std::uint32_t> ipv4(std::uint32_t v) override {
    if (fail_with) return std::unexpected(*fail_with);
    if ((v >> 28) == 0xE) return 0xE9FC0000u | (v & 0xFFu);
    return 0xF0000000u | ((v ^ 0x00ABCDEFu) & 0x0FFFFFFFu);
  }
  Result<Ipv6Addr> ipv6(const Ipv6Addr& a) override {
    Ipv6Addr o = a;
    o[0] = 0x20;
    o[1] = 0x01;
    o[2] = 0x0d;
    o[3] = 0xb8;
    o[15] = static_cast<std::uint8_t>(o[15] ^ 0x5A);
    return o;
  }
  Result<std::uint16_t> vlan(std::uint16_t v) override { return static_cast<std::uint16_t>(v + 1); }
  Result<std::uint16_t> port(std::uint16_t p) override {
    return p >= 49152 ? static_cast<std::uint16_t>(p ^ 1) : p;
  }
  Result<std::string> text(Category c, std::string_view v) override {
    return std::string(to_string(c)) + ":" + std::string(v.substr(0, 4));
  }
  Result<std::string> domain(std::string_view) override { return std::string("d-0.invalid"); }
  Result<std::string> tel(std::string_view v) override { return std::string(v); }
  Result<std::string> sdp_version(std::string_view, std::string_view v) override {
    return std::string(v);
  }
  Result<std::uint32_t> spi(std::uint32_t v) override { return v < 256 ? v : v ^ 0x5A5A5A5Au; }
  Result<std::uint32_t> ssrc(std::uint32_t v) override { return v ^ 0xA5A5A5A5u; }
  Result<std::uint32_t> binary(Category c, std::uint32_t v) override {
    const unsigned bits = binary_bits(c);
    return bits >= 32 ? v ^ 0x5A5A5A5Au : (v ^ 0x5A5A5A5Au) & ((1u << bits) - 1u);
  }
};

struct Rewriter {
  RuleSet rules = default_rules();
  std::optional<Policy> policy;
  FakeMapper mapper;
  RewriteOptions options;
  RewriteStats stats;
  // The TCP stream layer without SIP: the feature-001 behaviour (zero mode keeps the numbers,
  // drop mode renumbers through the offset map).
  std::optional<stream::TcpStreams> streams;
  Rewriter() { policy.emplace(rules); }
  explicit Rewriter(RuleSet rs) : rules(std::move(rs)) { policy.emplace(rules); }
  PacketOutput run(std::uint16_t lt, const Bytes& in, std::size_t fcs = 0) {
    if (!streams) streams.emplace(stream::SipFns{}, options.payload == PayloadPolicy::drop);
    DissectOptions dopt;
    dopt.fcs_len = lt == kLinkEthernet ? fcs : 0;
    std::optional<TcpOverride> tcp;
    if (auto seg = stream::segment_of(dissect(lt, in, dopt), in, 0)) {
      std::vector<stream::TcpStreams::Ticket> ready;
      auto a = streams->segment(*seg, ready);
      REQUIRE(a.has_value());
      auto o = streams->take(a->ticket, true, ready);
      REQUIRE(o.has_value());
      tcp = TcpOverride{o->payload, o->seq, o->ack, o->sack, o->sack_known, o->sip};
    }
    auto r = rewrite_packet(lt, in, fcs, *policy, mapper, options, stats, nullptr, tcp ? &*tcp : nullptr);
    REQUIRE(r.has_value());
    return *r;
  }
};

// Independent checksum verification of a rewritten IPv4 / IPv6 packet.
inline bool ipv4_header_ok(const Bytes& p, std::size_t off = 0) {
  const std::size_t ihl = static_cast<std::size_t>(p[off] & 0x0F) * 4;
  return inet_checksum(ByteView(p).subspan(off, ihl)) == 0;
}
inline bool l4_ok_v4(const Bytes& p, std::size_t ip, std::uint8_t proto) {
  const std::size_t ihl = static_cast<std::size_t>(p[ip] & 0x0F) * 4;
  const std::size_t tot = be16(p, ip + 2);
  const std::size_t l4 = ip + ihl;
  const std::size_t len = tot - ihl;
  std::uint32_t acc = inet_accumulate(ByteView(p).subspan(ip + 12, 8));
  acc = inet_accumulate(Bytes{0, proto, static_cast<std::uint8_t>(len >> 8),
                              static_cast<std::uint8_t>(len)}, acc);
  acc = inet_accumulate(ByteView(p).subspan(l4, len), acc);
  return inet_fold_sum(acc) == 0xFFFF;
}
inline bool sctp_ok(const Bytes& p, std::size_t off, std::size_t end) {
  Bytes s(p.begin() + static_cast<std::ptrdiff_t>(off), p.begin() + static_cast<std::ptrdiff_t>(end));
  const std::uint32_t stored = load32(s, 8, Endian::little);
  store32(s, 8, 0, Endian::little);
  return crc32c(s) == stored;
}

}  // namespace mcxanon::test
