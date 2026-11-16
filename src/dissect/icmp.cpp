// SPDX-License-Identifier: GPL-3.0-or-later
// ICMP (RFC 792), ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861).
#include "dissect/ctx.hpp"

namespace mcxanon::detail {
namespace {

int add_icmp_layer(Ctx& c, LayerKind k, std::size_t p, std::size_t limit, int ip_layer,
                   const Frame& f) {
  Layer l;
  l.kind = k;
  l.offset = p;
  l.header_len = 4;
  l.end = limit;
  l.declared_end = limit;
  l.parent_ip = ip_layer;
  l.depth = f.depth;
  l.embedded = f.embedded;
  return c.add_layer(l);
}

// The invoking packet inside an ICMP error message.
void parse_embedded(Ctx& c, bool v6, std::size_t p, std::size_t limit, int li, const Frame& f) {
  if (p >= limit) return;
  const std::size_t need = v6 ? 40u : 20u;
  if (limit - p < need) {
    c.rest(Fid::icmp_data, p, limit, li);
    return;
  }
  Frame e = f;
  e.embedded = true;
  e.parent_ip = -1;
  const std::size_t end = v6 ? parse_ipv6(c, p, limit, e) : parse_ipv4(c, p, limit, e);
  c.rest(Fid::icmp_data, end, limit, li);
}

void parse_ndp_options(Ctx& c, std::size_t p, std::size_t limit, int li) {
  while (p < limit) {
    if (limit - p < 2 || c.u8(p + 1) == 0 ||
        static_cast<std::size_t>(c.u8(p + 1)) * 8u > limit - p) {
      c.parse_failure(p, limit, li);
      return;
    }
    const std::uint8_t type = c.u8(p);
    const std::size_t len = static_cast<std::size_t>(c.u8(p + 1)) * 8u;
    c.emit(Fid::ndp_opt_hdr, p, 2, li);
    const std::size_t body = p + 2;
    const std::size_t oend = p + len;
    if ((type == 1 || type == 2) && len == 8) {
      c.emit(Fid::ndp_opt_lla, body, 6, li);
    } else if (type == 3 && len == 32) {
      c.emit(Fid::ndp_opt_prefix_fixed, body, 14, li);
      c.emit(Fid::ndp_opt_prefix_addr, body + 14, 16, li);
    } else if (type == 5 && len == 8) {
      c.emit(Fid::ndp_opt_mtu, body, 6, li);
    } else {
      if (type != 1 && type != 2 && type != 3 && type != 4 && type != 5) {
        c.unknown("ndp_option", type);
      }
      c.rest(Fid::ndp_opt_other, body, oend, li);
    }
    p = oend;
  }
}

}  // namespace

void parse_icmpv4(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (limit - p < 4) {
    c.parse_failure(p, limit, ip_layer);
    return;
  }
  const int li = add_icmp_layer(c, LayerKind::icmpv4, p, limit, ip_layer, f);
  c.emit(Fid::icmp_type_code, p, 2, li);
  c.emit(Fid::icmp_checksum, p + 2, 2, li);
  const std::size_t b = p + 4;
  if (limit - b < 4) {
    c.rest(Fid::icmp_data, b, limit, li);
    return;
  }
  switch (c.u8(p)) {
    case 0: case 8: case 13: case 14: case 15: case 16: case 17: case 18:
      c.emit(Fid::icmp_echo, b, 4, li);
      c.rest(Fid::icmp_data, b + 4, limit, li);
      return;
    case 3: case 4: case 11: case 12:
      c.emit(Fid::icmp_rest, b, 4, li);
      parse_embedded(c, false, b + 4, limit, li, f);
      return;
    case 5:
      c.emit(Fid::icmp_gateway, b, 4, li);
      parse_embedded(c, false, b + 4, limit, li, f);
      return;
    default:
      c.emit(Fid::icmp_other, b, 4, li);
      c.rest(Fid::icmp_data, b + 4, limit, li);
      return;
  }
}

void parse_icmpv6(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (limit - p < 4) {
    c.parse_failure(p, limit, ip_layer);
    return;
  }
  const int li = add_icmp_layer(c, LayerKind::icmpv6, p, limit, ip_layer, f);
  c.emit(Fid::icmpv6_type_code, p, 2, li);
  c.emit(Fid::icmpv6_checksum, p + 2, 2, li);
  const std::size_t b = p + 4;
  const std::uint8_t type = c.u8(p);
  const auto need = [&](std::size_t n) { return limit - b >= n; };
  switch (type) {
    case 1: case 2: case 3: case 4:
      if (!need(4)) break;
      c.emit(Fid::icmpv6_rest, b, 4, li);
      parse_embedded(c, true, b + 4, limit, li, f);
      return;
    case 128: case 129:
      if (!need(4)) break;
      c.emit(Fid::icmpv6_echo, b, 4, li);
      c.rest(Fid::icmp_data, b + 4, limit, li);
      return;
    case 133:  // Router Solicitation
      if (!need(4)) break;
      c.emit(Fid::ndp_fixed, b, 4, li);
      parse_ndp_options(c, b + 4, limit, li);
      return;
    case 134:  // Router Advertisement
      if (!need(12)) break;
      c.emit(Fid::ndp_fixed, b, 12, li);
      parse_ndp_options(c, b + 12, limit, li);
      return;
    case 135: case 136:  // Neighbor Solicitation / Advertisement
      if (!need(20)) break;
      c.emit(Fid::ndp_fixed, b, 4, li);
      c.emit(Fid::ndp_target, b + 4, 16, li);
      parse_ndp_options(c, b + 20, limit, li);
      return;
    case 137:  // Redirect
      if (!need(36)) break;
      c.emit(Fid::ndp_fixed, b, 4, li);
      c.emit(Fid::ndp_target, b + 4, 16, li);
      c.emit(Fid::ndp_dest, b + 20, 16, li);
      parse_ndp_options(c, b + 36, limit, li);
      return;
    default:
      break;
  }
  c.rest(Fid::icmp_data, b, limit, li);
}

}  // namespace mcxanon::detail
