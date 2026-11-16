// SPDX-License-Identifier: GPL-3.0-or-later
// IPv4 (RFC 791) and its options; IPv6 (RFC 8200) and extension headers
// (RFC 8200 §4, RFC 6275 §6.3-6.4, RFC 8754 §2); AH (RFC 4302), ESP (RFC 4303).
#include "dissect/ctx.hpp"

namespace mcxanon::detail {
namespace {

void parse_ipv4_options(Ctx& c, std::size_t p, std::size_t end, int li) {
  while (p < end) {
    const std::uint8_t type = c.u8(p);
    if (type == 0) {  // End of Option List; the rest is padding
      c.emit(Fid::ipv4_opt_eol, p, 1, li);
      c.rest(Fid::ipv4_opt_padding, p + 1, end, li);
      return;
    }
    if (type == 1) {
      c.emit(Fid::ipv4_opt_nop, p, 1, li);
      ++p;
      continue;
    }
    if (end - p < 2) {
      c.unknown("ipv4_option", type);
      c.rest(Fid::ipv4_opt_malformed, p, end, li);
      return;
    }
    const std::size_t len = c.u8(p + 1);
    if (len < 2 || len > end - p) {
      c.unknown("ipv4_option", type);
      c.rest(Fid::ipv4_opt_malformed, p, end, li);
      return;
    }
    const std::size_t oend = p + len;
    if ((type == 7 || type == 131 || type == 137) && len >= 3 && (len - 3) % 4 == 0) {
      // Record Route, Loose / Strict Source Route: type, length, pointer, addresses.
      c.emit(Fid::ipv4_opt_route_hdr, p, 3, li);
      for (std::size_t a = p + 3; a < oend; a += 4) c.emit(Fid::ipv4_opt_route_addr, a, 4, li);
    } else if (type == 68 && len >= 4) {
      // Internet Timestamp: type, length, pointer, overflow/flags, then entries.
      const unsigned flags = c.u8(p + 3) & 0x0Fu;
      c.emit(Fid::ipv4_opt_ts_hdr, p, 4, li);
      if (flags == 0 && (len - 4) % 4 == 0) {
        for (std::size_t a = p + 4; a < oend; a += 4) c.emit(Fid::ipv4_opt_ts_value, a, 4, li);
      } else if ((flags == 1 || flags == 3) && (len - 4) % 8 == 0) {
        for (std::size_t a = p + 4; a < oend; a += 8) {
          c.emit(Fid::ipv4_opt_ts_addr, a, 4, li);
          c.emit(Fid::ipv4_opt_ts_value, a + 4, 4, li);
        }
      } else {
        c.rest(Fid::ipv4_opt_other, p + 4, oend, li);
      }
    } else {
      c.unknown("ipv4_option", type);
      c.emit(Fid::ipv4_opt_other, p, len, li);
    }
    p = oend;
  }
}

// IPv6 option TLVs of a Hop-by-Hop or Destination Options header.
void parse_ipv6_options(Ctx& c, std::size_t p, std::size_t end, int li) {
  while (p < end) {
    const std::uint8_t type = c.u8(p);
    if (type == 0) {
      c.emit(Fid::ipv6_opt_pad1, p, 1, li);
      ++p;
      continue;
    }
    if (end - p < 2 || c.u8(p + 1) > end - p - 2) {
      c.unknown("ipv6_option", type);
      c.rest(Fid::ipv6_opt_malformed, p, end, li);
      return;
    }
    const std::size_t len = 2u + c.u8(p + 1);
    switch (type) {
      case 1: c.emit(Fid::ipv6_opt_padn, p, len, li); break;
      case 5: c.emit(Fid::ipv6_opt_ra, p, len, li); break;
      case 0xC2:
        c.emit(Fid::ipv6_opt_jumbo, p, len, li);
        c.layer(li).jumbo = true;
        break;
      case 0xC9:
        if (len == 18) {
          c.emit(Fid::ipv6_opt_hao_hdr, p, 2, li);
          c.emit(Fid::ipv6_opt_hao_addr, p + 2, 16, li);
        } else {
          c.emit(Fid::ipv6_opt_other, p, len, li);
        }
        break;
      default:
        c.unknown("ipv6_option", type);
        c.emit(Fid::ipv6_opt_other, p, len, li);
        break;
    }
    p += len;
  }
}

void parse_routing(Ctx& c, std::size_t p, std::size_t hend, int li) {
  // p points at the Routing Type (after next header and length).
  c.emit(Fid::ipv6_rh_fixed, p, 2, li);
  const std::uint8_t rtype = c.u8(p);
  const std::size_t body = p + 2;
  if ((rtype == 0 || rtype == 2) && hend - body >= 4 && (hend - body - 4) % 16 == 0) {
    c.emit(Fid::ipv6_rh_reserved, body, 4, li);
    for (std::size_t a = body + 4; a < hend; a += 16) c.emit(Fid::ipv6_rh_addr, a, 16, li);
    return;
  }
  if (rtype == 4 && hend - body >= 4) {
    // Segment Routing Header: last entry, flags, tag; then segments, then TLVs.
    c.emit(Fid::ipv6_srh_fixed, body, 4, li);
    const std::size_t segs = static_cast<std::size_t>(c.u8(body)) + 1;
    std::size_t a = body + 4;
    if (segs * 16 > hend - a) {
      c.rest(Fid::ipv6_rh_data, a, hend, li);
      return;
    }
    for (std::size_t i = 0; i < segs; ++i, a += 16) c.emit(Fid::ipv6_srh_seg, a, 16, li);
    c.rest(Fid::ipv6_srh_tlv, a, hend, li);
    return;
  }
  c.rest(Fid::ipv6_rh_data, body, hend, li);
}

}  // namespace

std::size_t parse_ipv4(Ctx& c, std::size_t p, std::size_t limit, const Frame& f) {
  if (limit - p < 20 || (c.u8(p) >> 4) != 4) {
    c.parse_failure(p, limit, f.parent_ip);
    return limit;
  }
  const std::size_t ihl = static_cast<std::size_t>(c.u8(p) & 0x0Fu) * 4u;
  const std::size_t totlen = c.u16(p + 2);
  if (ihl < 20 || ihl > limit - p || (!f.embedded && totlen < ihl)) {
    c.parse_failure(p, limit, f.parent_ip);
    return limit;
  }
  Layer l;
  l.kind = LayerKind::ipv4;
  l.offset = p;
  l.header_len = ihl;
  l.declared_end = p + totlen;
  l.end = f.embedded ? limit : std::min(limit, l.declared_end);
  l.parent_ip = f.parent_ip;
  l.depth = f.depth;
  l.embedded = f.embedded;
  l.upper_offset = p + ihl;
  const std::uint16_t frag = c.u16(p + 6);
  const bool mf = (frag & 0x2000u) != 0;
  const std::size_t frag_off = static_cast<std::size_t>(frag & 0x1FFFu) * 8u;
  l.fragment_nonfirst = frag_off > 0;
  l.fragment_first = mf && frag_off == 0;
  l.fragment_field = p + 6;
  const int li = c.add_layer(l);
  c.emit(Fid::ipv4_vihl, p, 1, li);
  c.emit(Fid::ipv4_tos, p + 1, 1, li);
  c.emit(Fid::ipv4_totlen, p + 2, 2, li);
  c.emit(Fid::ipv4_id, p + 4, 2, li);
  c.emit(Fid::ipv4_frag, p + 6, 2, li);
  c.emit(Fid::ipv4_ttl, p + 8, 1, li);
  c.emit(Fid::ipv4_proto, p + 9, 1, li);
  c.emit(Fid::ipv4_checksum, p + 10, 2, li);
  c.emit(Fid::ipv4_src, p + 12, 4, li);
  c.emit(Fid::ipv4_dst, p + 16, 4, li);
  parse_ipv4_options(c, p + 20, p + ihl, li);
  const std::size_t end = c.layer(li).end;
  Frame inner = f;
  inner.parent_ip = li;
  if (l.fragment_nonfirst) {
    c.rest(Fid::payload_fragment, p + ihl, end, li);
  } else {
    parse_ip_upper(c, c.u8(p + 9), false, p + ihl, end, li, inner);
  }
  return end;
}

std::size_t parse_ipv6(Ctx& c, std::size_t p, std::size_t limit, const Frame& f) {
  if (limit - p < 40 || (c.u8(p) >> 4) != 6) {
    c.parse_failure(p, limit, f.parent_ip);
    return limit;
  }
  const std::size_t plen = c.u16(p + 4);
  Layer l;
  l.kind = LayerKind::ipv6;
  l.offset = p;
  l.declared_end = p + 40 + plen;
  l.end = f.embedded ? limit : std::min(limit, l.declared_end);
  l.parent_ip = f.parent_ip;
  l.depth = f.depth;
  l.embedded = f.embedded;
  const int li = c.add_layer(l);
  c.emit(Fid::ipv6_vtcfl, p, 4, li);
  c.emit(Fid::ipv6_plen, p + 4, 2, li);
  c.emit(Fid::ipv6_nh, p + 6, 1, li);
  c.emit(Fid::ipv6_hlim, p + 7, 1, li);
  c.emit(Fid::ipv6_src, p + 8, 16, li);
  c.emit(Fid::ipv6_dst, p + 24, 16, li);

  std::uint8_t nh = c.u8(p + 6);
  std::size_t q = p + 40;
  // plen == 0 with a Jumbo Payload option: the extent is the captured data.
  auto end = [&] { return c.layer(li).end; };
  for (;;) {
    if (nh == 0 || nh == 60 || nh == 43) {
      if (end() - q < 8) {
        c.parse_failure(q, end(), li);
        return end();
      }
      const std::size_t hlen = (static_cast<std::size_t>(c.u8(q + 1)) + 1u) * 8u;
      if (hlen > end() - q) {
        c.parse_failure(q, end(), li);
        return end();
      }
      c.emit(Fid::ipv6_ext_hdr, q, 2, li);
      if (nh == 43) {
        parse_routing(c, q + 2, q + hlen, li);
      } else {
        parse_ipv6_options(c, q + 2, q + hlen, li);
        if (nh == 0 && c.layer(li).jumbo && plen == 0 && !f.embedded) {
          c.layer(li).end = limit;
          c.layer(li).declared_end = limit;
        }
      }
      nh = c.u8(q);
      q += hlen;
      continue;
    }
    if (nh == 44) {
      if (end() - q < 8) {
        c.parse_failure(q, end(), li);
        return end();
      }
      c.emit(Fid::ipv6_frag, q, 8, li);
      const std::uint16_t fo = c.u16(q + 2);
      const std::size_t off = static_cast<std::size_t>(fo >> 3) * 8u;
      c.layer(li).fragment_field = q;
      c.layer(li).fragment_nonfirst = off > 0;
      c.layer(li).fragment_first = (fo & 1u) != 0 && off == 0;
      nh = c.u8(q);
      q += 8;
      if (c.layer(li).fragment_nonfirst) {
        c.layer(li).upper_offset = q;
        c.layer(li).header_len = q - p;
        c.rest(Fid::payload_fragment, q, end(), li);
        return end();
      }
      continue;
    }
    if (nh == 51) {  // AH
      if (end() - q < 12) {
        c.parse_failure(q, end(), li);
        return end();
      }
      const std::size_t alen = (static_cast<std::size_t>(c.u8(q + 1)) + 2u) * 4u;
      if (alen < 12 || alen > end() - q) {
        c.parse_failure(q, end(), li);
        return end();
      }
      c.emit(Fid::ah_fixed, q, 4, li);
      c.emit(Fid::ah_spi, q + 4, 4, li);
      c.emit(Fid::ah_seq, q + 8, 4, li);
      c.rest(Fid::ah_icv, q + 12, q + alen, li);
      nh = c.u8(q);
      q += alen;
      continue;
    }
    break;
  }
  c.layer(li).upper_offset = q;
  c.layer(li).header_len = q - p;
  Frame inner = f;
  inner.parent_ip = li;
  parse_ip_upper(c, nh, true, q, end(), li, inner);
  return end();
}

void parse_nested_ip(Ctx& c, bool v6, std::size_t p, std::size_t limit, const Frame& f) {
  Frame inner = f;
  inner.depth = f.depth + 1;
  if (inner.depth > c.opt.max_depth) {
    c.out.depth_exceeded = true;
    c.unknown("parse_failure", 2);
    c.rest(Fid::payload_unparsed, p, limit, f.parent_ip);
    return;
  }
  const std::size_t end = v6 ? parse_ipv6(c, p, limit, inner) : parse_ipv4(c, p, limit, inner);
  c.rest(Fid::link_trailer, end, limit, f.parent_ip);
}

void parse_ip_upper(Ctx& c, std::uint8_t proto, bool v6, std::size_t p, std::size_t limit,
                    int ip_layer, const Frame& f) {
  if (p >= limit) return;
  if (f.embedded) {
    // Inside an ICMP error only the first bytes of the transport header are present.
    switch (proto) {
      case 6: parse_tcp(c, p, limit, ip_layer, f); return;
      case 17: parse_udp(c, p, limit, ip_layer, f); return;
      case 132: parse_sctp(c, p, limit, ip_layer, f); return;
      default: c.rest(Fid::icmp_data, p, limit, ip_layer); return;
    }
  }
  switch (proto) {
    case 1: parse_icmpv4(c, p, limit, ip_layer, f); return;
    case 58: parse_icmpv6(c, p, limit, ip_layer, f); return;
    case 6: parse_tcp(c, p, limit, ip_layer, f); return;
    case 17: parse_udp(c, p, limit, ip_layer, f); return;
    case 132: parse_sctp(c, p, limit, ip_layer, f); return;
    case 47: parse_gre(c, p, limit, ip_layer, f); return;
    case 4: parse_nested_ip(c, false, p, limit, f); return;
    case 41: parse_nested_ip(c, true, p, limit, f); return;
    case 59: c.rest(Fid::payload_l7, p, limit, ip_layer); return;  // No Next Header
    case 50:                                                        // ESP
      if (limit - p < 8) {
        c.parse_failure(p, limit, ip_layer);
        return;
      }
      c.emit(Fid::esp_spi, p, 4, ip_layer);
      c.emit(Fid::esp_seq, p + 4, 4, ip_layer);
      c.rest(Fid::payload_encrypted, p + 8, limit, ip_layer);
      return;
    case 51: {  // AH over IPv4 (IPv6 handles AH in its extension chain)
      if (limit - p < 12) {
        c.parse_failure(p, limit, ip_layer);
        return;
      }
      const std::size_t alen = (static_cast<std::size_t>(c.u8(p + 1)) + 2u) * 4u;
      if (alen < 12 || alen > limit - p) {
        c.parse_failure(p, limit, ip_layer);
        return;
      }
      c.emit(Fid::ah_fixed, p, 4, ip_layer);
      c.emit(Fid::ah_spi, p + 4, 4, ip_layer);
      c.emit(Fid::ah_seq, p + 8, 4, ip_layer);
      c.rest(Fid::ah_icv, p + 12, p + alen, ip_layer);
      parse_ip_upper(c, c.u8(p), v6, p + alen, limit, ip_layer, f);
      return;
    }
    default:
      c.unknown(v6 ? "ipv6_nh" : "ip_proto", proto);
      c.rest(Fid::payload_unknown, p, limit, ip_layer);
      return;
  }
}

}  // namespace mcxanon::detail
