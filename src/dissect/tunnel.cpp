// SPDX-License-Identifier: GPL-3.0-or-later
// GRE (RFC 2784, RFC 2890) and GTP-U (3GPP TS 29.281 §5).
#include "dissect/ctx.hpp"

namespace mcxanon::detail {

void parse_gre(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (limit - p < 4) {
    c.parse_failure(p, limit, ip_layer);
    return;
  }
  const std::uint16_t flags = c.u16(p);
  const bool csum = (flags & 0x8000u) != 0;
  const bool routing = (flags & 0x4000u) != 0;
  const bool key = (flags & 0x2000u) != 0;
  const bool seq = (flags & 0x1000u) != 0;
  const unsigned version = flags & 0x7u;
  const std::size_t hlen = 4u + (csum ? 4u : 0u) + (key ? 4u : 0u) + (seq ? 4u : 0u);
  if (routing || version != 0 || limit - p < hlen) {
    c.unknown("gre_proto", c.u16(p + 2));
    c.rest(Fid::payload_unknown, p, limit, ip_layer);
    return;
  }
  Layer l;
  l.kind = LayerKind::gre;
  l.offset = p;
  l.header_len = hlen;
  l.end = limit;
  l.declared_end = limit;
  l.parent_ip = ip_layer;
  l.depth = f.depth;
  const int li = c.add_layer(l);
  c.emit(Fid::gre_flags, p, 2, li);
  c.emit(Fid::gre_proto, p + 2, 2, li);
  std::size_t q = p + 4;
  if (csum) {
    c.emit(Fid::gre_checksum, q, 2, li);
    c.emit(Fid::gre_reserved1, q + 2, 2, li);
    q += 4;
  }
  if (key) {
    c.emit(Fid::gre_key, q, 4, li);
    q += 4;
  }
  if (seq) {
    c.emit(Fid::gre_seq, q, 4, li);
    q += 4;
  }
  const std::uint16_t proto = c.u16(p + 2);
  switch (proto) {
    case 0x0800: parse_nested_ip(c, false, q, limit, f); return;
    case 0x86DD: parse_nested_ip(c, true, q, limit, f); return;
    case 0x6558: {  // Transparent Ethernet Bridging
      Frame inner = f;
      inner.depth = f.depth + 1;
      inner.parent_ip = -1;
      if (inner.depth > c.opt.max_depth) {
        c.out.depth_exceeded = true;
        c.unknown("parse_failure", 2);
        c.rest(Fid::payload_unparsed, q, limit, li);
        return;
      }
      parse_ethernet(c, q, limit, inner);
      return;
    }
    default:
      c.unknown("gre_proto", proto);
      c.rest(Fid::payload_unknown, q, limit, li);
      return;
  }
}

void parse_gtpu(Ctx& c, std::size_t p, std::size_t limit, int udp_layer, const Frame& f) {
  if (limit - p < 8 || (c.u8(p) >> 5) != 1 || (c.u8(p) & 0x10u) == 0) {
    c.rest(Fid::payload_l7, p, limit, udp_layer);  // not GTPv1-U
    return;
  }
  const std::uint8_t flags = c.u8(p);
  const std::uint8_t type = c.u8(p + 1);
  Layer l;
  l.kind = LayerKind::gtpu;
  l.offset = p;
  l.declared_end = p + 8 + c.u16(p + 2);
  l.end = std::min(limit, l.declared_end);
  l.parent_ip = c.layer(udp_layer).parent_ip;
  l.depth = f.depth;
  const int li = c.add_layer(l);
  c.emit(Fid::gtpu_flags, p, 1, li);
  c.emit(Fid::gtpu_type, p + 1, 1, li);
  c.emit(Fid::gtpu_len, p + 2, 2, li);
  c.emit(Fid::gtpu_teid, p + 4, 4, li);
  const std::size_t end = c.layer(li).end;
  std::size_t q = p + 8;
  if ((flags & 0x07u) != 0) {  // E, S or PN: sequence, N-PDU, next extension type follow
    if (end - q < 4) {
      c.parse_failure(q, limit, li);
      return;
    }
    c.emit(Fid::gtpu_opt, q, 3, li);
    c.emit(Fid::gtpu_next_ext, q + 3, 1, li);
    std::uint8_t next = (flags & 0x04u) != 0 ? c.u8(q + 3) : 0;
    q += 4;
    while (next != 0) {
      if (end - q < 1) {
        c.parse_failure(q, limit, li);
        return;
      }
      const std::size_t elen = static_cast<std::size_t>(c.u8(q)) * 4u;
      if (elen == 0 || elen > end - q) {
        c.parse_failure(q, limit, li);
        return;
      }
      c.emit(Fid::gtpu_ext_len, q, 1, li);
      switch (next) {
        case 0x85:  // PDU Session Container
          c.rest(Fid::gtpu_ext_pdu_session, q + 1, q + elen - 1, li);
          break;
        case 0x03: case 0x04: case 0x20: case 0x40: case 0x81: case 0x82: case 0x83: case 0x84:
        case 0x86: case 0xC0:
          c.rest(Fid::gtpu_ext_other, q + 1, q + elen - 1, li);
          break;
        default:
          c.unknown("gtpu_ext", next);
          c.rest(Fid::gtpu_ext_other, q + 1, q + elen - 1, li);
          break;
      }
      c.emit(Fid::gtpu_next_ext, q + elen - 1, 1, li);
      next = c.u8(q + elen - 1);
      q += elen;
    }
  }
  c.layer(li).header_len = q - p;
  if (type == 0xFF && q < end) {  // G-PDU: an encapsulated T-PDU
    const unsigned v = c.u8(q) >> 4;
    Frame inner = f;
    inner.parent_ip = -1;
    if (v == 4 || v == 6) {
      parse_nested_ip(c, v == 6, q, end, inner);
    } else {
      c.rest(Fid::payload_unknown, q, end, li);
    }
  } else {
    c.rest(Fid::payload_l7, q, end, li);
  }
  c.rest(Fid::payload_l7, end, limit, li);
}

}  // namespace mcxanon::detail
