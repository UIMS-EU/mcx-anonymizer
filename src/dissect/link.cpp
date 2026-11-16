// SPDX-License-Identifier: GPL-3.0-or-later
// Link layer: Ethernet (IEEE 802.3), 802.1Q/802.1ad tags, Linux cooked v1/v2,
// BSD loopback, raw IP; ARP (RFC 826).
#include "dissect/ctx.hpp"

namespace mcxanon {

bool is_supported_linktype(std::uint16_t lt) {
  return lt == kLinkNull || lt == kLinkEthernet || lt == kLinkRaw || lt == kLinkSll ||
         lt == kLinkIpv4 || lt == kLinkIpv6 || lt == kLinkSll2;
}

namespace detail {
namespace {

std::size_t parse_arp(Ctx& c, std::size_t p, std::size_t limit, const Frame&) {
  Layer l;
  l.kind = LayerKind::arp;
  l.offset = p;
  if (limit - p < 8) {
    c.parse_failure(p, limit, -1);
    return limit;
  }
  const bool ether_ipv4 = c.u16(p) == 1 && c.u16(p + 2) == 0x0800 && c.u8(p + 4) == 6 &&
                          c.u8(p + 5) == 4;
  if (!ether_ipv4 || limit - p < 28) {
    l.header_len = 8;
    l.end = limit;
    const int li = c.add_layer(l);
    c.emit(Fid::arp_fixed, p, 8, li);
    c.unknown("ethertype", 0x0806);
    c.rest(Fid::payload_unknown, p + 8, limit, li);
    return limit;
  }
  l.header_len = 28;
  l.end = p + 28;
  const int li = c.add_layer(l);
  c.emit(Fid::arp_fixed, p, 8, li);
  c.emit(Fid::arp_sha, p + 8, 6, li);
  c.emit(Fid::arp_spa, p + 14, 4, li);
  c.emit(Fid::arp_tha, p + 18, 6, li);
  c.emit(Fid::arp_tpa, p + 24, 4, li);
  return p + 28;
}

// SLL / SLL2 link-layer address: 8 octets, of which halen are meaningful.
void emit_cooked_addr(Ctx& c, std::size_t off, std::uint8_t halen, int li, Fid addr, Fid pad,
                      Fid other) {
  if (halen == 6) {
    c.emit(addr, off, 6, li);
    c.emit(pad, off + 6, 2, li);
  } else {
    c.emit(other, off, 8, li);
  }
}

}  // namespace

std::size_t parse_ethertype(Ctx& c, std::uint16_t type, std::size_t p, std::size_t limit,
                            int link_layer, const Frame& f) {
  switch (type) {
    case 0x0800: return parse_ipv4(c, p, limit, f);
    case 0x86DD: return parse_ipv6(c, p, limit, f);
    case 0x0806: return parse_arp(c, p, limit, f);
    case 0x8100:
    case 0x88A8:
    case 0x9100: {
      if (limit - p < 4) {
        c.parse_failure(p, limit, link_layer);
        return limit;
      }
      Layer l;
      l.kind = LayerKind::vlan;
      l.offset = p;
      l.header_len = 4;
      l.end = limit;
      const int li = c.add_layer(l);
      c.emit(Fid::vlan_tci, p, 2, li);
      c.emit(Fid::vlan_type, p + 2, 2, li);
      return parse_ethertype(c, c.u16(p + 2), p + 4, limit, li, f);
    }
    default:
      c.unknown("ethertype", type);
      c.rest(Fid::payload_unknown, p, limit, link_layer);
      return limit;
  }
}

std::size_t parse_ethernet(Ctx& c, std::size_t p, std::size_t limit, const Frame& f) {
  if (limit - p < 14) {
    c.parse_failure(p, limit, -1);
    return limit;
  }
  Layer l;
  l.kind = LayerKind::ethernet;
  l.offset = p;
  l.header_len = 14;
  l.end = limit;
  l.depth = f.depth;
  const int li = c.add_layer(l);
  c.emit(Fid::eth_dst, p, 6, li);
  c.emit(Fid::eth_src, p + 6, 6, li);
  c.emit(Fid::eth_type, p + 12, 2, li);
  const std::size_t end = parse_ethertype(c, c.u16(p + 12), p + 14, limit, li, f);
  c.rest(Fid::link_trailer, end, limit, li);
  return limit;
}

}  // namespace detail

Dissection dissect(std::uint16_t linktype, ByteView data, const DissectOptions& options) {
  using namespace detail;
  Dissection out;
  out.linktype = linktype;
  Ctx c(data, out, options);
  const Frame top;
  const std::size_t n = data.size();
  switch (linktype) {
    case kLinkEthernet: {
      std::size_t limit = n;
      if (options.fcs_len > 0 && n >= 14 + options.fcs_len) limit = n - options.fcs_len;
      parse_ethernet(c, 0, limit, top);
      if (limit < n) {
        c.emit(Fid::eth_fcs, limit, n - limit, out.layers.empty() ? -1 : 0);
      }
      break;
    }
    case kLinkSll: {
      if (n < 16) {
        c.parse_failure(0, n, -1);
        break;
      }
      Layer l;
      l.kind = LayerKind::sll;
      l.header_len = 16;
      l.end = n;
      const int li = c.add_layer(l);
      c.emit(Fid::sll_pkttype, 0, 2, li);
      c.emit(Fid::sll_hatype, 2, 2, li);
      c.emit(Fid::sll_halen, 4, 2, li);
      emit_cooked_addr(c, 6, static_cast<std::uint8_t>(c.u16(4) == 6 ? 6 : 0), li, Fid::sll_addr,
                       Fid::sll_addr_pad, Fid::sll_addr_other);
      c.emit(Fid::sll_protocol, 14, 2, li);
      const std::size_t end = parse_ethertype(c, c.u16(14), 16, n, li, top);
      c.rest(Fid::link_trailer, end, n, li);
      break;
    }
    case kLinkSll2: {
      if (n < 20) {
        c.parse_failure(0, n, -1);
        break;
      }
      Layer l;
      l.kind = LayerKind::sll2;
      l.header_len = 20;
      l.end = n;
      const int li = c.add_layer(l);
      c.emit(Fid::sll2_protocol, 0, 2, li);
      c.emit(Fid::sll2_reserved, 2, 2, li);
      c.emit(Fid::sll2_ifindex, 4, 4, li);
      c.emit(Fid::sll2_hatype, 8, 2, li);
      c.emit(Fid::sll2_pkttype, 10, 1, li);
      c.emit(Fid::sll2_halen, 11, 1, li);
      emit_cooked_addr(c, 12, c.u8(11), li, Fid::sll2_addr, Fid::sll2_addr_pad,
                       Fid::sll2_addr_other);
      const std::size_t end = parse_ethertype(c, c.u16(0), 20, n, li, top);
      c.rest(Fid::link_trailer, end, n, li);
      break;
    }
    case kLinkNull: {
      if (n < 4) {
        c.parse_failure(0, n, -1);
        break;
      }
      Layer l;
      l.kind = LayerKind::null_loop;
      l.header_len = 4;
      l.end = n;
      const int li = c.add_layer(l);
      c.emit(Fid::null_family, 0, 4, li);
      // The family is in the capturing host's byte order: accept either.
      const std::uint32_t le = load32(data, 0, Endian::little);
      const std::uint32_t be = load32(data, 0, Endian::big);
      const auto fam = [&](std::uint32_t v) { return v == le || v == be; };
      std::size_t end = n;
      if (fam(2)) {
        end = parse_ipv4(c, 4, n, top);
      } else if (fam(24) || fam(28) || fam(30)) {
        end = parse_ipv6(c, 4, n, top);
      } else {
        c.unknown("linktype", kLinkNull);
        c.rest(Fid::payload_unknown, 4, n, li);
      }
      c.rest(Fid::link_trailer, end, n, li);
      break;
    }
    case kLinkRaw:
    case kLinkIpv4:
    case kLinkIpv6: {
      if (n == 0) break;
      const unsigned version = data[0] >> 4;
      std::size_t end = n;
      if (version == 4 && linktype != kLinkIpv6) {
        end = parse_ipv4(c, 0, n, top);
      } else if (version == 6 && linktype != kLinkIpv4) {
        end = parse_ipv6(c, 0, n, top);
      } else {
        c.parse_failure(0, n, -1);
      }
      c.rest(Fid::link_trailer, end, n, -1);
      break;
    }
    default:
      c.unknown("linktype", linktype);
      c.rest(Fid::payload_unknown, 0, n, -1);
      break;
  }
  return out;
}

}  // namespace mcxanon
