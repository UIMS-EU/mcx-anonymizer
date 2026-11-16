// SPDX-License-Identifier: GPL-3.0-or-later
// TCP (RFC 9293, options RFC 7323, RFC 2018, RFC 2385, RFC 5925), UDP (RFC 768)
// and SCTP (RFC 9260, RFC 5061, RFC 4895, RFC 8260, RFC 3758).
#include "dissect/ctx.hpp"

#include <algorithm>

namespace mcxanon::detail {
namespace {

Layer l4_layer(LayerKind k, std::size_t p, std::size_t hlen, std::size_t limit, int ip_layer,
               const Frame& f) {
  Layer l;
  l.kind = k;
  l.offset = p;
  l.header_len = hlen;
  l.end = limit;
  l.declared_end = limit;
  l.parent_ip = ip_layer;
  l.depth = f.depth;
  l.embedded = f.embedded;
  return l;
}

void parse_tcp_options(Ctx& c, std::size_t p, std::size_t end, int li) {
  while (p < end) {
    const std::uint8_t kind = c.u8(p);
    if (kind == 0) {
      c.emit(Fid::tcp_opt_eol, p, 1, li);
      c.rest(Fid::tcp_opt_padding, p + 1, end, li);
      return;
    }
    if (kind == 1) {
      c.emit(Fid::tcp_opt_nop, p, 1, li);
      ++p;
      continue;
    }
    if (end - p < 2 || c.u8(p + 1) < 2 || c.u8(p + 1) > end - p) {
      c.unknown("tcp_option", kind);
      c.rest(Fid::tcp_opt_malformed, p, end, li);
      return;
    }
    const std::size_t len = c.u8(p + 1);
    switch (kind) {
      case 2: c.emit(len == 4 ? Fid::tcp_opt_mss : Fid::tcp_opt_other, p, len, li); break;
      case 3: c.emit(len == 3 ? Fid::tcp_opt_wscale : Fid::tcp_opt_other, p, len, li); break;
      case 4: c.emit(len == 2 ? Fid::tcp_opt_sackperm : Fid::tcp_opt_other, p, len, li); break;
      case 5:
        c.emit((len - 2) % 8 == 0 ? Fid::tcp_opt_sack : Fid::tcp_opt_other, p, len, li);
        break;
      case 8: c.emit(len == 10 ? Fid::tcp_opt_ts : Fid::tcp_opt_other, p, len, li); break;
      case 19:
        c.emit(Fid::tcp_opt_md5_hdr, p, 2, li);
        c.rest(Fid::tcp_opt_md5_value, p + 2, p + len, li);
        break;
      case 29:
        c.emit(Fid::tcp_opt_ao_hdr, p, 2, li);
        c.rest(Fid::tcp_opt_ao_value, p + 2, p + len, li);
        break;
      default:
        c.unknown("tcp_option", kind);
        c.emit(Fid::tcp_opt_other, p, len, li);
        break;
    }
    p += len;
  }
}

// SCTP parameters (RFC 9260 §3.2.1): type, length, value, padding to 4.
void parse_sctp_params(Ctx& c, std::size_t p, std::size_t end, int li, int nesting = 0) {
  while (p < end) {
    if (end - p < 4 || c.u16(p + 2) < 4 || c.u16(p + 2) > end - p) {
      c.rest(Fid::sctp_param_other, p, end, li);
      return;
    }
    const std::uint16_t type = c.u16(p);
    const std::size_t len = c.u16(p + 2);
    const std::size_t v = p + 4;
    const std::size_t vend = p + len;
    c.emit(Fid::sctp_param_hdr, p, 4, li);
    switch (type) {
      case 5:  // IPv4 Address
        if (len == 8) c.emit(Fid::sctp_param_ipv4, v, 4, li);
        else c.rest(Fid::sctp_param_other, v, vend, li);
        break;
      case 6:  // IPv6 Address
        if (len == 20) c.emit(Fid::sctp_param_ipv6, v, 16, li);
        else c.rest(Fid::sctp_param_other, v, vend, li);
        break;
      case 9:       // Cookie Preservative
      case 12:      // Supported Address Types
      case 0x8000:  // ECN Capable
      case 0x8001:  // Adaptation Layer Indication
      case 0x8008:  // Supported Extensions
      case 0xC000:  // Forward-TSN Supported
        c.rest(Fid::sctp_param_keep, v, vend, li);
        break;
      case 0xC001:  // Add IP Address (RFC 5061 §4.2)
      case 0xC002:  // Delete IP Address
      case 0xC004:  // Set Primary Address
        if (vend - v >= 4 && nesting == 0) {
          c.emit(Fid::sctp_asconf_corr, v, 4, li);
          parse_sctp_params(c, v + 4, vend, li, nesting + 1);
        } else {
          c.rest(Fid::sctp_param_other, v, vend, li);
        }
        break;
      case 0xC005:  // Success Indication
        if (vend - v == 4) c.emit(Fid::sctp_asconf_corr, v, 4, li);
        else c.rest(Fid::sctp_param_other, v, vend, li);
        break;
      default:  // State Cookie, Host Name, Random, HMAC algorithms, error causes, unknown
        c.rest(Fid::sctp_param_other, v, vend, li);
        break;
    }
    const std::size_t padded = std::min(end, p + pad4(len));
    c.rest(Fid::sctp_padding, vend, padded, li);
    p = padded;
  }
}

}  // namespace

void parse_tcp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (f.embedded) {
    if (limit - p < 8) {
      c.rest(Fid::icmp_data, p, limit, ip_layer);
      return;
    }
    const int li = c.add_layer(l4_layer(LayerKind::tcp, p, 8, limit, ip_layer, f));
    c.emit(Fid::tcp_sport, p, 2, li);
    c.emit(Fid::tcp_dport, p + 2, 2, li);
    c.emit(Fid::icmp_embedded_l4_rest, p + 4, 4, li);
    c.rest(Fid::icmp_data, p + 8, limit, li);
    return;
  }
  if (limit - p < 20) {
    c.parse_failure(p, limit, ip_layer);
    return;
  }
  const std::size_t doff = static_cast<std::size_t>(c.u8(p + 12) >> 4) * 4u;
  if (doff < 20) {
    c.parse_failure(p, limit, ip_layer);
    return;
  }
  const std::size_t hend = std::min(limit, p + doff);
  const int li = c.add_layer(l4_layer(LayerKind::tcp, p, hend - p, limit, ip_layer, f));
  c.emit(Fid::tcp_sport, p, 2, li);
  c.emit(Fid::tcp_dport, p + 2, 2, li);
  c.emit(Fid::tcp_seq, p + 4, 4, li);
  c.emit(Fid::tcp_ack, p + 8, 4, li);
  c.emit(Fid::tcp_offflags, p + 12, 2, li);
  c.emit(Fid::tcp_window, p + 14, 2, li);
  c.emit(Fid::tcp_checksum, p + 16, 2, li);
  c.emit(Fid::tcp_urg, p + 18, 2, li);
  parse_tcp_options(c, p + 20, hend, li);
  c.rest(c.opt.tcp_payload_sip && !f.embedded ? Fid::payload_sip : Fid::payload_l7, hend, limit, li);
}

namespace {
// True when any enclosing IP layer is a fragment of a larger datagram.
bool inside_fragment(const Ctx& c) {
  return std::any_of(c.out.layers.begin(), c.out.layers.end(), [](const Layer& l) {
    return (l.kind == LayerKind::ipv4 || l.kind == LayerKind::ipv6) &&
           (l.fragment_first || l.fragment_nonfirst);
  });
}
}  // namespace

namespace {
// Calls the media classifier with the innermost IP addresses and the UDP ports (feature 004).
int classify_media(Ctx& c, std::size_t p, std::size_t end, int ip_layer, int udp_layer) {
  if (ip_layer < 0) return 0;
  const Layer& ip = c.layer(ip_layer);
  UdpFlowView v;
  if (ip.kind == LayerKind::ipv4) {
    v.src = c.data.subspan(ip.offset + 12, 4);
    v.dst = c.data.subspan(ip.offset + 16, 4);
  } else if (ip.kind == LayerKind::ipv6) {
    v.src = c.data.subspan(ip.offset + 8, 16);
    v.dst = c.data.subspan(ip.offset + 24, 16);
  } else {
    return 0;
  }
  v.sport = c.u16(p);
  v.dport = c.u16(p + 2);
  v.depth = c.layer(udp_layer).depth;
  return c.opt.classify_media(v, c.data.subspan(p + 8, end - (p + 8)), c.opt.classify_media_ctx);
}
}  // namespace

void parse_udp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (limit - p < 8) {
    if (f.embedded) c.rest(Fid::icmp_data, p, limit, ip_layer);
    else c.parse_failure(p, limit, ip_layer);
    return;
  }
  Layer l = l4_layer(LayerKind::udp, p, 8, limit, ip_layer, f);
  const std::size_t ulen = c.u16(p + 4);
  if (!f.embedded && ulen >= 8) {
    l.declared_end = p + ulen;
    l.end = std::min(limit, l.declared_end);
  }
  const int li = c.add_layer(l);
  c.emit(Fid::udp_sport, p, 2, li);
  c.emit(Fid::udp_dport, p + 2, 2, li);
  if (f.embedded) {
    c.emit(Fid::icmp_embedded_l4_rest, p + 4, 2, li);
    c.emit(Fid::icmp_embedded_l4_checksum, p + 6, 2, li);
    c.rest(Fid::icmp_data, p + 8, limit, li);
    return;
  }
  c.emit(Fid::udp_len, p + 4, 2, li);
  c.emit(Fid::udp_checksum, p + 6, 2, li);
  const std::size_t end = c.layer(li).end;
  // GTP-U on its registered port 2152 (3GPP TS 29.281 §4.4.2).
  if (c.u16(p) == 2152 || c.u16(p + 2) == 2152) {
    parse_gtpu(c, p + 8, end, li, f);
  } else if (end > p + 8 && c.opt.recognise_sip != nullptr && !inside_fragment(c) &&
             c.opt.recognise_sip(c.data.subspan(p + 8, end - (p + 8)))) {
    // One SIP message per datagram (RFC 3261 §18.3). A fragment never reaches here: a first
    // fragment holds only part of the datagram, so it is left to the fragment table.
    c.rest(Fid::payload_sip, p + 8, end, li);
  } else if (const int tag = end > p + 8 && c.opt.classify_media != nullptr && !inside_fragment(c)
                                 ? classify_media(c, p, end, ip_layer, li)
                                 : 0;
             tag != 0) {
    c.rest(Fid::payload_media, p + 8, end, li);
    c.out.media_tag = tag;
  } else {
    c.rest(Fid::payload_l7, p + 8, end, li);
  }
  c.rest(Fid::payload_l7, end, limit, li);  // bytes beyond the UDP length
}

void parse_sctp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f) {
  if (limit - p < 12) {
    if (f.embedded) {
      if (limit - p >= 8) {
        const int li = c.add_layer(l4_layer(LayerKind::sctp, p, 8, limit, ip_layer, f));
        c.emit(Fid::sctp_sport, p, 2, li);
        c.emit(Fid::sctp_dport, p + 2, 2, li);
        c.emit(Fid::sctp_vtag, p + 4, 4, li);
        c.rest(Fid::icmp_data, p + 8, limit, li);
      } else {
        c.rest(Fid::icmp_data, p, limit, ip_layer);
      }
    } else {
      c.parse_failure(p, limit, ip_layer);
    }
    return;
  }
  const int li = c.add_layer(l4_layer(LayerKind::sctp, p, 12, limit, ip_layer, f));
  c.emit(Fid::sctp_sport, p, 2, li);
  c.emit(Fid::sctp_dport, p + 2, 2, li);
  c.emit(Fid::sctp_vtag, p + 4, 4, li);
  if (f.embedded) {
    c.emit(Fid::icmp_embedded_l4_checksum, p + 8, 4, li);
    c.rest(Fid::icmp_data, p + 12, limit, li);
    return;
  }
  c.emit(Fid::sctp_checksum, p + 8, 4, li);
  std::size_t q = p + 12;
  while (q < limit) {
    if (limit - q < 4 || c.u16(q + 2) < 4) {
      c.parse_failure(q, limit, li);
      return;
    }
    const std::uint8_t type = c.u8(q);
    const std::size_t len = c.u16(q + 2);
    const std::size_t cend = std::min(limit, q + len);
    c.emit(Fid::sctp_chunk_hdr, q, 2, li);
    c.emit(Fid::sctp_chunk_len, q + 2, 2, li);
    const std::size_t b = q + 4;
    const auto fixed_then = [&](Fid fixed, std::size_t n, Fid then) {
      if (cend - b < n) {
        c.rest(Fid::sctp_chunk_other, b, cend, li);
        return;
      }
      c.emit(fixed, b, n, li);
      c.rest(then, b + n, cend, li);
    };
    switch (type) {
      case 0: fixed_then(Fid::sctp_data_fixed, 12, Fid::payload_l7); break;
      case 64: fixed_then(Fid::sctp_idata_fixed, 16, Fid::payload_l7); break;
      case 1:
      case 2:
        if (cend - b < 16) {
          c.rest(Fid::sctp_chunk_other, b, cend, li);
        } else {
          c.emit(Fid::sctp_init_fixed, b, 16, li);
          parse_sctp_params(c, b + 16, cend, li);
        }
        break;
      case 3: c.rest(Fid::sctp_sack_body, b, cend, li); break;
      case 7: c.rest(Fid::sctp_shutdown_body, b, cend, li); break;
      case 12:
      case 13: c.rest(Fid::sctp_ecn_body, b, cend, li); break;
      case 0xC0: c.rest(Fid::sctp_fwdtsn_body, b, cend, li); break;
      case 15: fixed_then(Fid::sctp_auth_fixed, 4, Fid::sctp_auth_hmac); break;
      case 0xC1:  // ASCONF: serial, then an address parameter and ASCONF parameters
      case 0x80:  // ASCONF-ACK: serial, then ASCONF parameter responses
        if (cend - b < 4) {
          c.rest(Fid::sctp_chunk_other, b, cend, li);
        } else {
          c.emit(Fid::sctp_asconf_serial, b, 4, li);
          parse_sctp_params(c, b + 4, cend, li);
        }
        break;
      case 4: case 5: case 6: case 8: case 9: case 10: case 11: case 14:
        c.rest(Fid::sctp_chunk_other, b, cend, li);
        break;
      default:
        c.unknown("sctp_chunk", type);
        c.rest(Fid::sctp_chunk_other, b, cend, li);
        break;
    }
    const std::size_t padded = std::min(limit, q + pad4(len));
    c.rest(Fid::sctp_padding, cend, padded, li);
    q = padded;
  }
}

}  // namespace mcxanon::detail
