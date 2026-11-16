// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal L2-L4 header walk for the scanner (FR-031 b, FR-032a): the byte
// ranges of recognised header fields, the positions where an IPv4 address can
// legitimately sit, and the header addresses. Tunnels (IP-in-IP, GRE, GTP-U)
// and the packet quoted by ICMP error messages are followed a few levels deep.
// Anything not recognised is left out, so matches there always count.
#include "scan/walker/walker.hpp"

#include <algorithm>

namespace mcxanon::scan::detail {
namespace {

constexpr int kMaxDepth = 4;

std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }

}  // namespace

bool keeps_ipv4(const std::uint8_t* a) {
  const bool zero = a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0;
  const bool bcast = a[0] == 255 && a[1] == 255 && a[2] == 255 && a[3] == 255;
  const bool loop = a[0] == 127;
  const bool local_mcast = a[0] == 224 && a[1] == 0 && (a[2] == 0 || a[2] == 1);
  return zero || bcast || loop || local_mcast;
}

bool keeps_ipv6(const std::uint8_t* a) {
  bool zero15 = true;
  for (int i = 0; i < 15; ++i) zero15 = zero15 && a[i] == 0;
  if (zero15 && (a[15] == 0 || a[15] == 1)) return true;
  if (a[0] == 0xFF) {
    const bool solicited = a[1] == 0x02 && a[11] == 0x01 && a[12] == 0xFF;
    const bool permanent = (a[1] & 0x10) == 0;
    return permanent && !solicited;
  }
  return false;
}

namespace {

bool keep_v4(const std::uint8_t* a) { return keeps_ipv4(a); }
bool keep_v6(const std::uint8_t* a) { return keeps_ipv6(a); }

class Walk {
 public:
  Walk(std::span<const std::uint8_t> p, std::uint64_t base, std::vector<Range>* header,
       std::vector<std::uint64_t>* slots, std::vector<Address>* addrs,
       std::vector<Payload>* payloads = nullptr)
      : p_(p), base_(base), header_(header), slots_(slots), addrs_(addrs), payloads_(payloads) {}

  void link(std::uint16_t lt) {
    switch (lt) {
      case 1: ethernet(0, 0); return;
      case 113:  // Linux cooked v1
        if (!has(0, 16)) return;
        field(0, 16);
        if (be16(at(4)) == 6) mac(6);
        ether_type(be16(at(14)), 16, 0);
        return;
      case 276:  // Linux cooked v2
        if (!has(0, 20)) return;
        field(0, 20);
        if (p_[11] == 6) mac(12);
        ether_type(be16(at(0)), 20, 0);
        return;
      case 0:  // BSD loopback
        if (!has(0, 5)) return;
        field(0, 4);
        ip_by_version(4, 0);
        return;
      case 101: case 228: case 229:
        ip_by_version(0, 0);
        return;
      default:
        return;
    }
  }

 private:
  [[nodiscard]] bool has(std::size_t off, std::size_t n) const { return off <= p_.size() && n <= p_.size() - off; }
  [[nodiscard]] const std::uint8_t* at(std::size_t off) const { return p_.data() + off; }
  void field(std::size_t a, std::size_t b) {
    if (header_ != nullptr && b <= p_.size()) header_->push_back({base_ + a, base_ + b});
  }
  void slot(std::size_t a) {
    if (slots_ != nullptr) slots_->push_back(base_ + a);
  }
  void mac(std::size_t off) {
    if (addrs_ == nullptr || !has(off, 6)) return;
    const std::uint8_t* m = at(off);
    const bool group = (m[0] & 1u) != 0;
    const bool zero = std::all_of(m, m + 6, [](auto v) { return v == 0; });
    if (!group && !zero) addrs_->push_back({1, std::vector<std::uint8_t>(m, m + 6)});
  }
  void v4(std::size_t off) {
    slot(off);
    if (addrs_ != nullptr && !keep_v4(at(off))) addrs_->push_back({4, std::vector<std::uint8_t>(at(off), at(off) + 4)});
  }
  // IPv4 addresses embedded in IPv6 addresses with a well-known embedding
  // prefix keep their position unsuppressed.
  void v6(std::size_t off) {
    const std::uint8_t* a = at(off);
    const bool zero80 = std::all_of(a, a + 10, [](auto v) { return v == 0; });
    const bool mapped_or_compat = zero80 && ((a[10] == 0 && a[11] == 0) || (a[10] == 0xFF && a[11] == 0xFF));
    const bool nat64 = a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xFF && a[3] == 0x9B &&
                       std::all_of(a + 4, a + 12, [](auto v) { return v == 0; });
    const bool isatap = (a[8] == 0x00 || a[8] == 0x02) && a[9] == 0x00 && a[10] == 0x5E && a[11] == 0xFE;
    if (mapped_or_compat || nat64 || isatap) slot(off + 12);
    if (a[0] == 0x20 && a[1] == 0x02) slot(off + 2);                                // 6to4
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x00 && a[3] == 0x00) slot(off + 4);  // Teredo server
    if (addrs_ != nullptr && !keep_v6(a)) addrs_->push_back({6, std::vector<std::uint8_t>(a, a + 16)});
  }

  void ethernet(std::size_t off, int depth) {
    if (!has(off, 14)) return;
    field(off, off + 14);
    mac(off);
    mac(off + 6);
    std::uint16_t type = be16(at(off + 12));
    off += 14;
    while ((type == 0x8100 || type == 0x88A8 || type == 0x9100) && has(off, 4)) {
      field(off, off + 4);
      type = be16(at(off + 2));
      off += 4;
    }
    ether_type(type, off, depth);
  }

  void ether_type(std::uint16_t type, std::size_t off, int depth) {
    if (type == 0x0800) ipv4(off, depth);
    else if (type == 0x86DD) ipv6(off, depth);
    else if (type == 0x0806) arp(off);
  }

  void ip_by_version(std::size_t off, int depth) {
    if (!has(off, 1)) return;
    if ((p_[off] >> 4) == 4) ipv4(off, depth);
    else if ((p_[off] >> 4) == 6) ipv6(off, depth);
  }

  void arp(std::size_t off) {
    // Ethernet / IPv4 ARP only (RFC 826): 8 fixed bytes, then sender and target.
    if (!has(off, 28) || be16(at(off)) != 1 || be16(at(off + 2)) != 0x0800 || p_[off + 4] != 6 || p_[off + 5] != 4) return;
    field(off, off + 28);
    mac(off + 8);
    v4(off + 14);
    mac(off + 18);
    v4(off + 24);
  }

  void ipv4(std::size_t off, int depth) {
    if (depth > kMaxDepth || !has(off, 20) || (p_[off] >> 4) != 4) return;
    const std::size_t ihl = static_cast<std::size_t>(p_[off] & 0x0F) * 4;
    if (ihl < 20 || !has(off, ihl)) return;
    field(off, off + 20);  // options are not recognised
    v4(off + 12);
    v4(off + 16);
    if ((be16(at(off + 6)) & 0x1FFFu) != 0) return;  // later fragment: no transport header
    ip_src_ = off + 12;
    ip_len_ = 4;
    ip_end_ = std::min(p_.size(), off + std::max<std::size_t>(be16(at(off + 2)), ihl));
    transport(off + ihl, p_[off + 9], depth);
  }

  void ipv6(std::size_t off, int depth) {
    if (depth > kMaxDepth || !has(off, 40) || (p_[off] >> 4) != 6) return;
    field(off, off + 40);
    v6(off + 8);
    v6(off + 24);
    ip_src_ = off + 8;
    ip_len_ = 16;
    ip_end_ = std::min(p_.size(), off + 40 + be16(at(off + 4)));
    transport(off + 40, p_[off + 6], depth);  // extension headers are not recognised
  }

  void transport(std::size_t q, std::uint8_t proto, int depth) {
    switch (proto) {
      case 6: tcp(q); return;
      case 17: udp(q, depth); return;
      case 132: sctp(q); return;
      case 1: icmp4(q, depth); return;
      case 58: icmp6(q, depth); return;
      case 4: ipv4(q, depth + 1); return;
      case 41: ipv6(q, depth + 1); return;
      case 47: gre(q, depth); return;
      default: return;
    }
  }

  void tcp(std::size_t q) {
    if (!has(q, 20)) return;
    field(q, q + 20);
    const std::size_t doff = static_cast<std::size_t>(p_[q + 12] >> 4) * 4;
    std::size_t o = q + 20;
    while (o < q + doff && o < p_.size()) {
      const std::uint8_t kind = p_[o];
      if (kind == 0) break;
      if (kind == 1) {
        ++o;
        continue;
      }
      if (o + 1 >= p_.size() || p_[o + 1] < 2) break;
      if (kind == 8 && p_[o + 1] == 10) field(o + 2, o + 10);  // timestamp values
      o += p_[o + 1];
    }
    payload(true, q, q + doff, ip_end_);
  }

  // The L4 payload [from, to) with its direction key (addresses and ports).
  void payload(bool tcp, std::size_t l4, std::size_t from, std::size_t to) {
    if (payloads_ == nullptr || from >= to || to > p_.size() || ip_len_ == 0 || !has(l4, 4)) return;
    Payload pl;
    pl.tcp = tcp;
    pl.direction.assign(at(ip_src_), at(ip_src_) + 2 * ip_len_);
    pl.direction.insert(pl.direction.end(), at(l4), at(l4) + 4);
    pl.bytes = p_.subspan(from, to - from);
    payloads_->push_back(std::move(pl));
  }

  void udp(std::size_t q, int depth) {
    if (!has(q, 8)) return;
    field(q, q + 8);
    if (be16(at(q)) == 2152 || be16(at(q + 2)) == 2152) {
      gtpu(q + 8, depth);
      return;
    }
    const std::size_t ulen = be16(at(q + 4));
    const std::size_t end = std::min(p_.size(), ulen >= 8 ? q + ulen : ip_end_);
    payload(false, q, q + 8, end);
    rtp(q + 8, end);
  }

  // An RTP fixed header (RFC 3550 §5.1), its CSRC list and header extension header, when the
  // datagram has that shape (version 2, the lists inside the datagram): a header run whose
  // SSRC and CSRC words are value slots, where a short match is always a hit.
  // The shape check is the scanner's own; a payload it takes for RTP only gets the header run,
  // and the bytes after the header are raw (or a zero tail).
  void rtp(std::size_t r, std::size_t end) {
    if (end <= r || end - r < 12 || (p_[r] >> 6) != 2) return;
    // RFC 5761 §4: a second octet of 192 to 223 is an RTCP packet type.
    if (p_[r + 1] >= 192 && p_[r + 1] <= 223) {
      rtcp(r, end);
      return;
    }
    const std::size_t cc = p_[r] & 0x0Fu;
    std::size_t hdr = r + 12 + 4 * cc;
    if (hdr > end) return;
    if ((p_[r] & 0x10) != 0) {
      if (hdr + 4 > end) return;
      hdr += 4;  // profile and length; the elements are data (zeroed by the anonymiser)
    }
    field(r, hdr);
    for (std::size_t s = r + 8; s < r + 12 + 4 * cc; s += 4) slot(s);
  }

  // RTCP packets (RFC 3550 §6.4-§6.7, RFC 4585 §6.1, TS 24.380 §8.1.2-§8.1.3) as long as they
  // tile: common headers, SR sender info, report blocks, feedback SSRCs and MCX APP field
  // headers and short values are header runs; every SSRC word is a value slot (P7). Text
  // (SDES items, APP URIs) and longer values stay raw.
  void rtcp(std::size_t r, std::size_t end) {
    for (std::size_t o = r; o + 8 <= end && (p_[o] >> 6) == 2;) {
      const std::size_t len = 4 * (std::size_t{1} + be16(at(o + 2)));
      if (o + len > end) return;
      const std::uint8_t pt = p_[o + 1];
      const std::size_t count = p_[o] & 0x1Fu;
      field(o, o + 8);
      slot(o + 4);
      std::size_t q = o + 8;
      if (pt == 200) {  // SR: sender info
        if (q + 20 > o + len) return;
        field(q, q + 20);
        q += 20;
      }
      if (pt == 200 || pt == 201) {  // report blocks
        for (std::size_t k = 0; k < count && q + 24 <= o + len; ++k, q += 24) {
          field(q, q + 24);
          slot(q);
        }
      } else if (pt == 205 || pt == 206) {  // feedback: media source SSRC
        if (q + 4 <= o + len) {
          field(q, q + 4);
          slot(q);
        }
      } else if (pt == 207) {  // XR (RFC 3611 §3): block headers; the source SSRC of a block
        for (std::size_t bl = q; bl + 4 <= o + len;) {
          const std::size_t blen = 4 + 4 * std::size_t{be16(at(bl + 2))};
          if (bl + blen > o + len) break;
          field(bl, bl + 4);
          const std::uint8_t bt = p_[bl];
          if (bt == 5) {  // DLRR sub-blocks: SSRC, LRR, DLRR
            for (std::size_t sb = bl + 4; sb + 12 <= bl + blen; sb += 12) {
              field(sb, sb + 12);
              slot(sb);
            }
          } else if (bt != 4 && blen >= 8) {
            field(bl + 4, bl + 8);
            slot(bl + 4);
          }
          bl += blen;
        }
      } else if (pt == 204 && q + 4 <= o + len) {  // APP: name, then fields
        field(q, q + 4);
        for (std::size_t f = q + 4; f + 2 <= o + len;) {
          const std::size_t h = p_[f] < 192 ? 2 : 3;
          if (f + h > o + len) break;
          const std::size_t vlen = h == 2 ? p_[f + 1] : be16(at(f + 1));
          if (f + h + vlen > o + len) break;
          field(f, f + h + (vlen <= 2 ? vlen : 0));
          f += (h + vlen + 3) / 4 * 4;
        }
      }
      o += len;
    }
  }

  // GTP-U header, 3GPP TS 29.281 clause 5.1; extension headers clause 5.2.
  void gtpu(std::size_t g, int depth) {
    if (!has(g, 8) || (p_[g] >> 5) != 1 || (p_[g] & 0x10) == 0) return;
    std::size_t end = g + 8;
    if ((p_[g] & 0x07) != 0) {
      if (!has(g, 12)) return;
      end = g + 12;
      std::uint8_t next = p_[g + 11];
      while ((p_[g] & 0x04) != 0 && next != 0) {
        if (!has(end, 1) || p_[end] == 0) return;
        const std::size_t len = static_cast<std::size_t>(p_[end]) * 4;
        if (!has(end, len)) return;
        next = p_[end + len - 1];
        end += len;
      }
    }
    field(g, end);
    if (p_[g + 1] == 0xFF) ip_by_version(end, depth + 1);  // G-PDU
  }

  // GRE, RFC 2784 / RFC 2890: checksum, key and sequence number are optional.
  void gre(std::size_t g, int depth) {
    if (!has(g, 4)) return;
    const std::uint16_t flags = be16(at(g));
    if ((flags & 0x0007) != 0) return;  // only version 0
    std::size_t end = g + 4;
    if ((flags & 0x8000) != 0) end += 4;
    if ((flags & 0x2000) != 0) end += 4;
    if ((flags & 0x1000) != 0) end += 4;
    if (!has(g, end - g)) return;
    field(g, end);
    const std::uint16_t type = be16(at(g + 2));
    if (type == 0x6558) ethernet(end, depth + 1);
    else if (type == 0x0800) ipv4(end, depth + 1);
    else if (type == 0x86DD) ipv6(end, depth + 1);
  }

  void sctp(std::size_t q) {
    if (!has(q, 12)) return;
    field(q, q + 12);
    std::size_t c = q + 12;
    while (has(c, 4)) {
      const std::size_t len = be16(at(c + 2));
      field(c, c + 4);
      if (p_[c] == 0) field(c + 4, c + 16);  // DATA: TSN, stream, sequence, PPID
      if (p_[c] == 3) field(c + 4, c + 16);  // SACK: cumulative TSN, window, counts
      if (len < 4) break;
      c += (len + 3) & ~std::size_t{3};
    }
  }

  void icmp4(std::size_t q, int depth) {
    if (!has(q, 4)) return;
    const std::uint8_t type = p_[q];
    if (type == 0 || type == 8 || type == 13 || type == 14) {
      field(q, q + 8);
    } else if (type == 3 || type == 4 || type == 11 || type == 12) {
      field(q, q + 8);
      ipv4(q + 8, depth + 1);
    } else if (type == 5) {  // redirect: gateway address
      field(q, q + 8);
      if (has(q, 8)) v4(q + 4);
      ipv4(q + 8, depth + 1);
    } else {
      field(q, q + 4);
    }
  }

  void icmp6(std::size_t q, int depth) {
    if (!has(q, 4)) return;
    const std::uint8_t type = p_[q];
    if (type == 128 || type == 129) {
      field(q, q + 8);
    } else if (type >= 1 && type <= 4) {
      field(q, q + 8);
      ipv6(q + 8, depth + 1);
    } else {
      field(q, q + 4);
    }
  }

  std::span<const std::uint8_t> p_;
  std::uint64_t base_;
  std::vector<Range>* header_;
  std::vector<std::uint64_t>* slots_;
  std::vector<Address>* addrs_;
  std::vector<Payload>* payloads_;
  std::size_t ip_src_ = 0;
  std::size_t ip_len_ = 0;
  std::size_t ip_end_ = 0;
};

}  // namespace

void packet_fields(std::uint16_t lt, std::span<const std::uint8_t> p, std::uint64_t base, std::vector<Range>& header,
                   std::vector<std::uint64_t>& ipv4_slots) {
  Walk(p, base, &header, &ipv4_slots, nullptr).link(lt);
}

void packet_addresses(std::uint16_t lt, std::span<const std::uint8_t> p, std::vector<Address>& out) {
  Walk(p, 0, nullptr, nullptr, &out).link(lt);
}

void packet_payloads(std::uint16_t lt, std::span<const std::uint8_t> p, std::vector<Payload>& out) {
  Walk(p, 0, nullptr, nullptr, nullptr, &out).link(lt);
}

}  // namespace mcxanon::scan::detail
