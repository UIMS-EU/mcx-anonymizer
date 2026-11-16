// SPDX-License-Identifier: GPL-3.0-or-later
#include "rewrite/apply.hpp"

#include "bytes/endian.hpp"
#include "rewrite/checksum.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace mcxanon {

namespace {

// --- checksums -------------------------------------------------------------------------------

enum class CsState { valid, invalid, unverifiable, udp_zero };

struct CsCalc {
  std::size_t field = 0;  // offset of the checksum field
  int width = 2;          // 2 (Internet checksum) or 4 (CRC32c, little-endian)
  std::uint32_t correct = 0;
  bool truncated = false;
  bool udp = false;
};

std::uint32_t pseudo_sum(const Dissection& d, ByteView b, const Layer& ip, std::uint8_t proto,
                         std::size_t len) {
  Bytes ph;
  if (ip.kind == LayerKind::ipv4) {
    ph.insert(ph.end(), b.begin() + static_cast<std::ptrdiff_t>(ip.offset + 12),
              b.begin() + static_cast<std::ptrdiff_t>(ip.offset + 20));
    ph.push_back(0);
    ph.push_back(proto);
    ph.push_back(static_cast<std::uint8_t>(len >> 8));
    ph.push_back(static_cast<std::uint8_t>(len));
  } else {
    ph.insert(ph.end(), b.begin() + static_cast<std::ptrdiff_t>(ip.offset + 8),
              b.begin() + static_cast<std::ptrdiff_t>(ip.offset + 40));
    for (int s = 24; s >= 0; s -= 8) ph.push_back(static_cast<std::uint8_t>(len >> s));
    ph.insert(ph.end(), {0, 0, 0, proto});
  }
  (void)d;
  return inet_accumulate(ph);
}

// Internet checksum over [from, to) with the 16-bit field at `field` treated as zero.
std::uint16_t inet_excluding(ByteView b, std::size_t from, std::size_t to, std::size_t field,
                             std::uint32_t acc) {
  // `field - from` is even for every protocol handled here.
  acc = inet_accumulate(b.subspan(from, field - from), acc);
  acc = inet_accumulate(b.subspan(field + 2, to - field - 2), acc);
  std::uint16_t cs = static_cast<std::uint16_t>(~inet_fold_sum(acc));
  return cs;
}

std::optional<CsCalc> compute(const Dissection& d, std::size_t li, ByteView b) {
  const Layer& l = d.layers[li];
  const auto parent = [&]() -> const Layer* {
    return l.parent_ip >= 0 ? &d.layers[static_cast<std::size_t>(l.parent_ip)] : nullptr;
  };
  CsCalc c;
  switch (l.kind) {
    case LayerKind::ipv4: {
      if (l.offset + l.header_len > b.size()) return std::nullopt;
      c.field = l.offset + 10;
      c.correct = inet_excluding(b, l.offset, l.offset + l.header_len, c.field, 0);
      return c;
    }
    case LayerKind::icmpv4:
    case LayerKind::icmpv6: {
      const Layer* ip = parent();
      if (ip == nullptr || l.end - l.offset < 4) return std::nullopt;
      const bool v6 = l.kind == LayerKind::icmpv6;
      if (v6 && ip->kind != LayerKind::ipv6) return std::nullopt;
      c.field = l.offset + 2;
      const std::size_t declared = ip->declared_end > l.offset ? ip->declared_end : l.end;
      c.truncated = l.end < declared;
      const std::uint32_t acc = v6 ? pseudo_sum(d, b, *ip, 58, declared - l.offset) : 0;
      c.correct = inet_excluding(b, l.offset, l.end, c.field, acc);
      return c;
    }
    case LayerKind::udp: {
      const Layer* ip = parent();
      if (l.embedded || ip == nullptr) return std::nullopt;
      c.field = l.offset + 6;
      c.udp = true;
      c.truncated = l.end < l.declared_end;
      const std::uint32_t acc = pseudo_sum(d, b, *ip, 17, l.declared_end - l.offset);
      std::uint16_t cs = inet_excluding(b, l.offset, l.end, c.field, acc);
      if (cs == 0) cs = 0xFFFF;  // RFC 768: a computed zero is transmitted as all ones
      c.correct = cs;
      return c;
    }
    case LayerKind::tcp: {
      const Layer* ip = parent();
      if (l.embedded || ip == nullptr || l.end - l.offset < 20) return std::nullopt;
      c.field = l.offset + 16;
      const std::size_t declared = ip->declared_end > l.offset ? ip->declared_end : l.end;
      c.truncated = l.end < declared;
      const std::uint32_t acc = pseudo_sum(d, b, *ip, 6, declared - l.offset);
      c.correct = inet_excluding(b, l.offset, l.end, c.field, acc);
      return c;
    }
    case LayerKind::sctp: {
      const Layer* ip = parent();
      if (l.embedded || ip == nullptr || l.end - l.offset < 12) return std::nullopt;
      c.field = l.offset + 8;
      c.width = 4;
      c.truncated = ip->end < ip->declared_end;
      Bytes copy(b.begin() + static_cast<std::ptrdiff_t>(l.offset),
                 b.begin() + static_cast<std::ptrdiff_t>(l.end));
      std::memset(copy.data() + 8, 0, 4);
      c.correct = crc32c(copy);
      return c;
    }
    case LayerKind::gre: {
      if ((b[l.offset] & 0x80u) == 0) return std::nullopt;
      const Layer* ip = parent();
      c.field = l.offset + 4;
      c.truncated = ip != nullptr && ip->end < ip->declared_end;
      c.correct = inet_excluding(b, l.offset, l.end, c.field, 0);
      return c;
    }
    default:
      return std::nullopt;
  }
}

std::uint32_t stored(ByteView b, const CsCalc& c) {
  return c.width == 2 ? be16(b, c.field) : load32(b, c.field, Endian::little);
}

void store(MutByteView b, const CsCalc& c, std::uint32_t v) {
  if (c.width == 2) {
    store16(b, c.field, static_cast<std::uint16_t>(v), Endian::big);
  } else {
    store32(b, c.field, v, Endian::little);
  }
}

CsState evaluate(ByteView b, const CsCalc& c) {
  const std::uint32_t s = stored(b, c);
  if (c.udp && s == 0) return CsState::udp_zero;
  if (c.truncated) return CsState::unverifiable;
  if (c.udp) {
    // 0x0000 and 0xFFFF are the same one's-complement value.
    const std::uint32_t alt = c.correct == 0xFFFF ? 0 : c.correct;
    return (s == c.correct || s == alt) ? CsState::valid : CsState::invalid;
  }
  if (c.width == 2 && ((s == 0xFFFF && c.correct == 0) || (s == 0 && c.correct == 0xFFFF))) {
    return CsState::valid;
  }
  return s == c.correct ? CsState::valid : CsState::invalid;
}

// Value written for a checksum in the given state.
std::uint32_t output_value(const CsCalc& c, CsState st, ChecksumStats& stats) {
  switch (st) {
    case CsState::udp_zero:
      ++stats.udp_zero_kept;
      return 0;
    case CsState::valid:
      ++stats.valid_kept_valid;
      return c.correct;
    case CsState::unverifiable:
      ++stats.unverifiable_recomputed;
      return c.correct;
    case CsState::invalid: {
      ++stats.invalid_kept_invalid;
      const std::uint32_t mask = c.width == 2 ? 0x5555u : 0x55555555u;
      std::uint32_t v = c.correct ^ mask;
      if (v == 0) v = c.width == 2 ? 0xAAAAu : 0xAAAAAAAAu;
      return v;
    }
  }
  return c.correct;
}

// --- field actions --------------------------------------------------------------------------

bool starts_with(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }

void pad_field(MutByteView out, const FieldInstance& f) {
  const std::string_view name = field_name(f.id);
  auto* p = out.data() + f.offset;
  if (starts_with(name, "ipv6.opt.")) {
    if (f.length == 1) {
      p[0] = 0;  // Pad1
    } else {
      p[0] = 1;  // PadN
      p[1] = static_cast<std::uint8_t>(f.length - 2);
      std::memset(p + 2, 0, f.length - 2);
    }
  } else {
    std::memset(p, 1, f.length);  // IPv4 / TCP NOP
  }
}

Result<void> pseudonymise_field(MutByteView out, const FieldInstance& f, AddressMapper& m) {
  auto* p = out.data() + f.offset;
  switch (field_kind(f.id)) {
    case FieldKind::address_mac: {
      if (f.length != 6) break;
      MacAddr a{};
      std::memcpy(a.data(), p, 6);
      auto r = m.mac(a);
      if (!r) return std::unexpected(r.error());
      std::memcpy(p, r->data(), 6);
      return {};
    }
    case FieldKind::address_ipv4: {
      if (f.length != 4) break;
      auto r = m.ipv4(be32(out, f.offset));
      if (!r) return std::unexpected(r.error());
      store32(out, f.offset, *r, Endian::big);
      return {};
    }
    case FieldKind::address_ipv6: {
      if (f.length != 16) break;
      Ipv6Addr a{};
      std::memcpy(a.data(), p, 16);
      auto r = m.ipv6(a);
      if (!r) return std::unexpected(r.error());
      std::memcpy(p, r->data(), 16);
      return {};
    }
    case FieldKind::vlan: {
      if (f.length != 2) break;
      const std::uint16_t tci = be16(out, f.offset);
      auto r = m.vlan(tci & 0x0FFFu);
      if (!r) return std::unexpected(r.error());
      store16(out, f.offset, static_cast<std::uint16_t>((tci & 0xF000u) | (*r & 0x0FFFu)),
              Endian::big);
      return {};
    }
    case FieldKind::port: {
      if (f.length != 2) break;
      auto r = m.port(be16(out, f.offset));
      if (!r) return std::unexpected(r.error());
      store16(out, f.offset, *r, Endian::big);
      return {};
    }
    case FieldKind::numeric: {
      // The only pseudonymised numeric fields are the AH and ESP SPIs.
      if (f.length != 4 || (f.id != Fid::ah_spi && f.id != Fid::esp_spi)) break;
      auto r = m.spi(be32(out, f.offset));
      if (!r) return std::unexpected(r.error());
      store32(out, f.offset, *r, Endian::big);
      return {};
    }
    default:
      break;
  }
  std::memset(p, 0, f.length);  // a field that cannot hold a pseudonym is zeroed
  return {};
}

// Multicast MACs derived from an IP group follow the pseudonymised group.
void fix_multicast_macs(const Dissection& d, MutByteView out) {
  for (std::size_t i = 0; i < d.layers.size(); ++i) {
    const Layer& eth = d.layers[i];
    if (eth.kind != LayerKind::ethernet) continue;
    std::size_t j = i + 1;
    while (j < d.layers.size() && d.layers[j].kind == LayerKind::vlan) ++j;
    if (j >= d.layers.size()) continue;
    const Layer& ip = d.layers[j];
    auto* mac = out.data() + eth.offset;
    if (ip.kind == LayerKind::ipv4 && mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e &&
        (mac[3] & 0x80u) == 0 && (out[ip.offset + 16] >> 4) == 0xE) {
      mac[3] = out[ip.offset + 17] & 0x7Fu;
      mac[4] = out[ip.offset + 18];
      mac[5] = out[ip.offset + 19];
    } else if (ip.kind == LayerKind::ipv6 && mac[0] == 0x33 && mac[1] == 0x33 &&
               out[ip.offset + 24] == 0xFF) {
      std::memcpy(mac + 2, out.data() + ip.offset + 36, 4);
    }
  }
}

// --- drop mode ------------------------------------------------------------------------------

bool removable_tail(const FieldInstance& f) {
  return field_kind(f.id) == FieldKind::payload || f.id == Fid::link_trailer;
}

// Rebuilds an SCTP packet without DATA / I-DATA user data. Returns the new end.
std::size_t drop_sctp_data(Bytes& out, std::size_t off, std::size_t end) {
  Bytes rebuilt(out.begin() + static_cast<std::ptrdiff_t>(off),
                out.begin() + static_cast<std::ptrdiff_t>(off + 12));
  std::size_t q = off + 12;
  while (q + 4 <= end) {
    const std::uint8_t type = out[q];
    const std::size_t len = be16(out, q + 2);
    if (len < 4) break;
    const std::size_t padded = std::min(end, q + ((len + 3u) & ~std::size_t{3}));
    const std::size_t keep = type == 0 ? 16 : (type == 64 ? 20 : 0);
    if (keep != 0 && std::min(end, q + len) - q >= keep) {
      const std::size_t at = rebuilt.size();
      rebuilt.insert(rebuilt.end(), out.begin() + static_cast<std::ptrdiff_t>(q),
                     out.begin() + static_cast<std::ptrdiff_t>(q + keep));
      store16(rebuilt, at + 2, static_cast<std::uint16_t>(keep), Endian::big);
    } else {
      rebuilt.insert(rebuilt.end(), out.begin() + static_cast<std::ptrdiff_t>(q),
                     out.begin() + static_cast<std::ptrdiff_t>(padded));
    }
    q = padded;
  }
  if (q < end) {
    rebuilt.insert(rebuilt.end(), out.begin() + static_cast<std::ptrdiff_t>(q),
                   out.begin() + static_cast<std::ptrdiff_t>(end));
  }
  out.resize(off);
  out.insert(out.end(), rebuilt.begin(), rebuilt.end());
  return out.size();
}

void fix_lengths(const Dissection& d, Bytes& out, std::size_t cut_orig, std::size_t cut_new) {
  for (const Layer& l : d.layers) {
    if (l.embedded || l.offset >= cut_new || l.end < cut_orig) continue;
    switch (l.kind) {
      case LayerKind::ipv4:
        store16(out, l.offset + 2, static_cast<std::uint16_t>(cut_new - l.offset), Endian::big);
        if (l.fragment_first) {
          const std::uint16_t frag = be16(out, l.offset + 6);
          store16(out, l.offset + 6, static_cast<std::uint16_t>(frag & 0x4000u), Endian::big);
        }
        break;
      case LayerKind::ipv6:
        if (!l.jumbo) {
          store16(out, l.offset + 4, static_cast<std::uint16_t>(cut_new - l.offset - 40),
                  Endian::big);
        }
        if (l.fragment_first) {
          const std::uint16_t fo = be16(out, l.fragment_field + 2);
          store16(out, l.fragment_field + 2, static_cast<std::uint16_t>(fo & ~1u), Endian::big);
        }
        break;
      case LayerKind::udp:
        store16(out, l.offset + 4, static_cast<std::uint16_t>(cut_new - l.offset), Endian::big);
        break;
      case LayerKind::gtpu:
        store16(out, l.offset + 2, static_cast<std::uint16_t>(cut_new - l.offset - 8), Endian::big);
        break;
      default:
        break;
    }
  }
}

// Every non-embedded layer that encloses [at, at + len) changes its length by `delta` (research
// R13). Returns false when a new length does not fit its field.
bool lengths_fit(const Dissection& d, std::size_t at, std::size_t len, std::ptrdiff_t delta,
                 ByteView out) {
  for (const Layer& l : d.layers) {
    if (l.embedded || l.offset >= at || l.end < at + len) continue;
    std::size_t field = 0;
    switch (l.kind) {
      case LayerKind::ipv4: field = l.offset + 2; break;
      case LayerKind::ipv6: if (l.jumbo) continue; field = l.offset + 4; break;
      case LayerKind::udp: field = l.offset + 4; break;
      case LayerKind::gtpu: field = l.offset + 2; break;
      default: continue;
    }
    const auto v = static_cast<std::ptrdiff_t>(be16(out, field)) + delta;
    if (v < 0 || v > 0xFFFF) return false;
  }
  return true;
}

void shift_lengths(const Dissection& d, std::size_t at, std::size_t len, std::ptrdiff_t delta,
                   Bytes& out) {
  for (const Layer& l : d.layers) {
    if (l.embedded || l.offset >= at || l.end < at + len) continue;
    std::size_t field = 0;
    switch (l.kind) {
      case LayerKind::ipv4: field = l.offset + 2; break;
      case LayerKind::ipv6: if (l.jumbo) continue; field = l.offset + 4; break;
      case LayerKind::udp: field = l.offset + 4; break;
      case LayerKind::gtpu: field = l.offset + 2; break;
      default: continue;
    }
    store16(out, field, static_cast<std::uint16_t>(static_cast<std::ptrdiff_t>(be16(out, field)) + delta),
            Endian::big);
  }
}

// The outermost non-embedded TCP layer with a full header (the layer segment_of reads).
int tcp_layer(const Dissection& d) {
  for (std::size_t i = 0; i < d.layers.size(); ++i) {
    const Layer& l = d.layers[i];
    if (l.kind == LayerKind::tcp && !l.embedded && l.parent_ip >= 0 && l.end >= l.offset + 20) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

// Writes the stream layer's numbers into the TCP header, where the policy keeps them.
void apply_tcp_numbers(const Dissection& d, int ti, const Policy& policy, const TcpOverride& t,
                       Bytes& out) {
  const Layer& l = d.layers[static_cast<std::size_t>(ti)];
  if (policy.decide(Fid::tcp_seq).action == Action::keep) store32(out, l.offset + 4, t.seq, Endian::big);
  if (t.ack && policy.decide(Fid::tcp_ack).action == Action::keep) {
    store32(out, l.offset + 8, *t.ack, Endian::big);
  }
  if (!t.sack_known || policy.decide(Fid::tcp_opt_sack).action != Action::keep) return;
  std::size_t edge = 0;
  for (const auto& f : d.fields) {
    if (f.layer != ti || f.id != Fid::tcp_opt_sack) continue;
    for (std::size_t p = f.offset + 2; p + 4 <= f.offset + f.length && edge < t.sack.size(); p += 4) {
      store32(out, p, t.sack[edge++], Endian::big);
    }
  }
}

std::string unknown_key_kind(std::string_view k) { return std::string(k); }

// The outermost non-embedded fragmented IP layer (the layer stream::fragment_of reads).
int fragmented_layer(const Dissection& d) {
  for (std::size_t i = 0; i < d.layers.size(); ++i) {
    const Layer& l = d.layers[i];
    if ((l.kind == LayerKind::ipv4 || l.kind == LayerKind::ipv6) && !l.embedded &&
        (l.fragment_first || l.fragment_nonfirst)) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

// [begin, end) of an IP layer's fragmentable part: after the IPv4 header, or after the IPv6
// Fragment header.
std::optional<std::pair<std::size_t, std::size_t>> region_of(const Dissection& d, int li) {
  if (li < 0 || static_cast<std::size_t>(li) >= d.layers.size()) return std::nullopt;
  const Layer& ip = d.layers[static_cast<std::size_t>(li)];
  std::size_t begin = 0;
  if (ip.kind == LayerKind::ipv4) {
    begin = ip.offset + ip.header_len;
  } else if (ip.kind == LayerKind::ipv6 && ip.fragment_field != 0) {
    begin = ip.fragment_field + 8;
  } else {
    return std::nullopt;
  }
  const std::size_t end = std::min(ip.end, ip.declared_end);
  if (begin > end) return std::nullopt;
  return std::make_pair(begin, end);
}

// The fragment field of IP layer `ip` for the given offset and more-fragments flag; IPv4 keeps
// DF, IPv6 keeps its reserved bits.
void set_fragment(const Layer& ip, Bytes& out, std::uint32_t offset, bool more) {
  const std::size_t at = ip.kind == LayerKind::ipv4 ? ip.offset + 6 : ip.fragment_field + 2;
  const std::uint16_t old = be16(out, at);
  std::uint16_t v = 0;
  if (ip.kind == LayerKind::ipv4) {
    v = static_cast<std::uint16_t>((old & 0x4000u) | (more ? 0x2000u : 0u) | ((offset / 8) & 0x1FFFu));
  } else {
    v = static_cast<std::uint16_t>(((offset / 8) << 3) | (old & 0x0006u) | (more ? 1u : 0u));
  }
  store16(out, at, v, Endian::big);
}

}  // namespace

Result<PacketOutput> rewrite_packet(std::uint16_t linktype, ByteView data, std::size_t fcs_len,
                                    const Policy& policy, AddressMapper& mapper,
                                    const RewriteOptions& options, RewriteStats& stats,
                                    const L7Hook* l7, const TcpOverride* tcp,
                                    const FragmentOverride* frag) {
  ++stats.packets;
  DissectOptions dopt;
  dopt.fcs_len = linktype == kLinkEthernet ? fcs_len : 0;
  if (l7 != nullptr) {
    dopt.recognise_sip = l7->recognise;
    dopt.classify_media = l7->classify_media;
    dopt.classify_media_ctx = l7->classify_media_ctx;
  }
  dopt.tcp_payload_sip = tcp != nullptr && tcp->sip;
  const Dissection d0 = dissect(linktype, data, dopt);
  for (const auto& u : d0.unknown) ++stats.unknown[{unknown_key_kind(u.kind), u.id}];
  if (options.strict && (!is_supported_linktype(linktype) || !d0.unknown.empty())) {
    return fail(ErrorCode::input,
                "unsupported link type or protocol in the capture (--strict); see the report");
  }

  // Checksum validity of the input, per layer.
  std::vector<std::optional<CsState>> states(d0.layers.size());
  for (std::size_t i = 0; i < d0.layers.size(); ++i) {
    if (auto c = compute(d0, i, data)) states[i] = evaluate(data, *c);
  }
  std::optional<CsState> fcs_state;
  const bool has_fcs = dopt.fcs_len == 4 && data.size() >= 18;
  if (has_fcs) {
    const std::uint32_t crc = crc32_ethernet(data.first(data.size() - 4));
    fcs_state = load32(data, data.size() - 4, Endian::little) == crc ? CsState::valid
                                                                       : CsState::invalid;
  }

  PacketOutput result;
  Bytes& out = result.data;
  out.assign(data.begin(), data.end());
  const bool drop = options.payload == PayloadPolicy::drop;

  for (const auto& f : d0.fields) {
    Decision dec = policy.decide(f.id);
    const FieldKind kind = field_kind(f.id);
    if (kind == FieldKind::vlan && options.pseudonymise_vlan) dec.action = Action::pseudonymise;
    if (kind == FieldKind::port && options.pseudonymise_ports) dec.action = Action::pseudonymise;
    if (drop && f.id == Fid::tcp_opt_sack && !(tcp != nullptr && tcp->sack_known)) {
      dec.action = Action::pad;  // 001/R8: unmappable edges
    }
    auto& counter = stats.counters[std::string(field_name(f.id))];
    ++counter[std::string(to_string(dec.action))];
    if (dec.unclassified) ++counter["unclassified"];
    switch (dec.action) {
      case Action::keep:
      case Action::recompute:
      case Action::remove:
        break;
      case Action::zero:
      case Action::l7:  // the SIP or media layer splices its bytes later; without it: zeroed
        std::memset(out.data() + f.offset, 0, f.length);
        break;
      case Action::pad:
        pad_field(out, f);
        break;
      case Action::pseudonymise:
        if (auto r = pseudonymise_field(out, f, mapper); !r) return std::unexpected(r.error());
        break;
    }
  }
  fix_multicast_macs(d0, out);

  // The bytes that replace the application payload: from the TCP stream layer for a segment,
  // or from the SIP layer for a payload.sip datagram, in both cases from the original input.
  const FieldInstance* sip_field = nullptr;
  std::optional<Bytes> sip_bytes;
  const int ti = tcp != nullptr ? tcp_layer(d0) : -1;
  if (ti >= 0) {
    for (const auto& f : d0.fields) {
      if (f.layer == ti && (f.id == Fid::payload_l7 || f.id == Fid::payload_sip)) sip_field = &f;
    }
    if (sip_field != nullptr && !(drop && tcp->payload.empty()) &&
        lengths_fit(d0, sip_field->offset, sip_field->length,
                    static_cast<std::ptrdiff_t>(tcp->payload.size()) -
                        static_cast<std::ptrdiff_t>(sip_field->length),
                    out)) {
      sip_bytes = tcp->payload;
    }
  } else {
    for (const auto& f : d0.fields) {
      if ((f.id == Fid::payload_sip || f.id == Fid::payload_media) && policy.decide(f.id).action == Action::l7) {
        sip_field = &f;
      }
    }
  }
  if (ti < 0 && sip_field != nullptr && l7 != nullptr && l7->rewrite) {
    auto r = l7->rewrite(data.subspan(sip_field->offset, sip_field->length),
                         L7Context{sip_field->id, sip_field->id == Fid::payload_media ? d0.media_tag : 0});
    if (!r) return std::unexpected(r.error());
    if (*r && lengths_fit(d0, sip_field->offset, sip_field->length,
                          static_cast<std::ptrdiff_t>((*r)->size()) -
                              static_cast<std::ptrdiff_t>(sip_field->length),
                          out)) {
      sip_bytes = std::move(*r);
    }
  }

  const int fi = frag != nullptr ? fragmented_layer(d0) : -1;
  std::size_t payload_end = out.size();
  if (has_fcs) payload_end -= 4;
  if (drop && fi < 0) {  // an output fragment of a rewritten SIP datagram is kept (FR-003)
    for (const auto& l : d0.layers) {
      if ((l.kind == LayerKind::ipv4 || l.kind == LayerKind::ipv6) && l.fragment_nonfirst &&
          !l.embedded) {
        result.drop = true;
        ++stats.packets_dropped;
        return result;
      }
    }
    if (has_fcs) out.resize(payload_end);
    std::size_t cut_orig = out.size();
    std::size_t cut_new = out.size();
    const Layer* sctp = nullptr;
    for (const auto& l : d0.layers) {
      if (l.kind == LayerKind::sctp && !l.embedded) sctp = &l;
    }
    if (sctp != nullptr) {
      cut_orig = sctp->end;
      cut_new = drop_sctp_data(out, sctp->offset, sctp->end);
    } else {
      std::size_t t = out.size();
      for (auto it = d0.fields.rbegin(); it != d0.fields.rend(); ++it) {
        if (it->id == Fid::eth_fcs) continue;
        if (!removable_tail(*it)) break;
        if (&*it == sip_field && sip_bytes) break;  // FR-003: a rewritten SIP message stays
        t = it->offset;
      }
      cut_orig = t;
      cut_new = t;
      out.resize(t);
    }
    if (cut_new < data.size() - (has_fcs ? 4 : 0)) result.truncated = true;
    fix_lengths(d0, out, cut_orig, cut_new);
  }

  if (sip_bytes) {
    // Splice: the zeroed payload.sip span is replaced, every enclosing length follows.
    const auto at = static_cast<std::ptrdiff_t>(sip_field->offset);
    const auto delta = static_cast<std::ptrdiff_t>(sip_bytes->size()) -
                       static_cast<std::ptrdiff_t>(sip_field->length);
    out.erase(out.begin() + at, out.begin() + at + static_cast<std::ptrdiff_t>(sip_field->length));
    out.insert(out.begin() + at, sip_bytes->begin(), sip_bytes->end());
    shift_lengths(d0, sip_field->offset, sip_field->length, delta, out);
    result.l7_spliced = ti < 0;
  }
  if (ti >= 0) apply_tcp_numbers(d0, ti, policy, *tcp, out);
  if (fi >= 0) {
    // R16: the fragment carries its part of the rewritten datagram.
    const auto reg = region_of(d0, fi);
    if (!reg) return fail(ErrorCode::internal, "fragment override without a fragmentable part");
    const std::size_t len = reg->second - reg->first;
    const auto delta = static_cast<std::ptrdiff_t>(frag->payload.size()) - static_cast<std::ptrdiff_t>(len);
    if (!lengths_fit(d0, reg->first, len, delta, out)) {
      return fail(ErrorCode::internal, "an output fragment does not fit its length fields");
    }
    const auto at = static_cast<std::ptrdiff_t>(reg->first);
    out.erase(out.begin() + at, out.begin() + at + static_cast<std::ptrdiff_t>(len));
    out.insert(out.begin() + at, frag->payload.begin(), frag->payload.end());
    shift_lengths(d0, reg->first, len, delta, out);
    set_fragment(d0.layers[static_cast<std::size_t>(fi)], out, frag->offset, frag->more);
  }

  // Checksums over the rewritten packet; the layer structure is the same as d0's.
  const Dissection d1 = dissect(linktype, out, DissectOptions{has_fcs && !drop ? 4u : 0u, dopt.max_depth});
  const bool same_shape =
      d1.layers.size() == d0.layers.size() &&
      std::equal(d1.layers.begin(), d1.layers.end(), d0.layers.begin(),
                 [](const Layer& a, const Layer& b) { return a.kind == b.kind; });
  for (std::size_t i = d1.layers.size(); i-- > 0;) {
    // Inside an output fragment, the datagram's own checksums came with the rewritten datagram.
    if (fi >= 0 && static_cast<int>(i) > fi) continue;
    auto c = compute(d1, i, out);
    if (!c) continue;
    const CsState st = same_shape && states[i] ? *states[i] : CsState::unverifiable;
    store(out, *c, output_value(*c, st, stats.checksums));
  }
  if (has_fcs) {
    const std::size_t body = drop ? out.size() : out.size() - 4;
    if (drop) out.resize(out.size() + 4);
    CsCalc fc;
    fc.field = body;
    fc.width = 4;
    fc.correct = crc32_ethernet(ByteView(out).first(body));
    store(out, fc, output_value(fc, *fcs_state, stats.checksums));
  }
  return result;
}

Result<Bytes> reassembled_packet(std::uint16_t linktype, ByteView first, std::size_t fcs_len,
                                 int ip_layer, ByteView fragmentable) {
  DissectOptions dopt;
  dopt.fcs_len = linktype == kLinkEthernet ? fcs_len : 0;
  const Dissection d = dissect(linktype, first, dopt);
  const auto reg = region_of(d, ip_layer);
  if (!reg) return fail(ErrorCode::internal, "the first fragment has no fragmentable part");
  // Checksums of the layers up to the IP layer, as the first fragment carried them.
  std::vector<std::optional<CsState>> states(static_cast<std::size_t>(ip_layer) + 1);
  for (std::size_t i = 0; i < states.size(); ++i) {
    if (auto c = compute(d, i, first)) states[i] = evaluate(first, *c);
  }
  const bool has_fcs = dopt.fcs_len == 4 && first.size() >= 18;
  const bool fcs_valid = has_fcs && load32(first, first.size() - 4, Endian::little) ==
                                        crc32_ethernet(first.first(first.size() - 4));
  Bytes out(first.begin(), first.end());
  const std::size_t len = reg->second - reg->first;
  const auto delta = static_cast<std::ptrdiff_t>(fragmentable.size()) - static_cast<std::ptrdiff_t>(len);
  if (!lengths_fit(d, reg->first, len, delta, out)) {
    return fail(ErrorCode::input, "a reassembled datagram does not fit its length fields");
  }
  const auto at = static_cast<std::ptrdiff_t>(reg->first);
  out.erase(out.begin() + at, out.begin() + at + static_cast<std::ptrdiff_t>(len));
  out.insert(out.begin() + at, fragmentable.begin(), fragmentable.end());
  shift_lengths(d, reg->first, len, delta, out);
  set_fragment(d.layers[static_cast<std::size_t>(ip_layer)], out, 0, false);
  const Dissection d1 = dissect(linktype, out, dopt);
  for (std::size_t i = std::min(states.size(), d1.layers.size()); i-- > 0;) {
    if (!states[i] || *states[i] != CsState::valid) continue;
    if (auto c = compute(d1, i, out)) store(out, *c, c->correct);
  }
  if (fcs_valid) {
    const std::size_t body = out.size() - 4;
    store32(out, body, crc32_ethernet(ByteView(out).first(body)), Endian::little);
  }
  return out;
}

std::optional<std::pair<std::size_t, std::size_t>> fragmentable_region(std::uint16_t linktype, ByteView packet,
                                                                       std::size_t fcs_len, int ip_layer) {
  DissectOptions dopt;
  dopt.fcs_len = linktype == kLinkEthernet ? fcs_len : 0;
  return region_of(dissect(linktype, packet, dopt), ip_layer);
}

}  // namespace mcxanon
