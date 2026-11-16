// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/endpoints.hpp"

#include "sip/render.hpp"

#include <algorithm>
#include <cctype>

namespace mcxanon::media {
namespace {

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

bool looks_numeric(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0 || c == '.' || c == ':' || c == '[' || c == ']';
  });
}

bool is_multicast(const Address& a) {
  const bool mapped = std::all_of(a.bytes.begin(), a.bytes.begin() + 10, [](std::uint8_t b) { return b == 0; }) &&
                      a.bytes[10] == 0xFF && a.bytes[11] == 0xFF;
  if (mapped) return (a.bytes[12] & 0xF0) == 0xE0;  // 224.0.0.0/4
  return a.bytes[0] == 0xFF;                         // ff00::/8
}

bool is_unspecified(const Address& a) {
  const auto v6zero = std::all_of(a.bytes.begin(), a.bytes.end(), [](std::uint8_t b) { return b == 0; });
  return v6zero || a == Address::v4({0, 0, 0, 0});
}

// RTP profiles (RFC 3550 §5, RFC 4585, RFC 3711) and whether they are secure.
std::optional<bool> rtp_proto(std::string_view proto) {
  if (iequal(proto, "RTP/AVP") || iequal(proto, "RTP/AVPF")) return false;
  if (iequal(proto, "RTP/SAVP") || iequal(proto, "RTP/SAVPF")) return true;
  return std::nullopt;
}

// The authority of an MSRP URI as an endpoint: msrp://host:port/... (RFC 4975 §6).
std::optional<std::pair<Address, std::uint16_t>> path_endpoint(std::string_view uri) {
  const auto sep = uri.find("://");
  if (sep == std::string_view::npos) return std::nullopt;
  auto rest = uri.substr(sep + 3);
  rest = rest.substr(0, std::min(rest.find('/'), rest.find(';')));
  if (const auto at = rest.rfind('@'); at != std::string_view::npos) rest = rest.substr(at + 1);
  std::string_view host = rest, port;
  if (rest.starts_with('[')) {
    const auto close = rest.find(']');
    if (close == std::string_view::npos || close + 1 >= rest.size() || rest[close + 1] != ':') return std::nullopt;
    host = rest.substr(0, close + 1);
    port = rest.substr(close + 2);
  } else {
    const auto colon = rest.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;
    host = rest.substr(0, colon);
    port = rest.substr(colon + 1);
  }
  if (port.empty() || port.size() > 5 || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
    return std::nullopt;
  }
  std::uint32_t p = 0;
  for (char c : port) p = p * 10 + static_cast<std::uint32_t>(c - '0');
  if (p == 0 || p > 65535) return std::nullopt;
  const auto a = sip::parse_address_text(host);
  if (!a) return std::nullopt;
  const Address addr = a->v6 ? Address::v6(a->v6addr)
                             : Address::v4({static_cast<std::uint8_t>(a->v4 >> 24), static_cast<std::uint8_t>(a->v4 >> 16),
                                            static_cast<std::uint8_t>(a->v4 >> 8), static_cast<std::uint8_t>(a->v4)});
  return std::pair{addr, static_cast<std::uint16_t>(p)};
}

}  // namespace

Address Address::v4(const std::array<std::uint8_t, 4>& a) {
  Address x;
  x.bytes[10] = 0xFF;
  x.bytes[11] = 0xFF;
  std::copy(a.begin(), a.end(), x.bytes.begin() + 12);
  return x;
}

Address Address::v6(const std::array<std::uint8_t, 16>& a) {
  Address x;
  x.bytes = a;
  return x;
}

std::optional<Address> Address::from_bytes(ByteView raw) {
  if (raw.size() == 4) return v4({raw[0], raw[1], raw[2], raw[3]});
  if (raw.size() == 16) {
    std::array<std::uint8_t, 16> a{};
    std::copy(raw.begin(), raw.end(), a.begin());
    return v6(a);
  }
  return std::nullopt;
}

std::string_view to_string(Kind k) {
  switch (k) {
    case Kind::rtp: return "rtp";
    case Kind::rtcp: return "rtcp";
    case Kind::mux: return "mux";
    case Kind::fc: return "fc";
    case Kind::tc: return "tc";
    case Kind::msrp: return "msrp";
  }
  return "?";
}

std::string_view to_string(SkipReason r) {
  switch (r) {
    case SkipReason::fqdn: return "fqdn";
    case SkipReason::unspecified: return "unspecified";
    case SkipReason::multicast: return "multicast";
    case SkipReason::tls: return "tls";
    case SkipReason::rejected: return "rejected";
    case SkipReason::unsupported: return "unsupported";
    case SkipReason::malformed: return "malformed";
  }
  return "?";
}

std::variant<Address, SkipReason> connection_address(std::string_view addrtype, std::string_view address) {
  const auto slash = address.find('/');
  const bool suffix = slash != std::string_view::npos;
  const auto host = address.substr(0, slash);
  std::optional<sip::TextAddress> a;
  if (iequal(addrtype, "IP4")) {
    a = sip::parse_ipv4_text(host);
  } else if (iequal(addrtype, "IP6")) {
    a = sip::parse_ipv6_text(host);
  } else {
    return SkipReason::malformed;
  }
  if (!a) return looks_numeric(host) || host.empty() ? SkipReason::malformed : SkipReason::fqdn;
  const Address x = a->v6 ? Address::v6(a->v6addr)
                          : Address::v4({static_cast<std::uint8_t>(a->v4 >> 24), static_cast<std::uint8_t>(a->v4 >> 16),
                                         static_cast<std::uint8_t>(a->v4 >> 8), static_cast<std::uint8_t>(a->v4)});
  if (is_unspecified(x)) return SkipReason::unspecified;
  if (is_multicast(x) || suffix) return SkipReason::multicast;
  return x;
}

std::variant<std::vector<Announcement>, SkipReason> from_sdp(const sip::SdpMedia& m) {
  if (m.media.empty() || m.proto.empty()) return SkipReason::malformed;
  if (m.port == 0) return SkipReason::rejected;
  Announcement a;
  a.port = static_cast<std::uint16_t>(m.port);
  // The role.
  if ((iequal(m.media, "audio") || iequal(m.media, "video")) && rtp_proto(m.proto)) {
    a.role = Role::rtp;
    a.secure = *rtp_proto(m.proto);
    if (a.secure) a.keys = m.keys;
  } else if (iequal(m.media, "application") && iequal(m.proto, "udp") &&
             (m.fmt == "MCPTT" || m.fmt == "MCVideo")) {
    // TS 24.380 §4.3.3.1 / TS 24.581 §4.3.3.1: the m= port is an RTCP port.
    a.role = m.fmt == "MCPTT" ? Role::fc : Role::tc;
  } else if (iequal(m.media, "message") && iequal(m.proto, "TCP/MSRP")) {
    a.role = Role::msrp;
    a.transport = Transport::tcp;
  } else if (iequal(m.media, "message") && iequal(m.proto, "TCP/TLS/MSRP")) {
    return SkipReason::tls;  // FR-029: stays zeroed
  } else {
    return SkipReason::unsupported;
  }
  const auto addr = connection_address(m.addrtype, m.address);
  if (const auto* r = std::get_if<SkipReason>(&addr)) return *r;
  a.address = std::get<Address>(addr);
  if (a.role == Role::rtp) {
    a.rtcp_mux = m.rtcp_mux;
    if (m.rtcp_port) {
      if (*m.rtcp_port == 0 || *m.rtcp_port > 65535) return SkipReason::malformed;
      a.rtcp_port = static_cast<std::uint16_t>(*m.rtcp_port);
      if (!m.rtcp_address.empty()) {
        const auto ra = connection_address(m.rtcp_addrtype, m.rtcp_address);
        if (const auto* r = std::get_if<SkipReason>(&ra)) return *r;
        a.rtcp_address = std::get<Address>(ra);
      }
    }
  }
  std::vector<Announcement> out{a};
  if (a.role == Role::msrp) {
    // RFC 4975 §8.2: the path names the endpoint too; register it when it differs.
    for (const auto& p : m.paths) {
      const auto ep = path_endpoint(p);
      if (!ep || (ep->first == a.address && ep->second == a.port)) continue;
      Announcement b = a;
      b.address = ep->first;
      b.port = ep->second;
      out.push_back(b);
    }
  }
  return out;
}

EndpointTable::EndpointTable(std::size_t max_endpoints) : max_(std::max<std::size_t>(max_endpoints, 1)) {}

std::uint32_t EndpointTable::intern(const sip::KeyContext& k) {
  if (k.empty()) return 0;
  if (const auto it = context_ids_.find(k); it != context_ids_.end()) return it->second;
  if (contexts_.size() >= kMaxKeyContexts) return 0;
  contexts_.push_back(k);
  const auto id = static_cast<std::uint32_t>(contexts_.size());
  context_ids_.emplace(k, id);
  return id;
}

void EndpointTable::put(const EndpointKey& k, Kind kind, bool secure, std::uint64_t ts_us, std::uint32_t keys) {
  if (auto it = entries_.find(k); it != entries_.end()) {
    lru_.erase({it->second.last_used, it->second.seq, k});
    entries_.erase(it);
  } else if (entries_.size() >= max_) {
    const auto victim = *lru_.begin();
    lru_.erase(lru_.begin());
    entries_.erase(std::get<2>(victim));
    ++evicted_;
  }
  const Entry e{kind, secure, ts_us, next_seq_++, keys};
  entries_.emplace(k, e);
  lru_.insert({e.last_used, e.seq, k});
  ++registered_[kind];
}

void EndpointTable::announce(const Announcement& a, std::uint64_t ts_us) {
  if (a.port == 0) {
    ++skipped_[SkipReason::rejected];
    return;
  }
  const EndpointKey key{a.address, a.port, a.transport};
  switch (a.role) {
    case Role::rtp: {
      const auto keys = intern(a.keys);
      if (a.rtcp_mux) {
        put(key, Kind::mux, a.secure, ts_us, keys);
        return;
      }
      put(key, Kind::rtp, a.secure, ts_us, keys);
      if (a.rtcp_port) {
        put({a.rtcp_address.value_or(a.address), *a.rtcp_port, Transport::udp}, Kind::rtcp, a.secure, ts_us, keys);
      } else if (a.port < 65535) {
        // RFC 3550 §11: the RTCP stream uses the next higher port.
        put({a.address, static_cast<std::uint16_t>(a.port + 1), Transport::udp}, Kind::rtcp, a.secure, ts_us, keys);
      }
      return;
    }
    case Role::fc: put(key, Kind::fc, a.secure, ts_us); return;
    case Role::tc: put(key, Kind::tc, a.secure, ts_us); return;
    case Role::msrp: put(key, Kind::msrp, false, ts_us); return;
  }
}

std::optional<Lookup> EndpointTable::find(const EndpointKey& k, Match m, std::uint64_t ts_us) {
  const auto it = entries_.find(k);
  if (it == entries_.end()) return std::nullopt;
  auto& e = it->second;
  if (ts_us > e.last_used) {
    lru_.erase({e.last_used, e.seq, k});
    e.last_used = ts_us;
    lru_.insert({e.last_used, e.seq, k});
  }
  return Lookup{e.kind, e.secure, m, e.keys};
}

std::optional<Lookup> EndpointTable::lookup(const EndpointKey& dst, const EndpointKey& src, std::uint64_t ts_us) {
  if (auto d = find(dst, Match::dst, ts_us)) return d;
  return find(src, Match::src, ts_us);
}

}  // namespace mcxanon::media
