// SPDX-License-Identifier: GPL-3.0-or-later
// Internal: shared state of one dissection.
#pragma once

#include "bytes/endian.hpp"
#include "dissect/packet.hpp"

namespace mcxanon::detail {

struct Frame {
  int depth = 0;
  int parent_ip = -1;
  bool embedded = false;
};

class Ctx {
 public:
  Ctx(ByteView d, Dissection& o, const DissectOptions& options)
      : data(d), out(o), opt(options) {}

  ByteView data;
  Dissection& out;
  const DissectOptions& opt;

  [[nodiscard]] std::uint8_t u8(std::size_t off) const { return data[off]; }
  [[nodiscard]] std::uint16_t u16(std::size_t off) const { return be16(data, off); }
  [[nodiscard]] std::uint32_t u32(std::size_t off) const { return be32(data, off); }

  int add_layer(const Layer& l) {
    out.layers.push_back(l);
    return static_cast<int>(out.layers.size()) - 1;
  }
  Layer& layer(int i) { return out.layers[static_cast<std::size_t>(i)]; }

  // Emits a field; zero-length fields are skipped.
  void emit(Fid f, std::size_t off, std::size_t len, int layer) {
    if (len > 0) out.fields.push_back({f, off, len, layer});
  }
  // Covers [p, limit) with one field.
  void rest(Fid f, std::size_t p, std::size_t limit, int layer) {
    if (limit > p) emit(f, p, limit - p, layer);
  }
  void unknown(std::string_view kind, std::uint64_t id) { out.unknown.push_back({kind, id}); }
  void parse_failure(std::size_t p, std::size_t limit, int layer) {
    out.parse_failure = true;
    rest(Fid::payload_unparsed, p, limit, layer);
  }
};

// Each parser covers [p, return value) with fields; the caller covers the
// remainder up to its own limit.
std::size_t parse_ethernet(Ctx& c, std::size_t p, std::size_t limit, const Frame& f);
std::size_t parse_ethertype(Ctx& c, std::uint16_t type, std::size_t p, std::size_t limit,
                            int link_layer, const Frame& f);
std::size_t parse_ipv4(Ctx& c, std::size_t p, std::size_t limit, const Frame& f);
std::size_t parse_ipv6(Ctx& c, std::size_t p, std::size_t limit, const Frame& f);
// Upper-layer protocol after an IP header; covers [p, limit).
void parse_ip_upper(Ctx& c, std::uint8_t proto, bool v6, std::size_t p, std::size_t limit,
                    int ip_layer, const Frame& f);
void parse_icmpv4(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_icmpv6(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_tcp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_udp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_sctp(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_gre(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
void parse_gtpu(Ctx& c, std::size_t p, std::size_t limit, int ip_layer, const Frame& f);
// Nested IP packet (tunnels): checks the depth bound; covers [p, limit).
void parse_nested_ip(Ctx& c, bool v6, std::size_t p, std::size_t limit, const Frame& f);

inline std::size_t pad4(std::size_t n) { return (n + 3u) & ~std::size_t{3}; }

}  // namespace mcxanon::detail
