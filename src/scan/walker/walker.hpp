// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own minimal framing walker for pcap / pcapng and L2-L4 fixed
// headers. Written separately from the anonymiser's readers and dissectors on
// purpose: it only needs record boundaries, frame numbers, the
// byte ranges of recognised header fields and the IPv4 address positions
// (FR-032a), and header addresses (FR-031 b); anything it cannot follow is
// raw bytes.
#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace mcxanon::scan::detail {

struct Range {
  std::uint64_t begin = 0;
  std::uint64_t end = 0;
};

enum class RecordType { raw, pcap_header, pcap_packet, pcapng_block };

struct WalkRecord {
  std::uint64_t offset = 0;
  std::span<const std::uint8_t> bytes;
  RecordType type = RecordType::raw;
  std::uint64_t frame = 0;       // 1-based for packet records
  std::uint32_t block_type = 0;  // pcapng
  bool little_endian = true;
  std::uint16_t linktype = 0;              // packet records
  std::size_t packet_offset = 0;           // packet data within the record
  std::size_t packet_length = 0;
  std::vector<Range> header;               // recognised header fields, absolute stream offsets
  std::vector<std::uint64_t> ipv4_slots;   // absolute offsets of IPv4 address positions
};

// Reads up to n bytes; returns the number read, 0 at the end.
using ReadFn = std::function<std::size_t(std::uint8_t*, std::size_t)>;

void walk(const ReadFn& read, const std::function<void(const WalkRecord&)>& visit);

// Recognised L2-L4 header field ranges of a packet and the positions where an
// IPv4 address can sit: IPv4 address fields and the embedding position of IPv6
// addresses with a well-known embedding prefix (offsets relative to `base`).
void packet_fields(std::uint16_t linktype, std::span<const std::uint8_t> pkt, std::uint64_t base,
                   std::vector<Range>& header, std::vector<std::uint64_t>& ipv4_slots);

struct Address {
  int kind = 0;  // 1 mac, 4 ipv4, 6 ipv6
  std::vector<std::uint8_t> value;
};
// Addresses of the recognised L2-L4 headers (tunnels included), special addresses excluded.
void packet_addresses(std::uint16_t linktype, std::span<const std::uint8_t> pkt, std::vector<Address>& out);

// Special addresses the anonymiser keeps (unspecified, loopback, broadcast, local multicast).
bool keeps_ipv4(const std::uint8_t* a);
bool keeps_ipv6(const std::uint8_t* a);

// UDP and TCP payloads of the recognised headers, with a direction key (source and destination
// address, source and destination port), for the SIP harvester (FR-031).
struct Payload {
  bool tcp = false;
  std::vector<std::uint8_t> direction;
  std::span<const std::uint8_t> bytes;
};
void packet_payloads(std::uint16_t linktype, std::span<const std::uint8_t> pkt, std::vector<Payload>& out);

}  // namespace mcxanon::scan::detail
