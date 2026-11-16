// SPDX-License-Identifier: GPL-3.0-or-later
//
// Classic pcap file header and packet record header
// (draft-ietf-opsawg-pcap-09 §4 and §5).
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"
#include "capture/record.hpp"

#include <cstdint>

namespace mcxanon {

inline constexpr std::size_t kPcapFileHeaderSize = 24;
inline constexpr std::size_t kPcapRecordHeaderSize = 16;

struct PcapFileHeader {
  Endian endian = Endian::little;
  bool nanosecond = false;
  std::uint16_t major = 2;
  std::uint16_t minor = 4;
  std::uint32_t snaplen = 262144;
  std::uint16_t linktype = 1;
  bool fcs_present = false;
  std::uint8_t fcs_len_words = 0;  // FCS length in 16-bit words (valid when fcs_present)
};

struct PcapPacketHeader {
  std::uint32_t ts_sec = 0;
  std::uint32_t ts_frac = 0;  // microseconds or nanoseconds per the file magic
  std::uint32_t caplen = 0;
  std::uint32_t origlen = 0;
};

Result<PcapFileHeader> parse_pcap_file_header(ByteView b);
Bytes build_pcap_file_header(const PcapFileHeader& h);
Result<PcapPacketHeader> parse_pcap_packet_header(ByteView record, Endian e);
void store_pcap_packet_header(MutByteView record, const PcapPacketHeader& h, Endian e);
// Packet data of a pcap_packet record.
ByteView pcap_packet_data(const Record& r);

}  // namespace mcxanon
