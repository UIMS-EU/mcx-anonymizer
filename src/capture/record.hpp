// SPDX-License-Identifier: GPL-3.0-or-later
//
// One unit of a capture file as read from disk, with its raw bytes. The
// capture layer knows file formats only, no network protocols.
#pragma once

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"

#include <cstdint>

namespace mcxanon {

enum class CaptureFormat { pcap, pcapng };

enum class RecordKind {
  pcap_file_header,  // the 24-byte pcap file header
  pcap_packet,       // a pcap packet record (16-byte header + data)
  pcapng_block,      // any pcapng block (header, body, trailing length)
};

struct Record {
  RecordKind kind = RecordKind::pcapng_block;
  Endian endian = Endian::little;  // byte order of the record's section / file
  std::uint32_t block_type = 0;    // pcapng block type
  std::uint64_t frame_number = 0;  // 1-based packet counter; 0 for non-packet records
  std::uint64_t file_offset = 0;   // offset of the record in the input file
  Bytes bytes;                     // the full record exactly as stored
};

}  // namespace mcxanon
