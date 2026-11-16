// SPDX-License-Identifier: GPL-3.0-or-later
//
// pcapng block and option structure (draft-ietf-opsawg-pcapng-06).
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace mcxanon {

// Block types (§10.1, Table 9).
inline constexpr std::uint32_t kPcapngShb = 0x0A0D0D0Au;
inline constexpr std::uint32_t kPcapngIdb = 1;
inline constexpr std::uint32_t kPcapngPacketObsolete = 2;
inline constexpr std::uint32_t kPcapngSpb = 3;
inline constexpr std::uint32_t kPcapngNrb = 4;
inline constexpr std::uint32_t kPcapngIsb = 5;
inline constexpr std::uint32_t kPcapngEpb = 6;
inline constexpr std::uint32_t kPcapngDsb = 10;
inline constexpr std::uint32_t kPcapngCustomCopy = 0x00000BADu;
inline constexpr std::uint32_t kPcapngCustomNoCopy = 0x40000BADu;
inline constexpr std::uint32_t kPcapngByteOrderMagic = 0x1A2B3C4Du;

// Common option codes (§3.5).
inline constexpr std::uint16_t kOptEndOfOpt = 0;
inline constexpr std::uint16_t kOptComment = 1;

inline constexpr std::size_t kPcapngMaxBlockSize = 64u * 1024u * 1024u;

struct PcapngOption {
  std::uint16_t code = 0;
  Bytes value;
  bool operator==(const PcapngOption&) const = default;
};

// A block type, or (with option = true) a 16-bit option code, whose most
// significant bit is set is reserved for local use (§3.1, §3.5).
constexpr bool is_local_use_type(std::uint32_t type, bool option = false) {
  return option ? (type & 0x8000u) != 0 : (type & 0x80000000u) != 0;
}

// Parses the TLV option list of a block. The list ends at opt_endofopt or at
// the end of the region. Values are copied without padding.
Result<std::vector<PcapngOption>> parse_options(ByteView region, Endian e);
// Serialises options with 32-bit padding and a final opt_endofopt; an empty
// list serialises to nothing.
Bytes serialize_options(const std::vector<PcapngOption>& options, Endian e);

// Offset of the option list within a complete block (from the block start),
// or nullopt when the block type has no options or an opaque body.
Result<std::optional<std::size_t>> option_region_offset(std::uint32_t block_type, ByteView block,
                                                         Endian e);

// Builds a block from its fixed body (padded to 32 bits here) and options.
Bytes build_block(std::uint32_t block_type, ByteView fixed_body,
                  const std::vector<PcapngOption>& options, Endian e);
// Builds an SHB version 1.0 with Section Length -1 (unspecified).
Bytes build_shb(Endian e, const std::vector<PcapngOption>& options);

// Per-interface information from an IDB (§4.2).
struct InterfaceInfo {
  std::uint16_t linktype = 0;
  std::uint32_t snaplen = 0;
  std::uint8_t tsresol = 6;       // if_tsresol; default 10^-6
  std::int64_t tsoffset = 0;      // if_tsoffset, seconds
  std::optional<std::uint8_t> fcslen;  // if_fcslen
};

Result<InterfaceInfo> parse_idb(ByteView block, Endian e);

}  // namespace mcxanon
