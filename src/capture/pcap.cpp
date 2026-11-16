// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/pcap.hpp"

namespace mcxanon {

Result<PcapFileHeader> parse_pcap_file_header(ByteView b) {
  if (b.size() < kPcapFileHeaderSize) return fail(ErrorCode::input, "pcap file header truncated");
  PcapFileHeader h;
  const std::uint32_t be_magic = load32(b, 0, Endian::big);
  if (be_magic == 0xA1B2C3D4u || be_magic == 0xA1B23C4Du) {
    h.endian = Endian::big;
    h.nanosecond = be_magic == 0xA1B23C4Du;
  } else if (be_magic == 0xD4C3B2A1u || be_magic == 0x4D3CB2A1u) {
    h.endian = Endian::little;
    h.nanosecond = be_magic == 0x4D3CB2A1u;
  } else {
    return fail(ErrorCode::input, "not a pcap file (bad magic number)");
  }
  h.major = load16(b, 4, h.endian);
  h.minor = load16(b, 6, h.endian);
  if (h.major != 2) return fail(ErrorCode::input, "unsupported pcap major version");
  h.snaplen = load32(b, 16, h.endian);
  const std::uint32_t lt = load32(b, 20, h.endian);
  // Field layout, most significant bit first: FCS len (4), R (1), P (1), Reserved3 (10),
  // LinkType (16).
  const bool r_bit = ((lt >> 27) & 1u) != 0;
  const std::uint32_t reserved3 = (lt >> 16) & 0x3FFu;
  if (r_bit || reserved3 != 0) {
    return fail(ErrorCode::input, "pcap LinkType field has non-zero reserved bits");
  }
  h.fcs_present = ((lt >> 26) & 1u) != 0;
  h.fcs_len_words = static_cast<std::uint8_t>(lt >> 28);
  h.linktype = static_cast<std::uint16_t>(lt & 0xFFFFu);
  return h;
}

Bytes build_pcap_file_header(const PcapFileHeader& h) {
  Bytes b(kPcapFileHeaderSize, 0);
  store32(b, 0, h.nanosecond ? 0xA1B23C4Du : 0xA1B2C3D4u, h.endian);
  store16(b, 4, h.major, h.endian);
  store16(b, 6, h.minor, h.endian);
  store32(b, 16, h.snaplen, h.endian);
  std::uint32_t lt = h.linktype;
  if (h.fcs_present) lt |= (1u << 26) | (static_cast<std::uint32_t>(h.fcs_len_words & 0x0F) << 28);
  store32(b, 20, lt, h.endian);
  return b;
}

Result<PcapPacketHeader> parse_pcap_packet_header(ByteView record, Endian e) {
  if (record.size() < kPcapRecordHeaderSize) {
    return fail(ErrorCode::input, "pcap record header truncated");
  }
  PcapPacketHeader h;
  h.ts_sec = load32(record, 0, e);
  h.ts_frac = load32(record, 4, e);
  h.caplen = load32(record, 8, e);
  h.origlen = load32(record, 12, e);
  return h;
}

void store_pcap_packet_header(MutByteView record, const PcapPacketHeader& h, Endian e) {
  store32(record, 0, h.ts_sec, e);
  store32(record, 4, h.ts_frac, e);
  store32(record, 8, h.caplen, e);
  store32(record, 12, h.origlen, e);
}

ByteView pcap_packet_data(const Record& r) {
  if (r.bytes.size() < kPcapRecordHeaderSize) return {};
  return ByteView(r.bytes).subspan(kPcapRecordHeaderSize);
}

}  // namespace mcxanon
