// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/pcapng.hpp"

#include "bytes/reader.hpp"

#include <string>

namespace mcxanon {
namespace {

std::size_t pad4(std::size_t n) { return (n + 3u) & ~std::size_t{3}; }

}  // namespace

Result<std::vector<PcapngOption>> parse_options(ByteView region, Endian e) {
  std::vector<PcapngOption> out;
  Reader r(region, e);
  while (!r.empty()) {
    auto code = r.u16();
    auto len = r.u16();
    if (!code || !len) return fail(ErrorCode::input, "pcapng option header truncated");
    if (*code == kOptEndOfOpt) break;
    auto value = r.bytes(*len);
    if (!value) return fail(ErrorCode::input, "pcapng option value overruns its block");
    const std::size_t padding = pad4(*len) - *len;
    if (r.remaining() < padding) return fail(ErrorCode::input, "pcapng option padding truncated");
    (void)r.skip(padding);
    out.push_back(PcapngOption{*code, Bytes(value->begin(), value->end())});
  }
  return out;
}

Bytes serialize_options(const std::vector<PcapngOption>& options, Endian e) {
  Bytes out;
  if (options.empty()) return out;
  for (const auto& o : options) {
    const std::size_t at = out.size();
    out.resize(at + 4 + pad4(o.value.size()), 0);
    store16(out, at, o.code, e);
    store16(out, at + 2, static_cast<std::uint16_t>(o.value.size()), e);
    std::copy(o.value.begin(), o.value.end(), out.begin() + static_cast<std::ptrdiff_t>(at + 4));
  }
  out.resize(out.size() + 4, 0);  // opt_endofopt
  return out;
}

Result<std::optional<std::size_t>> option_region_offset(std::uint32_t block_type, ByteView block,
                                                         Endian e) {
  if (block.size() < 12) return fail(ErrorCode::input, "pcapng block too short");
  const std::size_t body_end = block.size() - 4;
  auto at = [&](std::size_t off) -> Result<std::optional<std::size_t>> {
    if (off > body_end) return fail(ErrorCode::input, "pcapng block body shorter than its fields");
    return std::optional<std::size_t>(off);
  };
  switch (block_type) {
    case kPcapngShb:
      return at(8 + 16);
    case kPcapngIdb:
      return at(8 + 8);
    case kPcapngIsb:
      return at(8 + 12);
    case kPcapngEpb:
    case kPcapngPacketObsolete: {
      if (block.size() < 8 + 20 + 4) return fail(ErrorCode::input, "packet block truncated");
      const std::uint32_t caplen = load32(block, 8 + 12, e);
      return at(8 + 20 + pad4(caplen));
    }
    case kPcapngDsb: {
      if (block.size() < 8 + 8 + 4) return fail(ErrorCode::input, "DSB truncated");
      const std::uint32_t len = load32(block, 8 + 4, e);
      return at(8 + 8 + pad4(len));
    }
    case kPcapngNrb: {
      // Records (type 16, length 16, value padded) up to nrb_record_end (§4.5).
      Reader r(block.subspan(8, body_end - 8), e);
      for (;;) {
        auto type = r.u16();
        auto len = r.u16();
        if (!type || !len) return fail(ErrorCode::input, "NRB record header truncated");
        if (*type == 0) return at(8 + r.offset());
        if (!r.skip(pad4(*len))) return fail(ErrorCode::input, "NRB record overruns its block");
      }
    }
    default:
      return std::optional<std::size_t>();  // SPB, custom and unknown blocks: no option list
  }
}

Bytes build_block(std::uint32_t block_type, ByteView fixed_body,
                  const std::vector<PcapngOption>& options, Endian e) {
  const Bytes opts = serialize_options(options, e);
  const std::size_t total = 8 + pad4(fixed_body.size()) + opts.size() + 4;
  Bytes b(total, 0);
  store32(b, 0, block_type, e);
  store32(b, 4, static_cast<std::uint32_t>(total), e);
  std::copy(fixed_body.begin(), fixed_body.end(), b.begin() + 8);
  std::copy(opts.begin(), opts.end(),
            b.begin() + static_cast<std::ptrdiff_t>(8 + pad4(fixed_body.size())));
  store32(b, total - 4, static_cast<std::uint32_t>(total), e);
  return b;
}

Bytes build_shb(Endian e, const std::vector<PcapngOption>& options) {
  Bytes body(16, 0);
  store32(body, 0, kPcapngByteOrderMagic, e);
  store16(body, 4, 1, e);
  store16(body, 6, 0, e);
  store64(body, 8, 0xFFFFFFFFFFFFFFFFull, e);
  return build_block(kPcapngShb, body, options, e);
}

Result<InterfaceInfo> parse_idb(ByteView block, Endian e) {
  if (block.size() < 8 + 8 + 4) return fail(ErrorCode::input, "IDB truncated");
  InterfaceInfo info;
  info.linktype = load16(block, 8, e);
  info.snaplen = load32(block, 12, e);
  auto opts = parse_options(block.subspan(16, block.size() - 16 - 4), e);
  if (!opts) return std::unexpected(opts.error());
  for (const auto& o : *opts) {
    if (o.code == 9 && o.value.size() == 1) info.tsresol = o.value[0];
    if (o.code == 14 && o.value.size() == 8) {
      info.tsoffset = static_cast<std::int64_t>(load64(o.value, 0, e));
    }
    if (o.code == 13 && o.value.size() == 1) info.fcslen = o.value[0];
  }
  return info;
}

}  // namespace mcxanon
