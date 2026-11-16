// SPDX-License-Identifier: GPL-3.0-or-later
#include "rewrite/pcapng_meta.hpp"

#include "bytes/reader.hpp"

#include <cstdio>

namespace mcxanon {
namespace {

void add_strings(ByteView v, std::vector<RemovedValue>& out) {
  std::size_t start = 0;
  for (std::size_t i = 0; i <= v.size(); ++i) {
    if (i == v.size() || v[i] == 0) {
      if (i > start) out.push_back({"string", Bytes(v.begin() + static_cast<std::ptrdiff_t>(start),
                                                     v.begin() + static_cast<std::ptrdiff_t>(i))});
      start = i + 1;
    }
  }
}

void add_bytes(const char* cat, ByteView v, std::size_t n, std::vector<RemovedValue>& out) {
  if (v.size() >= n) out.push_back({cat, Bytes(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(n))});
}

void collect_option_value(std::uint32_t block_type, const PcapngOption& o,
                          std::vector<RemovedValue>& out) {
  const ByteView v(o.value);
  if (o.code == 2988 || o.code == 19372) {  // custom string option: PEN, then UTF-8
    if (v.size() > 4) add_strings(v.subspan(4), out);
    return;
  }
  if (o.code == 1) {
    add_strings(v, out);
    return;
  }
  if (block_type == kPcapngShb && o.code >= 2 && o.code <= 4) {
    add_strings(v, out);
    return;
  }
  if (block_type == kPcapngIdb) {
    switch (o.code) {
      case 2: case 3: case 12: case 15: case 18: add_strings(v, out); return;
      case 11: if (v.size() > 1) add_strings(v.subspan(1), out); return;
      case 4: add_bytes("ipv4", v, 4, out); return;
      case 5: add_bytes("ipv6", v, 16, out); return;
      case 6: add_bytes("mac", v, 6, out); return;
      case 7: add_bytes("string", v, 8, out); return;
      default: return;
    }
  }
}

}  // namespace

Fid block_fid(std::uint32_t t) {
  switch (t) {
    case kPcapngShb: return Fid::pcapng_blk_shb;
    case kPcapngIdb: return Fid::pcapng_blk_idb;
    case kPcapngEpb: return Fid::pcapng_blk_epb;
    case kPcapngSpb: return Fid::pcapng_blk_spb;
    case kPcapngPacketObsolete: return Fid::pcapng_blk_pb;
    case kPcapngIsb: return Fid::pcapng_blk_isb;
    case kPcapngNrb: return Fid::pcapng_blk_nrb;
    case kPcapngDsb: return Fid::pcapng_blk_dsb;
    case 9: return Fid::pcapng_blk_journal;
    case kPcapngCustomCopy:
    case kPcapngCustomNoCopy: return Fid::pcapng_blk_custom;
    default: return Fid::pcapng_blk_other;
  }
}

Fid option_fid(std::uint32_t bt, std::uint16_t code) {
  if (code == 1) return Fid::pcapng_opt_comment;
  if (code == 2988 || code == 2989 || code == 19372 || code == 19373) return Fid::pcapng_opt_custom;
  switch (bt) {
    case kPcapngShb:
      switch (code) {
        case 2: return Fid::pcapng_shb_hardware;
        case 3: return Fid::pcapng_shb_os;
        case 4: return Fid::pcapng_shb_userappl;
        default: break;
      }
      break;
    case kPcapngIdb:
      switch (code) {
        case 2: return Fid::pcapng_idb_name;
        case 3: return Fid::pcapng_idb_description;
        case 4: return Fid::pcapng_idb_ipv4addr;
        case 5: return Fid::pcapng_idb_ipv6addr;
        case 6: return Fid::pcapng_idb_macaddr;
        case 7: return Fid::pcapng_idb_euiaddr;
        case 8: return Fid::pcapng_idb_speed;
        case 9: return Fid::pcapng_idb_tsresol;
        case 10: return Fid::pcapng_idb_tzone;
        case 11: return Fid::pcapng_idb_filter;
        case 12: return Fid::pcapng_idb_os;
        case 13: return Fid::pcapng_idb_fcslen;
        case 14: return Fid::pcapng_idb_tsoffset;
        case 15: return Fid::pcapng_idb_hardware;
        case 16: return Fid::pcapng_idb_txspeed;
        case 17: return Fid::pcapng_idb_rxspeed;
        case 18: return Fid::pcapng_idb_iana_tzname;
        default: break;
      }
      break;
    case kPcapngEpb:
    case kPcapngPacketObsolete:  // pack_flags / pack_hash equal epb_flags / epb_hash
      switch (code) {
        case 2: return Fid::pcapng_epb_flags;
        case 3: return Fid::pcapng_epb_hash;
        case 4: return bt == kPcapngEpb ? Fid::pcapng_epb_dropcount : Fid::pcapng_opt_other;
        case 5: return bt == kPcapngEpb ? Fid::pcapng_epb_packetid : Fid::pcapng_opt_other;
        case 6: return bt == kPcapngEpb ? Fid::pcapng_epb_queue : Fid::pcapng_opt_other;
        case 7: return bt == kPcapngEpb ? Fid::pcapng_epb_verdict : Fid::pcapng_opt_other;
        case 8:
          return bt == kPcapngEpb ? Fid::pcapng_epb_processid_threadid : Fid::pcapng_opt_other;
        default: break;
      }
      break;
    case kPcapngIsb:
      switch (code) {
        case 2: return Fid::pcapng_isb_starttime;
        case 3: return Fid::pcapng_isb_endtime;
        case 4: return Fid::pcapng_isb_ifrecv;
        case 5: return Fid::pcapng_isb_ifdrop;
        case 6: return Fid::pcapng_isb_filteraccept;
        case 7: return Fid::pcapng_isb_osdrop;
        case 8: return Fid::pcapng_isb_usrdeliv;
        default: break;
      }
      break;
    default:
      break;
  }
  return Fid::pcapng_opt_other;
}

bool block_structure_known(std::uint32_t t) {
  return t == kPcapngShb || t == kPcapngIdb || t == kPcapngEpb || t == kPcapngSpb ||
         t == kPcapngPacketObsolete || t == kPcapngIsb;
}

std::string block_key(std::uint32_t t) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "0x%08x", t);
  return buf;
}

bool keep_block(std::uint32_t t, const Policy& policy, RewriteStats& stats, MetaStats& meta) {
  const Fid f = block_fid(t);
  Decision d = policy.decide(f);
  if (!block_structure_known(t)) d.action = Action::remove;
  auto& c = stats.counters[std::string(field_name(f))];
  ++c[std::string(to_string(d.action))];
  if (d.unclassified) ++c["unclassified"];
  if (d.action != Action::keep) {
    ++meta.removed_blocks[block_key(t)];
    return false;
  }
  return true;
}

std::vector<PcapngOption> filter_options(std::uint32_t bt, const std::vector<PcapngOption>& options,
                                         Endian, const Policy& policy, RewriteStats& stats,
                                         MetaStats& meta, std::vector<RemovedValue>& removed) {
  std::vector<PcapngOption> kept;
  for (const auto& o : options) {
    const Fid f = option_fid(bt, o.code);
    Decision d = policy.decide(f);
    if (is_local_use_type(o.code, true)) d.action = Action::remove;
    auto& c = stats.counters[std::string(field_name(f))];
    ++c[std::string(to_string(d.action))];
    if (d.unclassified) ++c["unclassified"];
    if (d.action == Action::keep) {
      kept.push_back(o);
    } else {
      ++meta.removed_options[block_key(bt) + "/" + std::to_string(o.code)];
      collect_option_value(bt, o, removed);
    }
  }
  return kept;
}

void collect_block_values(std::uint32_t bt, ByteView block, Endian e,
                          std::vector<RemovedValue>& removed) {
  if (bt != kPcapngNrb || block.size() < 16) return;
  Reader r(block.subspan(8, block.size() - 12), e);
  for (;;) {
    auto type = r.u16();
    auto len = r.u16();
    if (!type || !len || *type == 0) break;
    auto v = r.bytes(*len);
    if (!v) return;
    (void)r.skip((4u - (static_cast<std::size_t>(*len) % 4u)) % 4u);
    switch (*type) {
      case 1: add_bytes("ipv4", *v, 4, removed); if (v->size() > 4) add_strings(v->subspan(4), removed); break;
      case 2: add_bytes("ipv6", *v, 16, removed); if (v->size() > 16) add_strings(v->subspan(16), removed); break;
      case 3: add_bytes("mac", *v, 6, removed); if (v->size() > 6) add_strings(v->subspan(6), removed); break;
      case 4: add_bytes("string", *v, 8, removed); if (v->size() > 8) add_strings(v->subspan(8), removed); break;
      default: add_strings(*v, removed); break;
    }
  }
  const std::size_t opts_at = 8 + r.offset();
  auto opts = parse_options(block.subspan(opts_at, block.size() - 4 - opts_at), e);
  if (!opts) return;
  for (const auto& o : *opts) {
    if (o.code == 3) add_bytes("ipv4", o.value, 4, removed);
    else if (o.code == 4) add_bytes("ipv6", o.value, 16, removed);
    else add_strings(o.value, removed);
  }
}

}  // namespace mcxanon
