// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/walker.hpp"

#include <algorithm>
#include <cstring>

namespace mcxanon::scan::detail {
namespace {

constexpr std::uint32_t kMaxBlock = 64u * 1024u * 1024u;

std::uint32_t rd32(const std::uint8_t* p, bool le) {
  return le ? (static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
               (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24))
            : ((static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8) | p[3]);
}
std::uint16_t rd16(const std::uint8_t* p, bool le) {
  return le ? static_cast<std::uint16_t>(p[0] | (p[1] << 8)) : static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

class Stream {
 public:
  explicit Stream(const ReadFn& r) : read_(r) {}
  // Reads exactly n bytes into buf (appending); returns false at the end of data.
  bool get(std::vector<std::uint8_t>& buf, std::size_t n) {
    const std::size_t at = buf.size();
    buf.resize(at + n);
    std::size_t done = 0;
    while (done < n) {
      const std::size_t got = read_(buf.data() + at + done, n - done);
      if (got == 0) break;
      done += got;
    }
    buf.resize(at + done);
    return done == n;
  }

 private:
  const ReadFn& read_;
};

void raw_rest(Stream& s, std::vector<std::uint8_t> head, std::uint64_t offset,
              const std::function<void(const WalkRecord&)>& visit) {
  std::vector<std::uint8_t> buf = std::move(head);
  for (;;) {
    if (!buf.empty()) {
      WalkRecord r;
      r.offset = offset;
      r.bytes = buf;
      visit(r);
      offset += buf.size();
    }
    buf.clear();
    if (!s.get(buf, 1u << 20) && buf.empty()) return;
  }
}

// Numeric values of kept options (headers are always numeric).
void option_numeric(const std::uint8_t* p, std::size_t len, std::uint64_t base, bool le, std::uint32_t block,
                    std::vector<Range>& out) {
  std::size_t q = 0;
  while (q + 4 <= len) {
    const std::uint16_t code = rd16(p + q, le);
    const std::uint16_t olen = rd16(p + q + 2, le);
    out.push_back({base + q, base + q + 4});
    if (code == 0) return;
    const std::size_t padded = (olen + 3u) & ~3u;
    if (q + 4 + padded > len) return;
    const bool numeric = (block == 1 && (code == 9 || code == 13 || code == 14)) ||
                         (block == 6 && (code == 2 || code == 4)) || (block == 2 && code == 2) ||
                         (block == 5 && code >= 2 && code <= 8);
    if (numeric) out.push_back({base + q + 4, base + q + 4 + olen});
    q += 4 + padded;
  }
}

void walk_pcap(Stream& s, std::vector<std::uint8_t> head, const std::function<void(const WalkRecord&)>& visit) {
  if (!s.get(head, 24 - head.size())) {
    raw_rest(s, std::move(head), 0, visit);
    return;
  }
  const bool le = head[0] == 0xD4 || head[0] == 0x4D;
  const std::uint16_t linktype = static_cast<std::uint16_t>(rd32(head.data() + 20, le) & 0xFFFFu);
  WalkRecord hr;
  hr.type = RecordType::pcap_header;
  hr.bytes = head;
  hr.little_endian = le;
  hr.header.push_back({0, 24});
  visit(hr);
  std::uint64_t offset = 24;
  std::uint64_t frame = 0;
  std::vector<std::uint8_t> rec;
  for (;;) {
    rec.clear();
    if (!s.get(rec, 16)) {
      raw_rest(s, std::move(rec), offset, visit);
      return;
    }
    const std::uint32_t caplen = rd32(rec.data() + 8, le);
    if (caplen > kMaxBlock || !s.get(rec, caplen)) {
      raw_rest(s, std::move(rec), offset, visit);
      return;
    }
    WalkRecord r;
    r.offset = offset;
    r.bytes = rec;
    r.type = RecordType::pcap_packet;
    r.frame = ++frame;
    r.little_endian = le;
    r.linktype = linktype;
    r.packet_offset = 16;
    r.packet_length = caplen;
    r.header.push_back({offset, offset + 16});
    packet_fields(linktype, std::span(rec).subspan(16), offset + 16, r.header, r.ipv4_slots);
    visit(r);
    offset += rec.size();
  }
}

void walk_pcapng(Stream& s, std::vector<std::uint8_t> head, const std::function<void(const WalkRecord&)>& visit) {
  std::uint64_t offset = 0;
  std::uint64_t frame = 0;
  bool le = true;
  std::vector<std::uint16_t> links;
  std::vector<std::uint8_t> blk = std::move(head);
  for (;;) {
    if (blk.size() < 12 && !s.get(blk, 12 - blk.size())) {
      raw_rest(s, std::move(blk), offset, visit);
      return;
    }
    const std::uint32_t raw_type = rd32(blk.data(), true);
    if (raw_type == 0x0A0D0D0Au) {
      if (rd32(blk.data() + 8, true) == 0x1A2B3C4Du) le = true;
      else if (rd32(blk.data() + 8, false) == 0x1A2B3C4Du) le = false;
      else {
        raw_rest(s, std::move(blk), offset, visit);
        return;
      }
      links.clear();
    }
    const std::uint32_t type = rd32(blk.data(), le);
    const std::uint32_t total = rd32(blk.data() + 4, le);
    if (total < 12 || total % 4 != 0 || total > kMaxBlock || !s.get(blk, total - 12) ||
        rd32(blk.data() + total - 4, le) != total) {
      raw_rest(s, std::move(blk), offset, visit);
      return;
    }
    WalkRecord r;
    r.offset = offset;
    r.bytes = blk;
    r.type = RecordType::pcapng_block;
    r.block_type = type;
    r.little_endian = le;
    r.header.push_back({offset, offset + 8});
    r.header.push_back({offset + total - 4, offset + total});
    const std::uint8_t* b = blk.data();
    const auto opts = [&](std::size_t at) {
      if (at + 4 <= total) option_numeric(b + at, total - 4 - at, offset + at, le, type, r.header);
    };
    switch (type) {
      case 0x0A0D0D0Au:
        r.header.push_back({offset + 8, offset + std::min<std::uint32_t>(24, total - 4)});
        opts(24);
        break;
      case 1:
        if (total >= 20) {
          links.push_back(rd16(b + 8, le));
          r.header.push_back({offset + 8, offset + 16});
          opts(16);
        }
        break;
      case 6:
      case 2:
        if (total >= 32) {
          const std::uint32_t ifid = type == 6 ? rd32(b + 8, le) : rd16(b + 8, le);
          const std::uint32_t caplen = rd32(b + 20, le);
          r.header.push_back({offset + 8, offset + 28});
          if (caplen <= total - 32) {
            r.frame = ++frame;
            r.linktype = ifid < links.size() ? links[ifid] : 0xFFFF;
            r.packet_offset = 28;
            r.packet_length = caplen;
            packet_fields(r.linktype, std::span(blk).subspan(28, caplen), offset + 28, r.header, r.ipv4_slots);
            // The padding to 32 bits is framing too: a short value straddling it and the next
            // field is a chance match (FR-032a).
            if (caplen % 4 != 0) r.header.push_back({offset + 28 + caplen, offset + 28 + ((caplen + 3u) & ~3u)});
            opts(28 + ((caplen + 3u) & ~3u));
          }
        }
        break;
      case 3:
        if (total >= 16) {
          const std::uint32_t len = std::min<std::uint32_t>(rd32(b + 8, le), total - 16);
          r.header.push_back({offset + 8, offset + 12});
          r.frame = ++frame;
          r.linktype = links.empty() ? 0xFFFF : links[0];
          r.packet_offset = 12;
          r.packet_length = len;
          packet_fields(r.linktype, std::span(blk).subspan(12, len), offset + 12, r.header, r.ipv4_slots);
          if (len % 4 != 0) r.header.push_back({offset + 12 + len, offset + 12 + ((len + 3u) & ~3u)});
        }
        break;
      case 5:
        if (total >= 24) {
          r.header.push_back({offset + 8, offset + 20});
          opts(20);
        }
        break;
      default:
        break;
    }
    visit(r);
    offset += total;
    blk.clear();
    if (!s.get(blk, 12)) {
      if (!blk.empty()) raw_rest(s, std::move(blk), offset, visit);
      return;
    }
  }
}

}  // namespace

void walk(const ReadFn& read, const std::function<void(const WalkRecord&)>& visit) {
  Stream s(read);
  std::vector<std::uint8_t> head;
  s.get(head, 4);
  if (head.size() == 4) {
    const bool pcap = (head[0] == 0xD4 && head[1] == 0xC3 && head[2] == 0xB2 && head[3] == 0xA1) ||
                      (head[0] == 0xA1 && head[1] == 0xB2 && head[2] == 0xC3 && head[3] == 0xD4) ||
                      (head[0] == 0x4D && head[1] == 0x3C && head[2] == 0xB2 && head[3] == 0xA1) ||
                      (head[0] == 0xA1 && head[1] == 0xB2 && head[2] == 0x3C && head[3] == 0x4D);
    const bool pcapng = head[0] == 0x0A && head[1] == 0x0D && head[2] == 0x0D && head[3] == 0x0A;
    if (pcap) return walk_pcap(s, std::move(head), visit);
    if (pcapng) return walk_pcapng(s, std::move(head), visit);
  }
  raw_rest(s, std::move(head), 0, visit);
}

}  // namespace mcxanon::scan::detail
