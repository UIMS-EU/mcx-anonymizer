// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/harvest.hpp"
#include "scan/walker/media_harvest.hpp"
#include "scan/walker/sip_harvest.hpp"
#include "scan/walker/web_harvest.hpp"

#include "mcxanon/scan.hpp"
#include "scan/walker/walker.hpp"

#include <cstdio>
#include <set>
#include <string>

namespace mcxanon::scan {
namespace detail {

bool harvest_allows(std::uint32_t block, std::uint16_t code) {
  switch (block) {
    case 1: return code == 9 || code == 13 || code == 14;   // if_tsresol, if_fcslen, if_tsoffset
    case 6: return code == 2 || code == 4;                  // epb_flags, epb_dropcount
    case 2: return code == 2;                               // pack_flags
    case 5: return code >= 2 && code <= 8;                  // ISB times and counters
    default: return false;
  }
}

namespace {

std::uint16_t rd16(const std::uint8_t* p, bool le) {
  return le ? static_cast<std::uint16_t>(p[0] | (p[1] << 8)) : static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

class Collector {
 public:
  void add(TokenCategory c, const std::uint8_t* b, std::size_t n) {
    if (n < 4) return;
    std::vector<std::uint8_t> v(b, b + n);
    if (seen_.insert({static_cast<int>(c), v}).second) {
      const char* cat = c == TokenCategory::mac ? "mac" : c == TokenCategory::ipv4 ? "ipv4"
                        : c == TokenCategory::ipv6 ? "ipv6" : "string";
      tokens_.push_back(Token{c, std::move(v), std::string("input:") + cat + "#" + std::to_string(++n_)});
    }
  }
  // NUL-separated strings, each one a token.
  void strings(const std::uint8_t* b, std::size_t n) {
    std::size_t start = 0;
    for (std::size_t i = 0; i <= n; ++i) {
      if (i == n || b[i] == 0) {
        add(TokenCategory::string, b + start, i - start);
        start = i + 1;
      }
    }
  }
  // Printable runs of at least 8 characters inside opaque data.
  void printable_runs(const std::uint8_t* b, std::size_t n) {
    std::size_t start = 0;
    std::size_t runs = 0;
    for (std::size_t i = 0; i <= n && runs < 4096; ++i) {
      const bool pr = i < n && b[i] >= 0x20 && b[i] < 0x7F;
      if (!pr) {
        if (i - start >= 8) {
          add(TokenCategory::string, b + start, i - start);
          ++runs;
        }
        start = i + 1;
      }
    }
  }
  std::vector<Token> take() { return std::move(tokens_); }

 private:
  std::set<std::pair<int, std::vector<std::uint8_t>>> seen_;
  std::vector<Token> tokens_;
  std::uint64_t n_ = 0;
};

void option_values(const WalkRecord& r, std::size_t at, Collector& c) {
  const bool le = r.little_endian;
  const std::uint8_t* b = r.bytes.data();
  const std::size_t end = r.bytes.size() >= 4 ? r.bytes.size() - 4 : 0;
  std::size_t q = at;
  while (q + 4 <= end) {
    const std::uint16_t code = rd16(b + q, le);
    const std::uint16_t len = rd16(b + q + 2, le);
    if (code == 0 || q + 4 + len > end) return;
    const std::uint8_t* v = b + q + 4;
    if (!harvest_allows(r.block_type, code)) {
      if (r.block_type == 1 && code == 4 && len >= 4) c.add(TokenCategory::ipv4, v, 4);
      else if (r.block_type == 1 && code == 5 && len >= 16) c.add(TokenCategory::ipv6, v, 16);
      else if (r.block_type == 1 && code == 6 && len >= 6) c.add(TokenCategory::mac, v, 6);
      else if (code == 2988 || code == 2989 || code == 19372 || code == 19373) {
        if (len > 4) c.strings(v + 4, len - 4u);
      } else if (r.block_type == 1 && code == 11 && len > 1) {
        c.strings(v + 1, len - 1u);
      } else {
        c.strings(v, len);
      }
    }
    q += 4 + ((len + 3u) & ~3u);
  }
}

void nrb_values(const WalkRecord& r, Collector& c) {
  const bool le = r.little_endian;
  const std::uint8_t* b = r.bytes.data();
  const std::size_t end = r.bytes.size() - 4;
  std::size_t q = 8;
  while (q + 4 <= end) {
    const std::uint16_t type = rd16(b + q, le);
    const std::uint16_t len = rd16(b + q + 2, le);
    if (type == 0 || q + 4 + len > end) break;
    const std::uint8_t* v = b + q + 4;
    const std::size_t alen = type == 1 ? 4 : type == 2 ? 16 : type == 3 ? 6 : type == 4 ? 8 : 0;
    if (alen > 0 && len >= alen) {
      c.add(type == 1 ? TokenCategory::ipv4 : type == 2 ? TokenCategory::ipv6
            : type == 3 ? TokenCategory::mac : TokenCategory::string, v, alen);
      c.strings(v + alen, len - alen);
    } else {
      c.strings(v, len);
    }
    q += 4 + ((len + 3u) & ~3u);
  }
  // NRB options follow the end record.
  if (q + 4 <= end) {
    WalkRecord opts = r;
    option_values(opts, q + 4, c);
  }
}

}  // namespace
}  // namespace detail

Result<std::vector<Token>> harvest_input(const std::filesystem::path& path, HarvestStats* stats) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return fail(ErrorCode::input, "cannot open " + path.filename().string() + " for harvesting");
  detail::Collector c;
  detail::SipHarvest sip;
  detail::WebHarvest web;  // feature 007
  detail::MediaHarvest media(sip);
  const detail::ReadFn read = [f](std::uint8_t* out, std::size_t n) { return std::fread(out, 1, n, f); };
  detail::walk(read, [&](const detail::WalkRecord& r) {
    if (r.type == detail::RecordType::pcapng_block) {
      switch (r.block_type) {
        case 0x0A0D0D0Au: detail::option_values(r, 24, c); break;
        case 1: detail::option_values(r, 16, c); break;
        case 5: detail::option_values(r, 20, c); break;
        case 6:
        case 2:
          if (r.packet_length > 0 || r.bytes.size() >= 32) {
            detail::option_values(r, 28 + ((r.packet_length + 3u) & ~std::size_t{3}), c);
          }
          break;
        case 3: break;
        case 4: detail::nrb_values(r, c); break;
        default:  // DSB, custom, journal, unknown: printable content
          if (r.bytes.size() > 12) c.printable_runs(r.bytes.data() + 8, r.bytes.size() - 12);
          break;
      }
    }
    if (r.frame > 0 && r.packet_length > 0) {
      std::vector<detail::Address> addrs;
      detail::packet_addresses(r.linktype, r.bytes.subspan(r.packet_offset, r.packet_length), addrs);
      for (const auto& a : addrs) {
        c.add(a.kind == 1 ? TokenCategory::mac : a.kind == 4 ? TokenCategory::ipv4 : TokenCategory::ipv6,
              a.value.data(), a.value.size());
      }
      // SIP and SDP identities in the L4 payloads (FR-031), by the scanner's own tokenizer.
      std::vector<detail::Payload> payloads;
      detail::packet_payloads(r.linktype, r.bytes.subspan(r.packet_offset, r.packet_length), payloads);
      for (const auto& p : payloads) {
        sip.feed(p.bytes, p.direction, p.tcp);
        if (p.tcp) web.feed(p.bytes, p.direction);
        // RTCP and MCX APP values over UDP, MSRP values over TCP (feature 004).
        if (p.tcp) {
          media.feed_tcp(p.bytes);
        } else {
          media.feed_udp(p.bytes);
        }
      }
    }
  });
  const bool err = std::ferror(f) != 0;
  std::fclose(f);
  if (err) return fail(ErrorCode::input, "read error while harvesting the input");
  auto tokens = c.take();
  auto sip_tokens = sip.take();
  if (stats != nullptr) stats->fragments = sip.fragments();
  tokens.insert(tokens.end(), std::make_move_iterator(sip_tokens.begin()), std::make_move_iterator(sip_tokens.end()));
  auto web_tokens = web.take();
  tokens.insert(tokens.end(), std::make_move_iterator(web_tokens.begin()), std::make_move_iterator(web_tokens.end()));
  return tokens;
}

}  // namespace mcxanon::scan
