// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/rtcp.hpp"

#include "media/mki.hpp"

#include "media/app.hpp"
#include "media/wire.hpp"
#include "sip/sdp.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::media {
namespace {

// RFC 3711 §3.4: the encrypted portion starts "from the ninth (9) octet"; the first 8 octets are
// the first packet's header and SSRC.
Result<std::optional<Bytes>> srtcp_view(ByteView d, RtcpEnv& env, const char* why) {
  ++env.counters.srtcp_view[why];
  if (d.size() < 8) return std::optional<Bytes>{};
  Bytes b(d.begin(), d.end());
  auto m = env.mapper.ssrc(get32(b, 4));
  if (!m) return std::unexpected(m.error());
  set32(b, 4, *m);
  // An APP name the rules know is public vocabulary: it is kept so that the packet still reads as
  // that family (an encrypted name is never a known one, RFC 3711 §3.4).
  const bool known_app = b[1] == 204 && b.size() >= 12 &&
                         env.rules.family_by_name(std::string_view(reinterpret_cast<const char*>(b.data() + 8), 4)) != nullptr;
  zero(b, known_app ? 12 : 8, b.size());
  // Feature 005 (FR-012a): an MKI after E+index (RFC 3711 §3.4) may carry key identifier pseudonyms.
  if (auto k = rewrite_mki(d, b, (known_app ? 12 : 8) + 4, true, env.keys, env.mapper, env.counters); !k) {
    return std::unexpected(k.error());
  }
  return std::optional<Bytes>(std::move(b));
}

std::string pt_key(std::uint8_t pt) { return pt >= 200 && pt <= 207 ? std::to_string(pt) : "other"; }

Result<void> map_ssrc(Bytes& b, std::size_t off, RtcpEnv& env) {
  if (off + 4 > b.size()) return {};
  auto m = env.mapper.ssrc(get32(b, off));
  if (!m) return std::unexpected(m.error());
  set32(b, off, *m);
  return {};
}

// The printable part of a removed value, as a scan token (FR-031).
void note_removed(ByteView v, RtcpEnv& env) {
  std::string t;
  for (const auto c : v) {
    if (c >= 0x20 && c < 0x7F) t.push_back(static_cast<char>(c));
  }
  if (t.size() >= 4) env.counters.removed(t);
}

void set_words(Bytes& p) { set16(p, 2, static_cast<std::uint16_t>(p.size() / 4 - 1)); }

// The header kept and the body zeroed: a packet type, block or value without a rule (P4).
Bytes header_only(ByteView p) {
  Bytes q(p.begin(), p.end());
  zero(q, 4, q.size());
  return q;
}

// A packet whose body does not follow its grammar: the header kept, the body zeroed, counted.
Bytes malformed(ByteView p, RtcpEnv& env) {
  ++env.counters.rtcp_zeroed["malformed"];
  return header_only(p);
}

// SR (RFC 3550 §6.4.1) and RR (§6.4.2): sender SSRC, sender info (SR), report blocks with their
// SSRC mapped and statistics kept; a profile-specific extension after the blocks is zeroed.
Result<Bytes> report(ByteView p, RtcpEnv& env) {
  Bytes q(p.begin(), p.end());
  const std::size_t blocks = p[0] & 0x1Fu;
  const std::size_t first = p[1] == 200 ? 28 : 8;
  if (q.size() < first + 24 * blocks) return malformed(p, env);
  if (auto r = map_ssrc(q, 4, env); !r) return std::unexpected(r.error());
  for (std::size_t k = 0; k < blocks; ++k) {
    if (auto r = map_ssrc(q, first + 24 * k, env); !r) return std::unexpected(r.error());
  }
  zero(q, first + 24 * blocks, q.size());
  return q;
}

std::string sdes_name(std::uint8_t type, RtcpEnv& env) {
  const auto it = env.rules.rtcp.sdes_items.find(type);
  return it == env.rules.rtcp.sdes_items.end() ? "unknown" : it->second.name;
}

// SDES (RFC 3550 §6.5): every chunk keeps its SSRC (mapped) and a pseudonymised CNAME (FR-010);
// every other item is removed. Chunks end with a null item and are padded to 32 bits.
Result<Bytes> sdes(ByteView p, RtcpEnv& env) {
  const std::size_t chunks = p[0] & 0x1Fu;
  Bytes out(p.begin(), p.begin() + 4);
  std::size_t i = 4;
  for (std::size_t k = 0; k < chunks; ++k) {
    if (i + 4 > p.size()) return malformed(p, env);
    Bytes chunk(p.begin() + static_cast<std::ptrdiff_t>(i), p.begin() + static_cast<std::ptrdiff_t>(i + 4));
    if (auto r = map_ssrc(chunk, 0, env); !r) return std::unexpected(r.error());
    i += 4;
    for (;;) {
      if (i >= p.size()) return malformed(p, env);
      const std::uint8_t type = p[i];
      if (type == 0) break;
      if (i + 2 > p.size()) return malformed(p, env);
      const std::size_t ilen = p[i + 1];
      if (i + 2 + ilen > p.size()) return malformed(p, env);
      const ByteView v = p.subspan(i + 2, ilen);
      i += 2 + ilen;
      const auto rule = env.rules.rtcp.sdes_items.find(type);
      if (rule != env.rules.rtcp.sdes_items.end() && rule->second.action == MediaAction::pseudonymise) {
        auto c = sip::map_cname(std::string_view(reinterpret_cast<const char*>(v.data()), v.size()), env.sip);
        if (!c) return std::unexpected(c.error());
        if (*c && (*c)->size() <= 255) {
          chunk.push_back(type);
          chunk.push_back(static_cast<std::uint8_t>((*c)->size()));
          chunk.insert(chunk.end(), (*c)->begin(), (*c)->end());
          continue;
        }
      }
      ++env.counters.sdes_removed[sdes_name(type, env)];
      note_removed(v, env);
    }
    // The null item, then padding to the next 32-bit boundary of the input (RFC 3550 §6.5).
    i += 1;
    while ((i - 4) % 4 != 0 && i < p.size()) ++i;
    chunk.push_back(0);
    pad4(chunk);
    out.insert(out.end(), chunk.begin(), chunk.end());
  }
  set_words(out);
  return out;
}

// BYE (RFC 3550 §6.6): SSRCs mapped, the optional reason removed (FR-011).
Result<Bytes> bye(ByteView p, RtcpEnv& env) {
  const std::size_t n = p[0] & 0x1Fu;
  if (p.size() < 4 + 4 * n) return malformed(p, env);
  Bytes out(p.begin(), p.begin() + static_cast<std::ptrdiff_t>(4 + 4 * n));
  for (std::size_t k = 0; k < n; ++k) {
    if (auto r = map_ssrc(out, 4 + 4 * k, env); !r) return std::unexpected(r.error());
  }
  if (p.size() > 4 + 4 * n) {
    const std::size_t len = p[4 + 4 * n];
    note_removed(p.subspan(5 + 4 * n, std::min(len, p.size() - 5 - 4 * n)), env);
  }
  set_words(out);
  return out;
}

// RTPFB / PSFB (RFC 4585 §6.1): sender and media source SSRCs mapped; the FCI kept by rule,
// RPSI (§6.3.3) with its native bit string zeroed, anything else zeroed (FR-012).
Result<Bytes> feedback(ByteView p, RtcpEnv& env) {
  if (p.size() < 12) return malformed(p, env);
  Bytes q(p.begin(), p.end());
  if (auto r = map_ssrc(q, 4, env); !r) return std::unexpected(r.error());
  if (auto r = map_ssrc(q, 8, env); !r) return std::unexpected(r.error());
  const std::uint8_t fmt = p[0] & 0x1Fu;
  const std::string key = std::to_string(p[1]) + "/" + std::to_string(fmt);
  const auto rule = env.rules.rtcp.feedback.find({p[1], fmt});
  if (rule == env.rules.rtcp.feedback.end() || rule->second.action != MediaAction::keep) {
    zero(q, 12, q.size());
    env.counters.count(env.counters.rtcp_feedback, key, "zero");
    return q;
  }
  if (p[1] == 206 && fmt == 3) zero(q, 14, q.size());  // RPSI: PB and payload type stay
  env.counters.count(env.counters.rtcp_feedback, key, "keep");
  return q;
}

// XR (RFC 3611 §2, §3): sender SSRC mapped; blocks with a rule keep their content with their
// SSRC fields mapped (§4.1-§4.7); other blocks keep their 4-octet header (P4).
Result<Bytes> xr(ByteView p, RtcpEnv& env) {
  if (p.size() < 8) return malformed(p, env);
  Bytes q(p.begin(), p.end());
  if (auto r = map_ssrc(q, 4, env); !r) return std::unexpected(r.error());
  for (std::size_t i = 8; i < q.size();) {
    if (i + 4 > q.size()) {
      zero(q, i, q.size());
      ++env.counters.rtcp_zeroed["malformed"];
      break;
    }
    const std::uint8_t bt = q[i];
    const std::size_t len = 4 + 4 * std::size_t{get16(q, i + 2)};
    if (i + len > q.size()) {
      zero(q, i + 4, q.size());
      ++env.counters.rtcp_zeroed["malformed"];
      break;
    }
    const auto rule = env.rules.rtcp.xr_blocks.find(bt);
    const std::string key = rule == env.rules.rtcp.xr_blocks.end() ? "other" : std::to_string(bt);
    if (rule == env.rules.rtcp.xr_blocks.end() || rule->second.action != MediaAction::keep) {
      zero(q, i + 4, i + len);
      env.counters.count(env.counters.rtcp_xr, key, "zero");
    } else {
      if (bt == 5) {  // DLRR: sub-blocks of SSRC, LRR, DLRR
        for (std::size_t s = i + 4; s + 12 <= i + len; s += 12) {
          if (auto r = map_ssrc(q, s, env); !r) return std::unexpected(r.error());
        }
      } else if (bt != 4 && len >= 8) {  // the SSRC of source; RRT (4) carries none
        if (auto r = map_ssrc(q, i + 4, env); !r) return std::unexpected(r.error());
      }
      env.counters.count(env.counters.rtcp_xr, key, "keep");
    }
    i += len;
  }
  return q;
}

}  // namespace

Result<std::optional<Bytes>> rewrite_rtcp(ByteView datagram, bool secure, RtcpEnv& env) {
  if (secure) return srtcp_view(datagram, env, "secure");
  // Tiling (RFC 3550 §6.4.1, RFC 5506 §3.4): version 2, length in 32-bit words minus one, the
  // packets cover the datagram exactly.
  std::vector<std::pair<std::size_t, std::size_t>> packets;
  std::size_t off = 0;
  while (off < datagram.size()) {
    if (datagram.size() - off < 4 || (datagram[off] >> 6) != 2) return srtcp_view(datagram, env, "undecodable");
    const std::size_t len = 4 * (std::size_t{1} + ((std::size_t{datagram[off + 2]} << 8) | datagram[off + 3]));
    if (len > datagram.size() - off) return srtcp_view(datagram, env, "undecodable");
    packets.emplace_back(off, len);
    off += len;
  }
  if (packets.empty()) return srtcp_view(datagram, env, "undecodable");
  Bytes out;
  out.reserve(datagram.size());
  for (const auto& [o, len] : packets) {
    const ByteView p = datagram.subspan(o, len);
    const std::uint8_t pt = p[1];
    ++env.counters.rtcp_by_packet_type[pt_key(pt)];
    if (pt == 204) {
      auto a = rewrite_app(p, env);
      if (!a) return std::unexpected(a.error());
      out.insert(out.end(), a->begin(), a->end());  // empty: an APP name without rules is removed
      continue;
    }
    const auto rule = env.rules.rtcp.packet_types.find(pt);
    Result<Bytes> q = header_only(p);  // a packet type without a rule (P4)
    if (rule != env.rules.rtcp.packet_types.end() && rule->second.action == MediaAction::keep) {
      switch (pt) {
        case 200:
        case 201: q = report(p, env); break;
        case 202: q = sdes(p, env); break;
        case 203: q = bye(p, env); break;
        case 205:
        case 206: q = feedback(p, env); break;
        case 207: q = xr(p, env); break;
        default: break;
      }
    }
    if (!q) return std::unexpected(q.error());
    out.insert(out.end(), q->begin(), q->end());
  }
  return std::optional<Bytes>(std::move(out));
}

}  // namespace mcxanon::media
