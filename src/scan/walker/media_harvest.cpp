// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/media_harvest.hpp"
#include "scan/walker/mikey_harvest.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <vector>

namespace mcxanon::scan::detail {
namespace {

std::uint32_t be32(const std::uint8_t* p) {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}

std::string_view text(std::span<const std::uint8_t> v) {
  return {reinterpret_cast<const char*>(v.data()), v.size()};
}

}  // namespace

void MediaHarvest::feed_udp(std::span<const std::uint8_t> d) {
  // The RTCP shape: every packet version 2 with a report, SDES, BYE, APP, feedback or XR type,
  // the lengths tiling the datagram (RFC 3550 §6.4.1, RFC 5506).
  std::vector<std::span<const std::uint8_t>> packets;
  for (std::size_t o = 0; o < d.size();) {
    if (d.size() - o < 8 || (d[o] >> 6) != 2 || d[o + 1] < 200 || d[o + 1] > 207) return;
    const std::size_t len = 4 * (std::size_t{1} + ((std::size_t{d[o + 2]} << 8) | d[o + 3]));
    if (len > d.size() - o) return;
    packets.push_back(d.subspan(o, len));
    o += len;
  }
  for (const auto p : packets) {
    const std::size_t count = p[0] & 0x1Fu;
    out_.ssrc(be32(&p[4]));
    switch (p[1]) {
      case 200:
      case 201: {
        const std::size_t first = p[1] == 200 ? 28 : 8;
        for (std::size_t k = 0; k < count && first + 24 * (k + 1) <= p.size(); ++k) {
          out_.ssrc(be32(&p[first + 24 * k]));
        }
        break;
      }
      case 202: {  // SDES chunks: SSRC, then items until a null item
        std::size_t i = 4;
        for (std::size_t k = 0; k < count && i + 4 <= p.size(); ++k) {
          out_.ssrc(be32(&p[i]));
          i += 4;
          while (i < p.size() && p[i] != 0) {
            if (i + 2 > p.size() || i + 2 + p[i + 1] > p.size()) return;
            out_.text_value(text(p.subspan(i + 2, p[i + 1])), "sdes");
            i += 2 + std::size_t{p[i + 1]};
          }
          i = (i + 4) & ~std::size_t{3};
        }
        break;
      }
      case 203:  // BYE: SSRCs, then an optional reason
        for (std::size_t k = 1; k < count && 4 + 4 * (k + 1) <= p.size(); ++k) out_.ssrc(be32(&p[4 + 4 * k]));
        if (4 + 4 * count < p.size()) {
          const std::size_t at = 4 + 4 * count;
          const std::size_t len = p[at];
          if (at + 1 + len <= p.size()) out_.text_value(text(p.subspan(at + 1, len)), "bye");
        }
        break;
      case 204: app(p); break;
      case 205:
      case 206:
        if (p.size() >= 12) out_.ssrc(be32(&p[8]));
        break;
      default: break;
    }
  }
}

void MediaHarvest::feed_tcp(std::span<const std::uint8_t> payload) {
  const std::string_view t = text(payload);
  for (std::size_t at = t.find("MSRP "); at != std::string_view::npos; at = t.find("MSRP ", at + 5)) {
    if (at > 0 && t[at - 1] != '\n') continue;
    const auto sp = t.find(' ', at + 5);
    const auto eol = t.find("\r\n", at);
    if (sp == std::string_view::npos || eol == std::string_view::npos || sp > eol) continue;
    out_.text_value(t.substr(at + 5, sp - at - 5), "msrp-tid");
    // Header lines up to an empty line or the end-line.
    for (std::size_t i = eol + 2; i < t.size();) {
      const auto e = t.find("\r\n", i);
      if (e == std::string_view::npos || e == i || t.substr(i, 7) == "-------") break;
      const auto line = t.substr(i, e - i);
      const auto colon = line.find(':');
      if (colon != std::string_view::npos) {
        std::string name(line.substr(0, colon));
        for (auto& ch : name) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        auto value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
        if (name == "message-id") {
          out_.text_value(value, "msrp-message-id");
        } else if (name == "to-path" || name == "from-path") {
          for (std::size_t p = 0; p < value.size();) {
            const auto q = std::min(value.find(' ', p), value.size());
            const auto uri = value.substr(p, q - p);
            out_.text_value(uri, "msrp-path");
            // The session id: after the authority's "/" up to ";" (RFC 4975 §6).
            const auto scheme = uri.find("://");
            const auto slash = scheme == std::string_view::npos ? scheme : uri.find('/', scheme + 3);
            if (slash != std::string_view::npos) {
              out_.text_value(uri.substr(slash + 1, uri.find(';', slash) - slash - 1), "msrp-session");
            }
            p = q + 1;
          }
        }
        // Other headers are either kept by the rules (Byte-Range, Status, Content-Type, ...) or
        // removed, in which case the anonymiser adds their values to the scan set itself.
      }
      i = e + 2;
    }
  }
}

// MCX APP (TS 24.380 §8.1.2, §8.1.3): every field value that is text is harvested (URIs and free
// text), and every 6-octet value is taken as an SSRC with spare bits (the SSRC fields of
// TS 24.380 §8.2.3.16 and TS 24.581 §9.2.3.16).
void MediaHarvest::app(std::span<const std::uint8_t> p) {
  if (p.size() < 12) return;
  for (std::size_t f = 12; f + 2 <= p.size();) {
    const std::size_t h = p[f] < 192 ? 2 : 3;
    if (f + h > p.size()) return;
    const std::size_t len = h == 2 ? p[f + 1] : ((std::size_t{p[f + 1]} << 8) | p[f + 2]);
    if (f + h + len > p.size()) return;
    const auto v = p.subspan(f + h, len);
    if (p[f] == 192) {
      // Feature 005: the MCPC PCK I_MESSAGE (TS 24.380 §8.3.3.10), binary or base64, read by the
      // MIKEY harvester; its text is not a raw value.
      const std::string_view t(reinterpret_cast<const char*>(v.data()), v.size());
      auto d = decode_base64(t);
      if (!(d && d->size() >= 2 && (*d)[0] == 1 && (*d)[1] == 26)) d = std::vector<std::uint8_t>(v.begin(), v.end());
      out_.mikey(*d);
      f += (h + len + 3) / 4 * 4;
      continue;
    }
    // A 6-octet value is an SSRC with spare bits, unless it is a Message Name: 4 upper-case or
    // digit characters (an APP name) and two zero octets (TS 24.581 §9.2.3.18).
    const bool name = len == 6 && v[4] == 0 && v[5] == 0 &&
                      std::all_of(v.begin(), v.begin() + 4, [](std::uint8_t c) {
                        return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                      });
    if (len == 6 && !name) out_.ssrc(be32(v.data()));
    out_.text_value(text(v), "app");
    f += (h + len + 3) / 4 * 4;
  }
}

}  // namespace mcxanon::scan::detail
