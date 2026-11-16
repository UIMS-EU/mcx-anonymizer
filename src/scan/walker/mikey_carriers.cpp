// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/mikey_carriers.hpp"

#include "scan/walker/mikey_harvest.hpp"

#include <string_view>

namespace mcxanon::scan::detail {

namespace {

bool b64char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

// Case-insensitive find of a lowercase needle.
std::size_t ifind(std::string_view h, std::string_view n, std::size_t from) {
  for (std::size_t i = from; i + n.size() <= h.size(); ++i) {
    std::size_t k = 0;
    while (k < n.size() && lower(h[i + k]) == n[k]) ++k;
    if (k == n.size()) return i;
  }
  return std::string_view::npos;
}

bool mikey_start(const std::vector<std::uint8_t>& b) { return b.size() >= 10 && b[0] == 1 && b[1] == 26; }

// application/mikey bodies and parts (RFC 3830 §10.1): after a Content-Type header line naming the
// type, the body starts after the blank line and ends at the next multipart delimiter or at the end
// of the payload. Base64 (with line breaks) when it decodes to a data-type-26 message, else binary.
void bodies(std::string_view text, std::vector<MikeyCarrierSpan>& out) {
  for (std::size_t p = ifind(text, "application/mikey", 0); p != std::string_view::npos && out.size() < 64;
       p = ifind(text, "application/mikey", p + 1)) {
    const auto line = text.rfind('\n', p);
    const auto head = text.substr(line == std::string_view::npos ? 0 : line + 1, p - (line == std::string_view::npos ? 0 : line + 1));
    if (ifind(head, "content-type:", 0) != 0 && ifind(head, "c:", 0) != 0) continue;
    const auto blank = text.find("\r\n\r\n", p);
    if (blank == std::string_view::npos) continue;
    const std::size_t start = blank + 4;
    std::size_t end = text.find("\r\n--", start);
    if (end == std::string_view::npos) end = text.size();
    if (end <= start) continue;
    const auto body = text.substr(start, end - start);
    bool b64 = true;
    for (char c : body) {
      if (!b64char(c) && c != '\r' && c != '\n') {
        b64 = false;
        break;
      }
    }
    if (b64) {
      if (auto d = decode_base64(body); d && mikey_start(*d)) {
        out.push_back({start, end - start, "body", std::move(*d)});
        continue;
      }
    }
    std::vector<std::uint8_t> raw(body.begin(), body.end());
    if (mikey_start(raw)) out.push_back({start, end - start, "body", std::move(raw)});
  }
}

// <GKTP> elements (TS 24.481 §7.7.4.2): the hexBinary text of "<GKTP" or "<prefix:GKTP" start tags.
void gktps(std::string_view text, std::vector<MikeyCarrierSpan>& out) {
  for (std::size_t p = text.find("GKTP"); p != std::string_view::npos && out.size() < 64; p = text.find("GKTP", p + 1)) {
    if (p == 0 || p + 4 >= text.size()) continue;
    const char after = text[p + 4];
    if (after != '>' && after != ' ' && after != '\t' && after != '\r' && after != '\n') continue;
    std::size_t lt = p - 1;
    if (text[lt] != '<') {
      if (text[lt] != ':') continue;
      while (lt > 0 && text[lt] != '<' && text[lt] != '>' && text[lt] != ' ') --lt;
      if (text[lt] != '<') continue;
    }
    const auto gt = text.find('>', p);
    if (gt == std::string_view::npos || text[gt - 1] == '/') continue;
    const auto close = text.find('<', gt + 1);
    if (close == std::string_view::npos) continue;
    if (auto d = decode_hex(text.substr(gt + 1, close - gt - 1)); d && !d->empty()) {
      out.push_back({gt + 1, close - gt - 1, "gktp", std::move(*d)});
    }
  }
}

// MCPC field 192 (TS 24.380 §8.3.3.10) of the RTCP APP packets of a compound packet: binary, or
// base64 when it decodes to a data-type-26 message.
void mcpc(std::span<const std::uint8_t> p, std::vector<MikeyCarrierSpan>& out) {
  for (std::size_t i = 0; i + 12 <= p.size() && (p[i] >> 6) == 2 && out.size() < 64;) {
    const std::size_t len = ((std::size_t{p[i + 2]} << 8 | p[i + 3]) + 1) * 4;
    if (i + len > p.size()) return;
    if (p[i + 1] == 204 && p[i + 8] == 'M' && p[i + 9] == 'C' && p[i + 10] == 'P' && p[i + 11] == 'C') {
      for (std::size_t f = i + 12; f + 3 <= i + len;) {
        const std::size_t h = p[f] < 192 ? 2 : 3;
        const std::size_t fl = h == 2 ? p[f + 1] : (std::size_t{p[f + 1]} << 8 | p[f + 2]);
        if (f + h + fl > i + len) break;
        if (p[f] == 192) {
          const std::string_view t(reinterpret_cast<const char*>(p.data() + f + h), fl);
          auto d = decode_base64(t);
          if (!(d && mikey_start(*d))) d = std::vector<std::uint8_t>(t.begin(), t.end());
          if (mikey_start(*d)) out.push_back({f + h, fl, "mcpc", std::move(*d)});
        }
        f += (h + fl + 3) / 4 * 4;
      }
    }
    i += len;
  }
}

}  // namespace

std::vector<MikeyCarrierSpan> find_mikey_carriers(std::span<const std::uint8_t> payload) {
  std::vector<MikeyCarrierSpan> out;
  const std::string_view text(reinterpret_cast<const char*>(payload.data()), payload.size());
  // SDP a=key-mgmt (RFC 4567 §3.1): "a=key-mgmt:" 0*1SP "mikey" SP base64.
  constexpr std::string_view kAttr = "a=key-mgmt:";
  for (std::size_t p = text.find(kAttr); p != std::string_view::npos && out.size() < 64;
       p = text.find(kAttr, p + 1)) {
    std::size_t i = p + kAttr.size();
    if (i < text.size() && text[i] == ' ') ++i;
    if (text.substr(i, 6) != "mikey ") continue;
    i += 6;
    std::size_t e = i;
    while (e < text.size() && b64char(text[e])) ++e;
    if (e - i < 16) continue;
    if (auto d = decode_base64(text.substr(i, e - i)); d && !d->empty()) {
      out.push_back({i, e - i, "sdp", std::move(*d)});
    }
  }
  bodies(text, out);
  gktps(text, out);
  mcpc(payload, out);
  return out;
}

}  // namespace mcxanon::scan::detail
