// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/web_carriers.hpp"

#include "scan/walker/hpack_strings.hpp"
#include "scan/walker/web_harvest.hpp"

#include <cctype>
#include <string_view>

namespace mcxanon::scan::detail {

namespace {

bool b64url_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_'; }

void jwts(std::string_view t, std::vector<WebCarrierSpan>& out) {
  for (std::size_t q = t.find("eyJ"); q != std::string_view::npos; q = t.find("eyJ", q + 3)) {
    std::size_t r = q;
    std::size_t seg = q;
    for (int k = 0; k < 2; ++k) {
      while (r < t.size() && b64url_char(t[r])) ++r;
      if (auto d = b64url_decode(t.substr(seg, r - seg)); d && r > seg) {
        out.push_back({seg, r - seg, "jwt", std::vector<std::uint8_t>(d->begin(), d->end())});
      }
      if (r >= t.size() || t[r] != '.') break;
      seg = ++r;
    }
  }
}

// h2 frames from the payload start or after a connection preface: Huffman literals of HEADERS
// and CONTINUATION payloads (the h2 frame layout of RFC 9113 §4.1).
void hpack(std::string_view t, std::vector<WebCarrierSpan>& out) {
  std::size_t p = 0;
  if (const auto pre = t.find("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); pre != std::string_view::npos) p = pre + 24;
  while (p + 9 <= t.size()) {
    const auto u = [&](std::size_t i) { return static_cast<std::size_t>(static_cast<unsigned char>(t[i])); };
    const std::size_t len = (u(p) << 16) | (u(p + 1) << 8) | u(p + 2);
    const auto type = u(p + 3);
    if (p + 9 + len > t.size() || type > 9) return;
    if (type == 1 || type == 9 || type == 5) {
      for (const auto& l : hpack_literals(t.substr(p + 9, len))) {
        if (l.huffman) out.push_back({p, 9 + len, "hpack", std::vector<std::uint8_t>(l.value.begin(), l.value.end())});
      }
    }
    p += 9 + len;
  }
}

}  // namespace

std::vector<WebCarrierSpan> find_web_carriers(std::span<const std::uint8_t> payload) {
  std::vector<WebCarrierSpan> out;
  const std::string_view t(reinterpret_cast<const char*>(payload.data()), payload.size());
  jwts(t, out);
  hpack(t, out);
  return out;
}

}  // namespace mcxanon::scan::detail
