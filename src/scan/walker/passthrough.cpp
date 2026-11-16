// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/passthrough.hpp"

#include "scan/walker/mikey_carriers.hpp"

#include <string_view>

namespace mcxanon::scan::detail {

namespace {

constexpr std::string_view kXenc = "http://www.w3.org/2001/04/xmlenc#";

bool name_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
         c == '.' || c == ':';
}

// xenc:EncryptedData subtrees: a start tag "<EncryptedData" or "<prefix:EncryptedData" whose
// element declares or uses the xenc namespace, up to the matching end tag of the same name
// (nested EncryptedData counted). An unterminated subtree is not a range.
void encrypted_data(std::string_view t, std::vector<PassthroughRange>& out) {
  constexpr std::string_view kName = "EncryptedData";
  for (std::size_t p = t.find(kName); p != std::string_view::npos && out.size() < 256; p = t.find(kName, p + 1)) {
    std::size_t lt = p;
    while (lt > 0 && name_char(t[lt - 1])) --lt;
    if (lt == 0 || t[lt - 1] != '<') continue;
    --lt;
    const auto qname = t.substr(lt + 1, p + kName.size() - lt - 1);
    if (qname.size() != kName.size() && qname[qname.size() - kName.size() - 1] != ':') continue;
    if (p + kName.size() >= t.size() || name_char(t[p + kName.size()])) continue;
    const auto gt = t.find('>', p);
    if (gt == std::string_view::npos) continue;
    // The namespace: declared on the tag, or the subtree is under a declaration of the prefix;
    // the scanner accepts the name with the xenc namespace anywhere before the tag ends.
    if (t.substr(0, gt).rfind(kXenc) == std::string_view::npos) continue;
    std::size_t end = std::string_view::npos;
    if (t[gt - 1] == '/') {
      end = gt + 1;
    } else {
      const std::string open = "<" + std::string(qname);
      const std::string close = "</" + std::string(qname) + ">";
      int depth = 1;
      for (std::size_t i = gt + 1; i < t.size();) {
        const auto o = t.find(open, i);
        const auto c = t.find(close, i);
        if (c == std::string_view::npos) break;
        if (o != std::string_view::npos && o < c && o + open.size() < t.size() && !name_char(t[o + open.size()])) {
          ++depth;
          i = o + open.size();
          continue;
        }
        if (--depth == 0) {
          end = c + close.size();
          break;
        }
        i = c + close.size();
      }
    }
    if (end == std::string_view::npos) continue;
    out.push_back({lt, end - lt, "encrypted-xml"});
    p = end - 1;
  }
}

}  // namespace

std::vector<PassthroughRange> passthrough_ranges(std::span<const std::uint8_t> payload) {
  std::vector<PassthroughRange> out;
  for (const auto& c : find_mikey_carriers(payload)) out.push_back({c.offset, c.length, c.carrier});
  encrypted_data({reinterpret_cast<const char*>(payload.data()), payload.size()}, out);
  return out;
}

const PassthroughRange* covering(const std::vector<PassthroughRange>& ranges, std::uint64_t offset,
                                 std::uint64_t length) {
  for (const auto& r : ranges) {
    if (offset >= r.offset && offset + length <= r.offset + r.length) return &r;
  }
  return nullptr;
}

}  // namespace mcxanon::scan::detail
