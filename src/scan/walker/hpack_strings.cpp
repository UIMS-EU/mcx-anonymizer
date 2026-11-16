// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/hpack_strings.hpp"

#include <map>

namespace mcxanon::scan::detail {

namespace {

std::optional<std::uint64_t> varint(std::string_view b, std::size_t& p, unsigned prefix) {
  if (p >= b.size()) return std::nullopt;
  const std::uint64_t mask = (1u << prefix) - 1;
  std::uint64_t v = static_cast<unsigned char>(b[p++]) & mask;
  if (v < mask) return v;
  for (unsigned shift = 0; shift <= 28; shift += 7) {
    if (p >= b.size()) return std::nullopt;
    const auto c = static_cast<unsigned char>(b[p++]);
    v += static_cast<std::uint64_t>(c & 0x7F) << shift;
    if ((c & 0x80) == 0) return v;
  }
  return std::nullopt;
}

std::optional<std::pair<std::string, bool>> str(std::string_view b, std::size_t& p) {
  if (p >= b.size()) return std::nullopt;
  const bool h = (static_cast<unsigned char>(b[p]) & 0x80) != 0;
  const auto n = varint(b, p, 7);
  if (!n || *n > 65536 || p + *n > b.size()) return std::nullopt;
  const auto raw = b.substr(p, static_cast<std::size_t>(*n));
  p += static_cast<std::size_t>(*n);
  if (!h) return std::make_pair(std::string(raw), false);
  auto d = hpack_huffman(raw);
  if (!d) return std::nullopt;
  return std::make_pair(std::move(*d), true);
}

}  // namespace

std::optional<std::string> hpack_huffman(std::string_view s) {
  static const auto codes = [] {
    std::map<std::pair<unsigned, std::uint32_t>, int> m;
    for (int i = 0; i < 257; ++i) m.emplace(std::make_pair(unsigned{kHuffman[i].bits}, kHuffman[i].code), i);
    return m;
  }();
  std::string out;
  std::uint32_t code = 0;
  unsigned bits = 0;
  for (const char ch : s) {
    for (int i = 7; i >= 0; --i) {
      code = (code << 1) | ((static_cast<unsigned char>(ch) >> i) & 1u);
      if (++bits > 30) return std::nullopt;
      const auto it = codes.find({bits, code});
      if (it == codes.end()) continue;
      if (it->second == 256) return std::nullopt;
      out.push_back(static_cast<char>(it->second));
      code = 0;
      bits = 0;
    }
  }
  return out;  // padding is not checked: the scanner reads whatever decodes
}

std::vector<HpackLiteral> hpack_literals(std::string_view b) {
  std::vector<HpackLiteral> out;
  std::size_t p = 0;
  while (p < b.size()) {
    const auto c = static_cast<unsigned char>(b[p]);
    if ((c & 0x80) != 0) {  // indexed: no literal
      if (!varint(b, p, 7)) break;
      continue;
    }
    if ((c & 0xE0) == 0x20) {  // table size update
      if (!varint(b, p, 5)) break;
      continue;
    }
    const auto idx = varint(b, p, (c & 0xC0) == 0x40 ? 6 : 4);
    if (!idx) break;
    HpackLiteral l;
    if (*idx == 0) {
      auto n = str(b, p);
      if (!n) break;
      l.name = std::move(n->first);
    } else if (*idx <= 61) {
      l.name = std::string(kStaticTable[*idx - 1].name);
    }
    auto v = str(b, p);
    if (!v) break;
    l.value = std::move(v->first);
    l.huffman = v->second;
    out.push_back(std::move(l));
  }
  return out;
}

}  // namespace mcxanon::scan::detail
