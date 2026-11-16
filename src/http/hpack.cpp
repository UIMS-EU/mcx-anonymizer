// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/hpack.hpp"

#include "http/hpack_tables.hpp"
#include "http/limits.hpp"

#include <array>
#include <cstdint>
#include <unordered_map>

namespace mcxanon::http {

namespace {

// RFC 7541 §5.1: an integer with an N-bit prefix; values over 2^28 are refused (bound).
std::optional<std::uint64_t> integer(std::string_view b, std::size_t& p, unsigned prefix) {
  if (p >= b.size()) return std::nullopt;
  const std::uint64_t max = (1u << prefix) - 1;
  std::uint64_t v = static_cast<unsigned char>(b[p++]) & max;
  if (v < max) return v;
  unsigned m = 0;
  for (;;) {
    if (p >= b.size() || m > 28) return std::nullopt;
    const auto c = static_cast<unsigned char>(b[p++]);
    v += static_cast<std::uint64_t>(c & 0x7F) << m;
    m += 7;
    if ((c & 0x80) == 0) break;
  }
  if (v > (1u << 28)) return std::nullopt;
  return v;
}

std::optional<std::string> string_literal(std::string_view b, std::size_t& p) {
  if (p >= b.size()) return std::nullopt;
  const bool huffman = (static_cast<unsigned char>(b[p]) & 0x80) != 0;
  const auto len = integer(b, p, 7);
  if (!len || *len > kMaxHpackString || p + *len > b.size()) return std::nullopt;
  const auto raw = b.substr(p, static_cast<std::size_t>(*len));
  p += static_cast<std::size_t>(*len);
  if (huffman) return huffman_decode(raw);
  return std::string(raw);
}

void put_integer(std::string& out, std::uint64_t v, unsigned prefix, std::uint8_t first) {
  const std::uint64_t max = (1u << prefix) - 1;
  if (v < max) {
    out.push_back(static_cast<char>(first | v));
    return;
  }
  out.push_back(static_cast<char>(first | max));
  v -= max;
  while (v >= 128) {
    out.push_back(static_cast<char>((v & 0x7F) | 0x80));
    v >>= 7;
  }
  out.push_back(static_cast<char>(v));
}

void put_string(std::string& out, std::string_view s) {
  put_integer(out, s.size(), 7, 0x00);
  out.append(s);
}

const std::unordered_map<std::uint64_t, int>& decode_table() {
  static const auto table = [] {
    std::unordered_map<std::uint64_t, int> t;
    for (int i = 0; i < 257; ++i) {
      t.emplace((static_cast<std::uint64_t>(kHuffman[i].bits) << 32) | kHuffman[i].code, i);
    }
    return t;
  }();
  return table;
}

}  // namespace

std::optional<std::string> huffman_decode(std::string_view s) {
  const auto& t = decode_table();
  std::string out;
  std::uint64_t code = 0;
  unsigned bits = 0;
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    for (int i = 7; i >= 0; --i) {
      code = (code << 1) | ((c >> i) & 1u);
      ++bits;
      if (bits > 30) return std::nullopt;
      if (bits < 5) continue;
      const auto it = t.find((static_cast<std::uint64_t>(bits) << 32) | code);
      if (it == t.end()) continue;
      if (it->second == 256) return std::nullopt;  // EOS in the string (§5.2)
      out.push_back(static_cast<char>(it->second));
      code = 0;
      bits = 0;
    }
  }
  // Padding: fewer than 8 bits, all ones (the most significant bits of EOS).
  if (bits > 7 || code != (std::uint64_t{1} << bits) - 1) return std::nullopt;
  return out;
}

std::string huffman_encode(std::string_view s) {
  std::string out;
  std::uint64_t acc = 0;
  unsigned bits = 0;
  for (const char ch : s) {
    const auto& h = kHuffman[static_cast<unsigned char>(ch)];
    acc = (acc << h.bits) | h.code;
    bits += h.bits;
    while (bits >= 8) {
      out.push_back(static_cast<char>((acc >> (bits - 8)) & 0xFF));
      bits -= 8;
    }
  }
  if (bits > 0) out.push_back(static_cast<char>(((acc << (8 - bits)) | ((1u << (8 - bits)) - 1)) & 0xFF));
  return out;
}

std::optional<std::pair<std::string, std::string>> HpackDecoder::entry(std::size_t index) const {
  if (index == 0) return std::nullopt;
  if (index <= 61) return std::make_pair(std::string(kStaticTable[index - 1].name), std::string(kStaticTable[index - 1].value));
  const std::size_t d = index - 62;
  if (d >= table_.size()) return std::nullopt;
  return table_[d];
}

bool HpackDecoder::add(std::string name, std::string value) {
  const std::size_t sz = name.size() + value.size() + 32;  // §4.1
  while (!table_.empty() && size_ + sz > max_) {
    size_ -= table_.back().first.size() + table_.back().second.size() + 32;
    table_.pop_back();
  }
  if (sz <= max_) {
    table_.emplace_front(std::move(name), std::move(value));
    size_ += sz;
  }
  return true;
}

std::optional<std::vector<HeaderField>> HpackDecoder::decode(std::string_view b) {
  std::vector<HeaderField> out;
  std::size_t total = 0;
  std::size_t p = 0;
  bool fields_seen = false;
  while (p < b.size()) {
    const auto c = static_cast<unsigned char>(b[p]);
    if ((c & 0x80) != 0) {  // §6.1 indexed
      const auto i = integer(b, p, 7);
      if (!i) return std::nullopt;
      auto e = entry(static_cast<std::size_t>(*i));
      if (!e) return std::nullopt;
      out.push_back({std::move(e->first), std::move(e->second)});
    } else if ((c & 0xE0) == 0x20) {  // §6.3 dynamic table size update
      if (fields_seen) return std::nullopt;
      const auto n = integer(b, p, 5);
      if (!n || *n > kMaxTable) return std::nullopt;
      max_ = static_cast<std::size_t>(*n);
      while (!table_.empty() && size_ > max_) {
        size_ -= table_.back().first.size() + table_.back().second.size() + 32;
        table_.pop_back();
      }
      continue;
    } else {
      // §6.2.1 incremental indexing (01), §6.2.2 without indexing (0000), §6.2.3 never indexed (0001).
      const bool incremental = (c & 0xC0) == 0x40;
      const auto idx = integer(b, p, incremental ? 6 : 4);
      if (!idx) return std::nullopt;
      std::string name;
      if (*idx == 0) {
        auto n = string_literal(b, p);
        if (!n) return std::nullopt;
        name = std::move(*n);
      } else {
        auto e = entry(static_cast<std::size_t>(*idx));
        if (!e) return std::nullopt;
        name = std::move(e->first);
      }
      auto v = string_literal(b, p);
      if (!v) return std::nullopt;
      if (incremental) add(name, *v);
      out.push_back({std::move(name), std::move(*v)});
    }
    fields_seen = true;
    total += out.back().name.size() + out.back().value.size() + 32;
    if (total > kMaxHeaderList || out.size() > kMaxFields) return std::nullopt;
  }
  return out;
}

std::string hpack_encode(const std::vector<HeaderField>& fields) {
  std::string out;
  for (const auto& f : fields) {
    std::size_t idx = 0;
    for (std::size_t i = 0; i < 61; ++i) {
      if (kStaticTable[i].name == f.name) {
        idx = i + 1;
        break;
      }
    }
    put_integer(out, idx, 4, 0x00);  // literal without indexing (§6.2.2)
    if (idx == 0) put_string(out, f.name);
    put_string(out, f.value);
  }
  return out;
}

}  // namespace mcxanon::http
