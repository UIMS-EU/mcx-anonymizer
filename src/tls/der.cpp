// SPDX-License-Identifier: GPL-3.0-or-later
#include "tls/der.hpp"

#include "tls/limits.hpp"

namespace mcxanon::tls::der {

namespace {

struct Reader {
  std::string_view b;
  std::size_t nodes = 0;

  // One element at `p`; on success `p` is past it.
  std::optional<Node> element(std::size_t& p, std::size_t depth) {
    if (depth > kMaxDerDepth || ++nodes > kMaxDerNodes || p + 2 > b.size()) return std::nullopt;
    Node n;
    n.tag = static_cast<std::uint8_t>(b[p++]);
    if ((n.tag & 0x1F) == 0x1F) return std::nullopt;  // high tag numbers are not used by X.509
    std::size_t len = static_cast<unsigned char>(b[p++]);
    if (len & 0x80) {
      const std::size_t k = len & 0x7F;
      if (k == 0 || k > 3 || p + k > b.size()) return std::nullopt;  // indefinite or too long
      len = 0;
      for (std::size_t i = 0; i < k; ++i) len = (len << 8) | static_cast<unsigned char>(b[p++]);
      if (len < 0x80 || (k > 1 && len < (std::size_t{1} << (8 * (k - 1))))) return std::nullopt;  // not minimal
    }
    if (p + len > b.size()) return std::nullopt;
    if (n.constructed()) {
      const std::size_t end = p + len;
      while (p < end) {
        auto c = element(p, depth + 1);
        if (!c || p > end) return std::nullopt;
        n.children.push_back(std::move(*c));
      }
    } else {
      n.content.assign(b.substr(p, len));
      p += len;
    }
    return n;
  }
};

void put_length(std::string& out, std::size_t len) {
  if (len < 0x80) {
    out.push_back(static_cast<char>(len));
    return;
  }
  std::string l;
  while (len > 0) {
    l.insert(l.begin(), static_cast<char>(len & 0xFF));
    len >>= 8;
  }
  out.push_back(static_cast<char>(0x80 | l.size()));
  out += l;
}

}  // namespace

std::optional<Node> parse(std::string_view b, bool exact) {
  Reader r{b};
  std::size_t p = 0;
  auto n = r.element(p, 0);
  if (!n || (exact && p != b.size())) return std::nullopt;
  return n;
}

std::string write(const Node& n) {
  std::string body;
  if (n.constructed()) {
    for (const auto& c : n.children) body += write(c);
  } else {
    body = n.content;
  }
  std::string out(1, static_cast<char>(n.tag));
  put_length(out, body.size());
  return out + body;
}

std::string oid_text(std::string_view c) {
  if (c.empty()) return {};
  std::string out;
  std::uint64_t v = 0;
  bool first = true;
  for (std::size_t i = 0; i < c.size(); ++i) {
    const auto x = static_cast<unsigned char>(c[i]);
    if (v == 0 && x == 0x80) return {};  // non-minimal subidentifier
    v = (v << 7) | (x & 0x7Fu);
    if (v > (std::uint64_t{1} << 56)) return {};
    if (x & 0x80) {
      if (i + 1 == c.size()) return {};
      continue;
    }
    if (first) {
      const std::uint64_t a = v < 40 ? 0 : v < 80 ? 1 : 2;
      out = std::to_string(a) + "." + std::to_string(v - 40 * a);
      first = false;
    } else {
      out += "." + std::to_string(v);
    }
    v = 0;
  }
  return out;
}

bool is_string_type(std::uint8_t tag) {
  switch (tag) {
    case kUtf8:
    case kPrintable:
    case kT61:
    case kIa5:
    case kVisible:
    case kUniversal:
    case kBmp: return true;
    default: return false;
  }
}

}  // namespace mcxanon::tls::der
