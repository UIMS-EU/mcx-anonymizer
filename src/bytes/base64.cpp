// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/base64.hpp"

#include <array>
#include <vector>

namespace mcxanon::base64 {

namespace {

constexpr std::string_view kStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::string_view kUrl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int value(char c, Alphabet a) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (a == Alphabet::standard) {
    if (c == '+') return 62;
    if (c == '/') return 63;
  } else {
    if (c == '-') return 62;
    if (c == '_') return 63;
  }
  return -1;
}

}  // namespace

bool alphabet_only(std::string_view text, Alphabet a) {
  for (char c : text) {
    if (value(c, a) < 0 && c != '=' && c != '\r' && c != '\n') return false;
  }
  return true;
}

std::optional<Decoded> decode(std::string_view text, Alphabet a) {
  Decoded out;
  // Split into lines; a line break is CRLF or LF, the same throughout.
  std::vector<std::string_view> lines;
  std::optional<bool> crlf;
  std::size_t start = 0;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] != '\n' && text[i] != '\r') continue;
    bool this_crlf = false;
    if (text[i] == '\r') {
      if (i + 1 >= text.size() || text[i + 1] != '\n') return std::nullopt;
      this_crlf = true;
    }
    if (crlf && *crlf != this_crlf) return std::nullopt;
    crlf = this_crlf;
    lines.push_back(text.substr(start, i - start));
    i += this_crlf ? 1 : 0;
    start = i + 1;
  }
  out.layout.final_break = !lines.empty() && start == text.size();
  if (start < text.size() || lines.empty()) lines.push_back(text.substr(start));
  out.layout.crlf = crlf.value_or(true);
  if (lines.size() > 1 || out.layout.final_break) {
    out.layout.line = lines.front().size();
    if (out.layout.line == 0) return std::nullopt;
    for (std::size_t i = 0; i + 1 < lines.size(); ++i) {
      if (lines[i].size() != out.layout.line) return std::nullopt;
    }
    if (lines.back().empty() || lines.back().size() > out.layout.line) return std::nullopt;
  }
  std::string joined;
  for (const auto& l : lines) joined += l;
  // Padding.
  std::size_t pad = 0;
  while (pad < joined.size() && pad < 2 && joined[joined.size() - 1 - pad] == '=') ++pad;
  const std::string_view body(joined.data(), joined.size() - pad);
  if (body.find('=') != std::string_view::npos) return std::nullopt;
  if (pad > 0) {
    if (joined.size() % 4 != 0) return std::nullopt;
    out.layout.padded = true;
  } else {
    const std::size_t r = body.size() % 4;
    if (r == 1) return std::nullopt;
    if (r != 0 && a == Alphabet::standard) return std::nullopt;  // the standard alphabet needs padding
    out.layout.padded = (r == 0);
  }
  if (pad > 0 && (body.size() % 4) != 4 - pad) return std::nullopt;
  std::uint32_t acc = 0;
  int bits = 0;
  for (char c : body) {
    const int v = value(c, a);
    if (v < 0) return std::nullopt;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.bytes.push_back(static_cast<std::uint8_t>(acc >> bits));
      acc &= (1u << bits) - 1;
    }
  }
  if (acc != 0) return std::nullopt;  // non-zero pad bits (RFC 4648 §3.5)
  return out;
}

std::string encode(ByteView b, const Layout& layout, Alphabet a) {
  const std::string_view alpha = a == Alphabet::standard ? kStd : kUrl;
  std::string s;
  s.reserve((b.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 3 <= b.size(); i += 3) {
    const std::uint32_t v = (static_cast<std::uint32_t>(b[i]) << 16) | (static_cast<std::uint32_t>(b[i + 1]) << 8) | b[i + 2];
    for (int k = 18; k >= 0; k -= 6) s += alpha[(v >> k) & 63];
  }
  const std::size_t rest = b.size() - i;
  if (rest > 0) {
    std::uint32_t v = static_cast<std::uint32_t>(b[i]) << 16;
    if (rest == 2) v |= static_cast<std::uint32_t>(b[i + 1]) << 8;
    s += alpha[(v >> 18) & 63];
    s += alpha[(v >> 12) & 63];
    if (rest == 2) s += alpha[(v >> 6) & 63];
    if (layout.padded) s.append(rest == 1 ? 2 : 1, '=');
  }
  if (layout.line == 0) return s;
  const std::string brk = layout.crlf ? "\r\n" : "\n";
  std::string out;
  for (std::size_t p = 0; p < s.size(); p += layout.line) {
    if (p > 0) out += brk;
    out += s.substr(p, layout.line);
  }
  if (layout.final_break) out += brk;
  return out;
}

}  // namespace mcxanon::base64
