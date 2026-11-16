// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/walker/mikey_harvest.hpp"

namespace mcxanon::scan::detail {

namespace {

constexpr std::size_t kMaxMessage = 65535;
constexpr std::size_t kMaxPayloads = 64;

int b64(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::uint32_t be32(std::span<const std::uint8_t> b, std::size_t at) {
  return (std::uint32_t{b[at]} << 24) | (std::uint32_t{b[at + 1]} << 16) | (std::uint32_t{b[at + 2]} << 8) | b[at + 3];
}

std::vector<std::uint8_t> sub(std::span<const std::uint8_t> b, std::size_t at, std::size_t n) {
  return {b.begin() + static_cast<std::ptrdiff_t>(at), b.begin() + static_cast<std::ptrdiff_t>(at + n)};
}

// The IV and DPPK-ID of a '3GPP key parameters' extension (TS 33.180 Table 8.5.4.1-1), from the
// layout whose DPPK-ID equals the CSB ID (with or without the optional Signalling algorithm octet).
void key_parameters(std::span<const std::uint8_t> d, std::uint32_t csb, MikeyValues& out) {
  for (std::size_t sig : {std::size_t{0}, std::size_t{1}}) {
    const std::size_t iv = 12 + sig;
    const std::size_t dppk = iv + 16;
    if (d.size() < dppk + 4) continue;
    if (be32(d, dppk) != csb) continue;
    out.bytes.push_back(sub(d, iv, 16));
    out.keys.push_back(sub(d, dppk, 4));
    return;
  }
}

}  // namespace

std::optional<std::vector<std::uint8_t>> decode_base64(std::string_view text) {
  std::vector<std::uint8_t> out;
  std::uint32_t acc = 0;
  int bits = 0;
  std::size_t pad = 0;
  for (char c : text) {
    if (c == '\r' || c == '\n') continue;
    if (c == '=') {
      ++pad;
      continue;
    }
    if (pad != 0) return std::nullopt;
    const int v = b64(c);
    if (v < 0) return std::nullopt;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>(acc >> bits));
      acc &= (1u << bits) - 1;
    }
    if (out.size() > kMaxMessage) return std::nullopt;
  }
  if (pad > 2) return std::nullopt;
  return out;
}

std::optional<std::vector<std::uint8_t>> decode_hex(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' || text.front() == '\n')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n')) {
    text.remove_suffix(1);
  }
  if (text.empty() || text.size() % 2 != 0 || text.size() > 2 * kMaxMessage) return std::nullopt;
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int hi = hexv(text[i]);
    const int lo = hexv(text[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

MikeyValues walk_mikey(std::span<const std::uint8_t> m) {
  MikeyValues out;
  if (m.size() < 10 || m.size() > kMaxMessage || m[0] != 1 || m[1] != 26) return out;
  const std::uint32_t csb = be32(m, 4);
  out.keys.push_back(sub(m, 4, 4));
  std::size_t i = 10;
  const unsigned cs = m[8];
  if (cs > 0 && m[9] == 2) {
    for (unsigned k = 0; k < cs; ++k) {
      if (m.size() - i < 3) return out;
      const unsigned np = m[i + 2] & 0x7F;
      i += 3;
      if (m.size() - i < np + 2) return out;
      i += np;
      const std::size_t sl = (std::size_t{m[i]} << 8) | m[i + 1];
      i += 2;
      if (m.size() - i < sl + 1) return out;
      i += sl;
      const std::size_t spl = m[i];
      ++i;
      if (m.size() - i < spl) return out;
      if (spl == 4 || spl == 8) {
        for (std::size_t w = 0; w < spl; w += 4) out.keys.push_back(sub(m, i + w, 4));
      }
      i += spl;
    }
  } else if (cs > 0) {
    return out;
  }
  unsigned next = m[2];
  for (std::size_t n = 0; n < kMaxPayloads && next != 0; ++n) {
    if (next == 4) {  // SIGN: the last payload
      if (m.size() - i < 2) return out;
      const std::size_t len = ((std::size_t{m[i]} << 8) | m[i + 1]) & 0x0FFF;
      i += 2;
      if (m.size() - i < len) return out;
      if (len >= 4) out.bytes.push_back(sub(m, i, len));
      return out;
    }
    if (m.size() - i < 1) return out;
    const unsigned following = m[i];
    ++i;
    switch (next) {
      case 5: {  // T
        if (m.size() - i < 1) return out;
        const std::size_t len = m[i] == 2 ? 4 : 8;
        i += 1;
        if (m.size() - i < len) return out;
        i += len;
        break;
      }
      case 11: {  // RAND
        if (m.size() - i < 1) return out;
        const std::size_t len = m[i];
        i += 1;
        if (m.size() - i < len) return out;
        if (len >= 4) out.bytes.push_back(sub(m, i, len));
        i += len;
        break;
      }
      case 14: {  // IDR
        if (m.size() - i < 4) return out;
        const unsigned role = m[i];
        const unsigned type = m[i + 1];
        const std::size_t len = (std::size_t{m[i + 2]} << 8) | m[i + 3];
        i += 4;
        if (m.size() - i < len) return out;
        const auto data = m.subspan(i, len);
        const std::string text(data.begin(), data.end());
        const bool hidden = role == 8 || role == 9 || role == 240 || role == 241;
        if (hidden && type == 2) {
          if (len >= 4) out.bytes.push_back(sub(m, i, len));
        } else if (hidden && len == 44) {
          if (auto d = decode_base64(text); d && d->size() == 32) {
            out.bytes.push_back(*d);
          } else {
            out.uris.push_back(text);
          }
        } else if (type == 0 || type == 1) {
          out.uris.push_back(text);
        } else if (len >= 4) {
          out.bytes.push_back(sub(m, i, len));
        }
        i += len;
        break;
      }
      case 10: {  // SP
        if (m.size() - i < 4) return out;
        const std::size_t len = (std::size_t{m[i + 2]} << 8) | m[i + 3];
        i += 4;
        if (m.size() - i < len) return out;
        i += len;
        break;
      }
      case 26: {  // SAKKE: kept ciphertext, nothing to harvest
        if (m.size() - i < 4) return out;
        const std::size_t len = (std::size_t{m[i + 2]} << 8) | m[i + 3];
        i += 4;
        if (m.size() - i < len) return out;
        i += len;
        break;
      }
      case 21: {  // General extension
        if (m.size() - i < 3) return out;
        const unsigned type = m[i];
        const std::size_t len = (std::size_t{m[i + 1]} << 8) | m[i + 2];
        i += 3;
        if (m.size() - i < len) return out;
        if (type == 7) key_parameters(m.subspan(i, len), csb, out);
        i += len;
        break;
      }
      default:
        return out;
    }
    next = following;
  }
  return out;
}

}  // namespace mcxanon::scan::detail
