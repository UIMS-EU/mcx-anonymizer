// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/patterns.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace mcxanon::scan::detail {
namespace {

using B = std::vector<std::uint8_t>;

B bytes_of(const std::string& s) {
  B o;
  o.reserve(s.size());
  for (const char c : s) o.push_back(static_cast<std::uint8_t>(c));
  return o;
}

std::string hex(const B& v, bool upper) {
  const char* d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string o;
  for (auto x : v) {
    o.push_back(d[x >> 4]);
    o.push_back(d[x & 15]);
  }
  return o;
}

std::string base64(const B& v) {
  static constexpr char kAlpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string o;
  std::size_t i = 0;
  for (; i + 2 < v.size(); i += 3) {
    const std::uint32_t n = (static_cast<std::uint32_t>(v[i]) << 16) | (static_cast<std::uint32_t>(v[i + 1]) << 8) | v[i + 2];
    for (int s = 18; s >= 0; s -= 6) o.push_back(kAlpha[(n >> s) & 63]);
  }
  if (i < v.size()) {
    std::uint32_t n = static_cast<std::uint32_t>(v[i]) << 16;
    if (i + 1 < v.size()) n |= static_cast<std::uint32_t>(v[i + 1]) << 8;
    o.push_back(kAlpha[(n >> 18) & 63]);
    o.push_back(kAlpha[(n >> 12) & 63]);
    o.push_back(i + 1 < v.size() ? kAlpha[(n >> 6) & 63] : '=');
    o.push_back('=');
  }
  return o;
}

B utf16(const std::string& s, bool le) {
  B o;
  for (const char ch : s) {
    const auto c = static_cast<std::uint8_t>(ch);
    if (le) {
      o.push_back(c);
      o.push_back(0);
    } else {
      o.push_back(0);
      o.push_back(c);
    }
  }
  return o;
}

std::string url(const std::string& s) {
  std::string o;
  const char* d = "0123456789ABCDEF";
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      o.push_back(static_cast<char>(c));
    } else {
      o.push_back('%');
      o.push_back(d[c >> 4]);
      o.push_back(d[c & 15]);
    }
  }
  return o;
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}
std::string upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

class Builder {
 public:
  Builder(std::uint32_t token, std::vector<Pattern>& out) : token_(token), out_(out) {}
  void add(B b, const std::string& enc, bool fold = false, bool short_bin = false, bool digits = false) {
    if (b.size() < kMinPattern) return;
    for (const auto& p : out_) {
      if (p.token == token_ && p.bytes == b && p.fold == fold) return;  // duplicate form
    }
    out_.push_back(Pattern{std::move(b), enc, fold, short_bin, token_, digits});
  }
  // Binary value: itself, hex (both cases) and base64 at the three alignments.
  void binary(const B& v, const std::string& enc, bool raw = true) {
    if (raw) add(v, enc, false, v.size() < 6);
    add(bytes_of(hex(v, false)), "hex");
    add(bytes_of(hex(v, true)), "hex-upper");
    for (std::size_t shift = 0; shift < 3; ++shift) {
      B padded(shift, 0);
      padded.insert(padded.end(), v.begin(), v.end());
      const std::string enc64 = base64(padded);
      // Characters influenced by the alignment bytes or by the end are not stable.
      const std::size_t lead = (shift * 8 + 5) / 6;
      const std::size_t stable_end = ((shift + v.size()) * 8) / 6;
      if (stable_end > lead + kMinPattern) {
        add(bytes_of(enc64.substr(lead, stable_end - lead)), "base64");
      }
    }
  }
  // Text form: case-insensitive, plus UTF-16 and URL encoding.
  void text(const std::string& t, const std::string& enc) {
    add(bytes_of(lower(t)), enc, true);
    add(utf16(lower(t), true), "utf16le", true);
    add(utf16(lower(t), false), "utf16be", true);
    const std::string u = url(t);
    if (u != t) add(bytes_of(lower(u)), "url", true);
  }
  // SIP escaping may encode any character (RFC 3261 §25.1 "escaped"): every byte as %xx,
  // matched case-insensitively.
  void escaped(const std::string& t) {
    std::string e;
    const char* d = "0123456789abcdef";
    for (const char ch : lower(t)) {
      const auto c = static_cast<unsigned char>(ch);
      e += '%';
      e += d[c >> 4];
      e += d[c & 15];
    }
    add(bytes_of(e), "sip-escaped", true);
  }
  // XML escaping (feature 003): a value written as XML text (& < > escaped) or
  // as an attribute value in either quote style (also " or '), matched case-insensitively.
  void xml_escaped(const std::string& t) {
    if (t.find_first_of("&<>\"'") == std::string::npos) return;
    for (const bool dq : {false, true}) {
      for (const bool sq : {false, true}) {
        std::string e;
        for (const char c : lower(t)) {
          switch (c) {
            case '&': e += "&amp;"; break;
            case '<': e += "&lt;"; break;
            case '>': e += "&gt;"; break;
            case '"': e += dq ? "&quot;" : "\""; break;
            case '\'': e += sq ? "&apos;" : "'"; break;
            default: e.push_back(c);
          }
        }
        add(bytes_of(e), "xml-escaped", true);
      }
    }
  }
  // Exact text form (case matters for the encoding name only).
  void text_exact(const std::string& t, const std::string& enc) { add(bytes_of(t), enc); }

 private:
  std::uint32_t token_;
  std::vector<Pattern>& out_;
};

}  // namespace

std::string format_ipv4(const std::uint8_t* a) {
  return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + "." +
         std::to_string(a[3]);
}

std::string format_ipv6(const std::uint8_t* a) {
  std::array<std::uint16_t, 8> g{};
  for (std::size_t i = 0; i < 8; ++i) g[i] = static_cast<std::uint16_t>((a[2 * i] << 8) | a[2 * i + 1]);
  // Longest run of two or more zero groups, first one on ties (RFC 5952 §4.2).
  int best = -1;
  int best_len = 1;
  for (int i = 0; i < 8;) {
    if (g[static_cast<std::size_t>(i)] != 0) {
      ++i;
      continue;
    }
    int j = i;
    while (j < 8 && g[static_cast<std::size_t>(j)] == 0) ++j;
    if (j - i > best_len) {
      best = i;
      best_len = j - i;
    }
    i = j;
  }
  std::string o;
  char buf[8];
  for (int i = 0; i < 8; ++i) {
    if (i == best) {
      o += "::";
      i += best_len - 1;
      continue;
    }
    if (!o.empty() && o.back() != ':') o += ":";
    std::snprintf(buf, sizeof buf, "%x", g[static_cast<std::size_t>(i)]);
    o += buf;
  }
  return o;
}

std::vector<Pattern> expand(const Token& t, std::uint32_t index, bool& scannable) {
  std::vector<Pattern> out;
  Builder b(index, out);
  const auto& v = t.value;
  if (v.size() < kMinPattern) {  // too short to search without meaningless matches
    scannable = false;
    return out;
  }
  switch (t.category) {
    case TokenCategory::ipv4: {
      if (v.size() != 4) break;
      b.binary(v, "binary");
      const std::string txt = format_ipv4(v.data());
      b.text(txt, "text");
      b.text(std::to_string(v[3]) + "." + std::to_string(v[2]) + "." + std::to_string(v[1]) + "." +
                 std::to_string(v[0]) + ".in-addr.arpa",
             "reverse-dns");
      B mapped(10, 0);
      mapped.push_back(0xff);
      mapped.push_back(0xff);
      mapped.insert(mapped.end(), v.begin(), v.end());
      b.add(mapped, "ipv4-in-ipv6");
      b.text("::ffff:" + txt, "ipv4-in-ipv6-text");
      B nat64{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0};  // RFC 6052 well-known prefix
      nat64.insert(nat64.end(), v.begin(), v.end());
      b.add(nat64, "ipv4-in-ipv6");
      B six_to_four{0x20, 0x02};  // RFC 3056
      six_to_four.insert(six_to_four.end(), v.begin(), v.end());
      b.add(six_to_four, "ipv4-in-ipv6");
      break;
    }
    case TokenCategory::ipv6: {
      if (v.size() != 16) break;
      b.binary(v, "binary");
      const std::string txt = format_ipv6(v.data());
      b.add(bytes_of(txt), "text", true);
      b.text_exact(upper(txt), "text-upper");
      b.add(utf16(txt, true), "utf16le", true);
      b.add(utf16(txt, false), "utf16be", true);
      std::string full;
      for (std::size_t i = 0; i < 16; i += 2) {
        if (i) full += ":";
        full += hex(B{v[i], v[i + 1]}, false);
      }
      b.add(bytes_of(full), "text-full", true);
      std::string rev;
      const std::string h = hex(v, false);
      for (auto it = h.rbegin(); it != h.rend(); ++it) {
        rev.push_back(*it);
        rev.push_back('.');
      }
      b.add(bytes_of(rev + "ip6.arpa"), "reverse-dns", true);
      break;
    }
    case TokenCategory::mac: {
      if (v.size() != 6) break;
      b.binary(v, "binary");
      const std::string h = hex(v, false);
      std::string colon, dash, dot;
      for (std::size_t i = 0; i < 12; i += 2) {
        if (i) {
          colon += ':';
          dash += '-';
        }
        colon += h.substr(i, 2);
        dash += h.substr(i, 2);
      }
      dot = h.substr(0, 4) + "." + h.substr(4, 4) + "." + h.substr(8, 4);
      b.text(colon, "text");
      b.text(dash, "text-dash");
      b.text(dot, "text-dot");
      b.add(bytes_of(h), "text-plain", true);
      B eui{static_cast<std::uint8_t>(v[0] ^ 0x02), v[1], v[2], 0xff, 0xfe, v[3], v[4], v[5]};
      b.add(eui, "eui64");
      break;
    }
    case TokenCategory::number: {
      // Decimal digits on digit boundaries; no hex or base64 forms (they occur by chance in
      // digit strings).
      b.add(v, "decimal", false, false, true);
      break;
    }
    case TokenCategory::binary: {
      if (v.size() != 4) break;
      const std::uint32_t n = (static_cast<std::uint32_t>(v[0]) << 24) | (static_cast<std::uint32_t>(v[1]) << 16) |
                              (static_cast<std::uint32_t>(v[2]) << 8) | v[3];
      // A 32-bit value below 2^16 (an SSRC, a reference) starts with two zero bytes: it would
      // match zeroed payloads and padding counts everywhere. It is unscannable ("short",
      // feature 004); the value stays pseudonymised.
      if (n < 0x10000u) break;
      b.add(v, "binary", false, true);
      b.add(bytes_of(std::to_string(n)), "decimal", false, false, true);
      break;
    }
    case TokenCategory::key: {
      // A 32-bit key identifier (feature 005): hex (8 digits, both cases) and base64
      // always; the raw form, a short binary token, only from 2^16 up (as for `binary`); decimal on
      // digit boundaries.
      if (v.size() != 4) break;
      const std::uint32_t n = (static_cast<std::uint32_t>(v[0]) << 24) | (static_cast<std::uint32_t>(v[1]) << 16) |
                              (static_cast<std::uint32_t>(v[2]) << 8) | v[3];
      b.binary(v, "binary", n >= 0x10000u);
      b.add(bytes_of(std::to_string(n)), "decimal", false, false, true);
      break;
    }
    case TokenCategory::bytes: {
      // A byte string (UID, RAND, IV, signature; feature 005): itself, hex in both cases and
      // base64 at the three alignments.
      if (v.size() < kMinPattern) break;
      b.binary(v, "binary");
      break;
    }
    case TokenCategory::string:
    case TokenCategory::deny: {
      const std::string s(v.begin(), v.end());
      b.text(s, "text");
      b.escaped(s);
      b.xml_escaped(s);
      if (t.category == TokenCategory::string) b.add(v, "binary");  // raw bytes, case kept
      for (std::size_t shift = 0; shift < 3; ++shift) {
        B padded(shift, 0);
        padded.insert(padded.end(), v.begin(), v.end());
        const std::string enc64 = base64(padded);
        const std::size_t lead = (shift * 8 + 5) / 6;
        const std::size_t stable_end = ((shift + v.size()) * 8) / 6;
        if (stable_end > lead + kMinPattern) b.add(bytes_of(enc64.substr(lead, stable_end - lead)), "base64");
      }
      break;
    }
  }
  scannable = !out.empty();
  return out;
}

}  // namespace mcxanon::scan::detail
