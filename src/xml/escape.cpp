// SPDX-License-Identifier: GPL-3.0-or-later
#include "xml/escape.hpp"

#include <cstdint>

namespace mcxanon::xml {
namespace {

void append_utf8(std::string& out, char32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// The value of a reference body between '&' and ';' (XML 1.0 [66], [68]); nullopt if invalid.
std::optional<char32_t> reference(std::string_view ref) {
  if (ref == "lt") return U'<';
  if (ref == "gt") return U'>';
  if (ref == "amp") return U'&';
  if (ref == "apos") return U'\'';
  if (ref == "quot") return U'"';
  if (ref.size() < 2 || ref[0] != '#') return std::nullopt;
  std::uint32_t v = 0;
  if (ref[1] == 'x') {
    if (ref.size() < 3) return std::nullopt;
    for (const char c : ref.substr(2)) {
      const int d = hex_digit(c);
      if (d < 0 || v > 0x10FFFF) return std::nullopt;
      v = v * 16 + static_cast<std::uint32_t>(d);
    }
  } else {
    for (const char c : ref.substr(1)) {
      if (c < '0' || c > '9' || v > 0x10FFFF) return std::nullopt;
      v = v * 10 + static_cast<std::uint32_t>(c - '0');
    }
  }
  if (!is_xml_char(static_cast<char32_t>(v))) return std::nullopt;
  return static_cast<char32_t>(v);
}

}  // namespace

bool is_xml_char(char32_t cp) {
  return cp == 0x9 || cp == 0xA || cp == 0xD || (cp >= 0x20 && cp <= 0xD7FF) ||
         (cp >= 0xE000 && cp <= 0xFFFD) || (cp >= 0x10000 && cp <= 0x10FFFF);
}

std::optional<std::string> unescape(std::string_view raw, bool attribute) {
  std::string out;
  out.reserve(raw.size());
  for (std::size_t i = 0; i < raw.size(); ++i) {
    const char c = raw[i];
    if (c == '&') {
      const auto semi = raw.find(';', i + 1);
      if (semi == std::string_view::npos || semi - i > 12) return std::nullopt;
      const auto cp = reference(raw.substr(i + 1, semi - i - 1));
      if (!cp) return std::nullopt;
      append_utf8(out, *cp);
      i = semi;
    } else if (attribute && (c == '\t' || c == '\n' || c == '\r')) {
      if (c == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') ++i;  // CR LF is one line end
      out += ' ';
    } else if (!attribute && c == '\r') {
      // XML 1.0 §2.11: CR LF and a lone CR are a line feed.
      if (i + 1 < raw.size() && raw[i + 1] == '\n') ++i;
      out += '\n';
    } else {
      out += c;
    }
  }
  return out;
}

std::string escape_text(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '\r': out += "&#13;"; break;
      default: out += c;
    }
  }
  return out;
}

std::string escape_attr(std::string_view text, char quote) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '\t': out += "&#9;"; break;
      case '\n': out += "&#10;"; break;
      case '\r': out += "&#13;"; break;
      case '"': out += quote == '"' ? "&quot;" : "\""; break;
      case '\'': out += quote == '\'' ? "&apos;" : "'"; break;
      default: out += c;
    }
  }
  return out;
}

}  // namespace mcxanon::xml
