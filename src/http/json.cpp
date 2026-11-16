// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/json.hpp"

#include "http/limits.hpp"

#include <cstdint>

namespace mcxanon::http {

namespace {

class Reader {
 public:
  explicit Reader(std::string_view s) : s_(s) {}

  std::optional<Json> document() {
    ws();
    auto v = value(0);
    if (!v) return std::nullopt;
    ws();
    if (p_ != s_.size()) return std::nullopt;
    return v;
  }

 private:
  void ws() {
    while (p_ < s_.size() && (s_[p_] == ' ' || s_[p_] == '\t' || s_[p_] == '\n' || s_[p_] == '\r')) ++p_;
  }

  bool lit(std::string_view w) {
    if (s_.substr(p_, w.size()) != w) return false;
    p_ += w.size();
    return true;
  }

  bool count() { return ++count_ <= kMaxJsonMembers; }

  std::optional<Json> value(std::size_t depth) {
    if (depth > kMaxJsonDepth || p_ >= s_.size()) return std::nullopt;
    Json j;
    const char c = s_[p_];
    if (c == '{') {
      j.type = Json::Type::object;
      ++p_;
      ws();
      if (p_ < s_.size() && s_[p_] == '}') {
        ++p_;
        return j;
      }
      for (;;) {
        ws();
        auto k = string();
        if (!k) return std::nullopt;
        ws();
        if (p_ >= s_.size() || s_[p_] != ':') return std::nullopt;
        ++p_;
        ws();
        auto v = value(depth + 1);
        if (!v || !count()) return std::nullopt;
        bool dup = false;
        for (const auto& m : j.members) dup = dup || m.first == *k;
        if (!dup) j.members.push_back(JsonMember{std::move(*k), std::move(*v)});
        ws();
        if (p_ < s_.size() && s_[p_] == ',') {
          ++p_;
          continue;
        }
        if (p_ < s_.size() && s_[p_] == '}') {
          ++p_;
          return j;
        }
        return std::nullopt;
      }
    }
    if (c == '[') {
      j.type = Json::Type::array;
      ++p_;
      ws();
      if (p_ < s_.size() && s_[p_] == ']') {
        ++p_;
        return j;
      }
      for (;;) {
        ws();
        auto v = value(depth + 1);
        if (!v || !count()) return std::nullopt;
        j.items.push_back(std::move(*v));
        ws();
        if (p_ < s_.size() && s_[p_] == ',') {
          ++p_;
          continue;
        }
        if (p_ < s_.size() && s_[p_] == ']') {
          ++p_;
          return j;
        }
        return std::nullopt;
      }
    }
    if (c == '"') {
      auto t = string();
      if (!t) return std::nullopt;
      return Json::string_of(std::move(*t));
    }
    if (lit("true")) {
      j.type = Json::Type::boolean;
      j.boolean = true;
      return j;
    }
    if (lit("false")) {
      j.type = Json::Type::boolean;
      return j;
    }
    if (lit("null")) return j;
    return number();
  }

  // RFC 8259 §6: -? int frac? exp?
  std::optional<Json> number() {
    const std::size_t start = p_;
    const auto digits = [&] {
      const std::size_t b = p_;
      while (p_ < s_.size() && s_[p_] >= '0' && s_[p_] <= '9') ++p_;
      return p_ - b;
    };
    if (p_ < s_.size() && s_[p_] == '-') ++p_;
    if (p_ < s_.size() && s_[p_] == '0') {
      ++p_;
    } else if (digits() == 0) {
      return std::nullopt;
    }
    if (p_ < s_.size() && s_[p_] == '.') {
      ++p_;
      if (digits() == 0) return std::nullopt;
    }
    if (p_ < s_.size() && (s_[p_] == 'e' || s_[p_] == 'E')) {
      ++p_;
      if (p_ < s_.size() && (s_[p_] == '+' || s_[p_] == '-')) ++p_;
      if (digits() == 0) return std::nullopt;
    }
    if (p_ - start > 64) return std::nullopt;
    return Json::number_of(std::string(s_.substr(start, p_ - start)));
  }

  static void utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  std::optional<std::uint32_t> hex4() {
    if (p_ + 4 > s_.size()) return std::nullopt;
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = s_[p_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
      else return std::nullopt;
    }
    return v;
  }

  std::optional<std::string> string() {
    if (p_ >= s_.size() || s_[p_] != '"') return std::nullopt;
    ++p_;
    std::string out;
    while (p_ < s_.size()) {
      if (out.size() > kMaxJsonString) return std::nullopt;
      const auto c = static_cast<unsigned char>(s_[p_]);
      if (c == '"') {
        ++p_;
        return out;
      }
      if (c < 0x20) return std::nullopt;
      if (c == '\\') {
        if (++p_ >= s_.size()) return std::nullopt;
        const char e = s_[p_++];
        switch (e) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            auto cp = hex4();
            if (!cp) return std::nullopt;
            if (*cp >= 0xD800 && *cp <= 0xDBFF) {
              if (!lit("\\u")) return std::nullopt;
              auto lo = hex4();
              if (!lo || *lo < 0xDC00 || *lo > 0xDFFF) return std::nullopt;
              *cp = 0x10000 + ((*cp - 0xD800) << 10) + (*lo - 0xDC00);
            } else if (*cp >= 0xDC00 && *cp <= 0xDFFF) {
              return std::nullopt;
            }
            utf8(out, *cp);
            break;
          }
          default: return std::nullopt;
        }
        continue;
      }
      // UTF-8 sequence, validated (RFC 3629).
      std::size_t n = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
      if (n == 0 || p_ + n > s_.size() || (n == 2 && c < 0xC2) || (n == 4 && c > 0xF4)) return std::nullopt;
      for (std::size_t i = 1; i < n; ++i) {
        if ((static_cast<unsigned char>(s_[p_ + i]) & 0xC0) != 0x80) return std::nullopt;
      }
      if (n == 3) {
        const auto c1 = static_cast<unsigned char>(s_[p_ + 1]);
        if ((c == 0xE0 && c1 < 0xA0) || (c == 0xED && c1 > 0x9F)) return std::nullopt;
      }
      if (n == 4) {
        const auto c1 = static_cast<unsigned char>(s_[p_ + 1]);
        if ((c == 0xF0 && c1 < 0x90) || (c == 0xF4 && c1 > 0x8F)) return std::nullopt;
      }
      out.append(s_.substr(p_, n));
      p_ += n;
    }
    return std::nullopt;
  }

  std::string_view s_;
  std::size_t p_ = 0;
  std::size_t count_ = 0;
};

void write_string(std::string& out, std::string_view s) {
  static constexpr char kHex[] = "0123456789abcdef";
  out.push_back('"');
  for (char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(kHex[c >> 4]);
          out.push_back(kHex[c & 15]);
        } else {
          out.push_back(ch);
        }
    }
  }
  out.push_back('"');
}

void write(std::string& out, const Json& j) {
  switch (j.type) {
    case Json::Type::null: out += "null"; break;
    case Json::Type::boolean: out += j.boolean ? "true" : "false"; break;
    case Json::Type::number: out += j.text; break;
    case Json::Type::string: write_string(out, j.text); break;
    case Json::Type::array:
      out.push_back('[');
      for (std::size_t i = 0; i < j.items.size(); ++i) {
        if (i) out.push_back(',');
        write(out, j.items[i]);
      }
      out.push_back(']');
      break;
    case Json::Type::object:
      out.push_back('{');
      for (std::size_t i = 0; i < j.members.size(); ++i) {
        if (i) out.push_back(',');
        write_string(out, j.members[i].first);
        out.push_back(':');
        write(out, j.members[i].second);
      }
      out.push_back('}');
      break;
  }
}

}  // namespace

std::optional<Json> parse_json(std::string_view text) {
  if (text.size() > kMaxRewrittenBody) return std::nullopt;
  return Reader(text).document();
}

std::string write_json(const Json& j) {
  std::string out;
  write(out, j);
  return out;
}

}  // namespace mcxanon::http
