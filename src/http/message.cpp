// SPDX-License-Identifier: GPL-3.0-or-later
#include "http/message.hpp"

#include "http/counters.hpp"
#include "http/limits.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <utility>

namespace mcxanon::http {

namespace {

// RFC 9110 §5.6.2 tchar.
bool tchar(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}

bool vchar(char c) { return c > 0x20 && c < 0x7f; }

std::string_view trim_ows(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

bool http1_version(std::string_view v) {
  return v.size() == 8 && v.starts_with("HTTP/1.") && v[7] >= '0' && v[7] <= '9';
}

// "HTTP/1.x SP 3DIGIT" or "token SP target SP HTTP/1.x" on the first line (without its CRLF).
bool start_line_ok(std::string_view line, Head* h) {
  if (line.starts_with("HTTP/")) {
    if (line.size() < 12 || !http1_version(line.substr(0, 8)) || line[8] != ' ') return false;
    const auto code = line.substr(9, 3);
    if (!std::all_of(code.begin(), code.end(), [](char c) { return c >= '0' && c <= '9'; })) return false;
    if (line.size() > 12 && line[12] != ' ') return false;
    for (char c : line.substr(12)) {
      if (c != '\t' && c != ' ' && !vchar(c) && static_cast<unsigned char>(c) < 0x80) return false;
    }
    if (h != nullptr) {
      h->request = false;
      h->version = line.substr(0, 8);
      h->status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
    }
    return h == nullptr || (h->status >= 100 && h->status <= 599);
  }
  const auto sp1 = line.find(' ');
  if (sp1 == std::string_view::npos || sp1 == 0) return false;
  const auto sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos || sp2 == sp1 + 1) return false;
  const auto method = line.substr(0, sp1);
  const auto target = line.substr(sp1 + 1, sp2 - sp1 - 1);
  const auto version = line.substr(sp2 + 1);
  if (!is_token(method) || !http1_version(version)) return false;
  if (!std::all_of(target.begin(), target.end(), vchar)) return false;
  if (h != nullptr) {
    h->request = true;
    h->method = method;
    h->target = target;
    h->version = version;
  }
  return true;
}

constexpr std::array<std::pair<int, std::string_view>, 46> kReasons{{
    {100, "Continue"}, {101, "Switching Protocols"}, {200, "OK"}, {201, "Created"}, {202, "Accepted"},
    {203, "Non-Authoritative Information"}, {204, "No Content"}, {205, "Reset Content"}, {206, "Partial Content"},
    {300, "Multiple Choices"}, {301, "Moved Permanently"}, {302, "Found"}, {303, "See Other"}, {304, "Not Modified"},
    {305, "Use Proxy"}, {307, "Temporary Redirect"}, {308, "Permanent Redirect"}, {400, "Bad Request"},
    {401, "Unauthorized"}, {402, "Payment Required"}, {403, "Forbidden"}, {404, "Not Found"},
    {405, "Method Not Allowed"}, {406, "Not Acceptable"}, {407, "Proxy Authentication Required"},
    {408, "Request Timeout"}, {409, "Conflict"}, {410, "Gone"}, {411, "Length Required"},
    {412, "Precondition Failed"}, {413, "Content Too Large"}, {414, "URI Too Long"},
    {415, "Unsupported Media Type"}, {416, "Range Not Satisfiable"}, {417, "Expectation Failed"},
    {421, "Misdirected Request"}, {422, "Unprocessable Content"}, {426, "Upgrade Required"},
    {500, "Internal Server Error"}, {501, "Not Implemented"}, {502, "Bad Gateway"}, {503, "Service Unavailable"},
    {504, "Gateway Timeout"}, {505, "HTTP Version Not Supported"}, {0, ""}, {0, ""}}};

}  // namespace

bool is_token(std::string_view s) { return !s.empty() && std::all_of(s.begin(), s.end(), tchar); }

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

std::string counted_name(std::string_view name) {
  if (name.size() > 64 || !is_token(name)) return "(invalid)";
  return std::string(name);
}

std::optional<bool> is_start(std::string_view b) {
  const auto eol = b.find("\r\n");
  if (eol == std::string_view::npos) {
    if (b.size() >= kMaxFieldBytes) return false;
    // A prefix that cannot become a start line is decided early (binary data, SIP).
    if (!b.empty() && !tchar(b.front())) return false;
    const auto sp = b.find(' ');
    if (sp != std::string_view::npos && !is_token(b.substr(0, sp))) return false;
    if (b.find('\n') != std::string_view::npos) return false;
    return std::nullopt;
  }
  if (eol > kMaxFieldBytes) return false;
  Head h;
  if (!start_line_ok(b.substr(0, eol), &h)) return false;
  return true;
}

std::optional<bool> is_preface(std::string_view b) {
  if (b.size() < kPreface.size()) return kPreface.starts_with(b) ? std::nullopt : std::optional<bool>(false);
  return b.starts_with(kPreface);
}

Parse parse_head(std::string_view b, Head& out) {
  out = Head{};
  std::size_t pos = 0;
  bool first = true;
  for (;;) {
    const auto eol = b.find("\r\n", pos);
    if (eol == std::string_view::npos) {
      if (b.size() - pos > kMaxFieldBytes || b.size() > kMaxHeadBytes) return Parse::bad;
      if (b.substr(pos).find('\n') != std::string_view::npos) return Parse::bad;  // a bare LF
      return Parse::more;
    }
    if (eol - pos > kMaxFieldBytes || eol + 2 > kMaxHeadBytes) return Parse::bad;
    const auto line = b.substr(pos, eol - pos);
    if (line.find('\n') != std::string_view::npos || line.find('\r') != std::string_view::npos) return Parse::bad;
    pos = eol + 2;
    if (first) {
      if (!start_line_ok(line, &out)) return Parse::bad;
      first = false;
      continue;
    }
    if (line.empty()) {
      out.length = pos;
      return Parse::ok;
    }
    if (line.front() == ' ' || line.front() == '\t') return Parse::bad;  // obs-fold (RFC 9112 §5.2)
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) return Parse::bad;
    const auto value = trim_ows(line.substr(colon + 1));
    for (char c : value) {
      const auto u = static_cast<unsigned char>(c);
      if (u < 0x20 && c != '\t') return Parse::bad;
      if (u == 0x7f) return Parse::bad;
    }
    if (out.fields.size() >= kMaxFields) return Parse::bad;
    out.fields.push_back({line.substr(0, colon), value});
  }
}

const Field* find(const Head& h, std::string_view name) {
  for (const auto& f : h.fields) {
    if (iequal(f.name, name)) return &f;
  }
  return nullptr;
}

std::vector<std::string_view> values_of(const Head& h, std::string_view name) {
  std::vector<std::string_view> out;
  for (const auto& f : h.fields) {
    if (!iequal(f.name, name)) continue;
    std::string_view v = f.value;
    while (!v.empty()) {
      const auto c = v.find(',');
      const auto item = trim_ows(v.substr(0, c));
      if (!item.empty()) out.push_back(item);
      if (c == std::string_view::npos) break;
      v.remove_prefix(c + 1);
    }
  }
  return out;
}

BodyPlan plan_body(const Head& h, std::string_view request_method) {
  BodyPlan p;
  if (!h.request) {
    if (request_method == "HEAD" || (h.status >= 100 && h.status <= 199) || h.status == 204 || h.status == 304) return p;
    if (request_method == "CONNECT" && h.status >= 200 && h.status <= 299) {
      p.connect_tunnel = true;
      return p;
    }
  }
  const auto te = values_of(h, "Transfer-Encoding");
  if (!te.empty()) {
    // RFC 9112 §6.3 rule 3: chunked must be the final coding of a request; a response whose
    // final coding is not chunked runs to the end of the connection.
    if (find(h, "Content-Length") != nullptr && h.request) {
      p.kind = BodyPlan::Kind::bad;
      return p;
    }
    if (iequal(te.back(), "chunked")) {
      p.kind = BodyPlan::Kind::chunked;
    } else {
      p.kind = h.request ? BodyPlan::Kind::bad : BodyPlan::Kind::to_close;
    }
    return p;
  }
  const auto cl = values_of(h, "Content-Length");
  if (!cl.empty()) {
    std::optional<std::uint64_t> len;
    for (const auto v : cl) {
      std::uint64_t x = 0;
      if (v.empty() || v.size() > 15 || !std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        p.kind = BodyPlan::Kind::bad;
        return p;
      }
      std::from_chars(v.data(), v.data() + v.size(), x);
      if (len && *len != x) {
        p.kind = BodyPlan::Kind::bad;
        return p;
      }
      len = x;
    }
    p.kind = *len == 0 ? BodyPlan::Kind::none : BodyPlan::Kind::length;
    p.length = *len;
    return p;
  }
  p.kind = h.request ? BodyPlan::Kind::none : BodyPlan::Kind::to_close;
  return p;
}

Chunk chunk_at(std::string_view b) {
  Chunk c;
  const auto eol = b.find("\r\n");
  if (eol == std::string_view::npos) {
    c.kind = b.size() > kMaxChunkLine ? Chunk::Kind::bad : Chunk::Kind::more;
    return c;
  }
  if (eol > kMaxChunkLine) {
    c.kind = Chunk::Kind::bad;
    return c;
  }
  const auto line = b.substr(0, eol);
  std::size_t n = 0;
  while (n < line.size() && std::isxdigit(static_cast<unsigned char>(line[n])) != 0) ++n;
  if (n == 0 || n > 15) {
    c.kind = Chunk::Kind::bad;
    return c;
  }
  const auto ext = line.substr(n);
  if (!ext.empty()) {
    // chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    const auto t = ext.find_first_not_of(" \t");
    if (t == std::string_view::npos || ext[t] != ';') {
      c.kind = Chunk::Kind::bad;
      return c;
    }
    for (char ch : ext) {
      if (static_cast<unsigned char>(ch) < 0x20 && ch != '\t') {
        c.kind = Chunk::Kind::bad;
        return c;
      }
    }
  }
  std::uint64_t size = 0;
  std::from_chars(line.data(), line.data() + n, size, 16);
  c.line = eol + 2;
  if (size > 0) {
    c.kind = Chunk::Kind::data;
    c.size = size;
    return c;
  }
  // last-chunk, then trailer-section CRLF.
  std::size_t pos = c.line;
  for (;;) {
    const auto e = b.find("\r\n", pos);
    if (e == std::string_view::npos) {
      c.kind = b.size() - c.line > kMaxTrailer ? Chunk::Kind::bad : Chunk::Kind::more;
      return c;
    }
    if (e + 2 - c.line > kMaxTrailer) {
      c.kind = Chunk::Kind::bad;
      return c;
    }
    if (e == pos) {
      c.kind = Chunk::Kind::last;
      c.total = e + 2;
      return c;
    }
    const auto field = b.substr(pos, e - pos);
    const auto colon = field.find(':');
    if (colon == std::string_view::npos || !is_token(field.substr(0, colon))) {
      c.kind = Chunk::Kind::bad;
      return c;
    }
    pos = e + 2;
  }
}

Dechunked dechunk(std::string_view b, std::size_t limit) {
  Dechunked d;
  std::size_t pos = 0;
  for (;;) {
    if (pos > limit) {
      d.kind = Dechunked::Kind::over;
      return d;
    }
    const auto c = chunk_at(b.substr(pos));
    switch (c.kind) {
      case Chunk::Kind::more:
        d.kind = b.size() > limit ? Dechunked::Kind::over : Dechunked::Kind::more;
        return d;
      case Chunk::Kind::bad: d.kind = Dechunked::Kind::bad; return d;
      case Chunk::Kind::last:
        d.kind = pos + c.total > limit ? Dechunked::Kind::over : Dechunked::Kind::done;
        d.encoded = pos + c.total;
        return d;
      case Chunk::Kind::data: {
        if (c.size > limit) {
          d.kind = Dechunked::Kind::over;
          return d;
        }
        const auto need = pos + c.line + c.size + 2;
        if (need > limit) {
          d.kind = Dechunked::Kind::over;
          return d;
        }
        if (b.size() < need) {
          d.kind = Dechunked::Kind::more;
          return d;
        }
        if (b.substr(need - 2, 2) != "\r\n") {
          d.kind = Dechunked::Kind::bad;
          return d;
        }
        d.data.append(b.substr(pos + c.line, c.size));
        pos = need;
        break;
      }
    }
  }
}

std::string_view reason_phrase(int code) {
  for (const auto& [c, r] : kReasons) {
    if (c == code) return r;
  }
  return {};
}

}  // namespace mcxanon::http
