// SPDX-License-Identifier: GPL-3.0-or-later
#include "media/msrp.hpp"

#include "sip/sdp.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace mcxanon::media {
namespace {

constexpr std::string_view kEnd = "-------";

std::string lower(std::string_view s) {
  std::string o(s);
  for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

bool alnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }

// ident = ALPHANUM 3*31ident-char; ident-char = ALPHANUM / "." / "-" / "+" / "%" / "=" (RFC 4975 §9).
bool ident(std::string_view s) {
  return s.size() >= 4 && s.size() <= 32 && alnum(s[0]) && std::all_of(s.begin(), s.end(), [](char c) {
           return alnum(c) || c == '.' || c == '-' || c == '+' || c == '%' || c == '=';
         });
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return s;
}

std::vector<std::string_view> split(std::string_view s, char sep) {
  std::vector<std::string_view> out;
  for (std::size_t i = 0;;) {
    const auto p = s.find(sep, i);
    out.push_back(s.substr(i, p == std::string_view::npos ? p : p - i));
    if (p == std::string_view::npos) break;
    i = p + 1;
  }
  return out;
}

// The transaction id of a start line, or empty.
std::string_view start_tid(std::string_view d) {
  if (!d.starts_with("MSRP ")) return {};
  const auto sp = d.find(' ', 5);
  const auto eol = d.find("\r\n");
  if (sp == std::string_view::npos || eol == std::string_view::npos || sp > eol) return {};
  const auto tid = d.substr(5, sp - 5);
  return ident(tid) ? tid : std::string_view{};
}

}  // namespace

std::optional<bool> msrp_is_start(std::string_view d) {
  constexpr std::string_view p = "MSRP ";
  if (d.size() < p.size()) return p.starts_with(d) ? std::nullopt : std::optional<bool>(false);
  if (!d.starts_with(p)) return false;
  if (d.find("\r\n") == std::string_view::npos) return d.size() < 512 ? std::nullopt : std::optional<bool>(false);
  return !start_tid(d).empty();
}

MsrpFrame msrp_frame(std::string_view d) {
  const auto is = msrp_is_start(d);
  if (!is) return {MsrpFrameKind::more, 0};
  if (!*is) return {MsrpFrameKind::invalid, 0};
  const std::string mark = std::string(kEnd) + std::string(start_tid(d));
  for (std::size_t at = d.find(mark); at != std::string_view::npos; at = d.find(mark, at + 1)) {
    if (at == 0 || d[at - 1] != '\n') continue;
    const std::size_t f = at + mark.size();
    if (f + 3 > d.size()) return {MsrpFrameKind::more, 0};
    if ((d[f] == '$' || d[f] == '+' || d[f] == '#') && d.substr(f + 1, 2) == "\r\n") {
      return {MsrpFrameKind::message, f + 3};
    }
  }
  return {MsrpFrameKind::more, 0};
}

Result<MsrpRewrite> rewrite_msrp(std::string_view m, const MediaRuleSet& rules, sip::Context& sip,
                                 AddressMapper& mapper, MediaCounters& c) {
  MsrpRewrite out;
  const auto zeroed = [&](const char* why) -> Result<MsrpRewrite> {
    ++c.msrp_zeroed[why];
    MsrpRewrite z;
    z.zeroed = true;
    return z;
  };
  const auto eol = m.find("\r\n");
  const auto tid = start_tid(m);
  if (tid.empty() || eol == std::string_view::npos) return zeroed("malformed");
  const auto rest = m.substr(5 + tid.size() + 1, eol - (5 + tid.size() + 1));
  auto ptid = mapper.text(Category::msrp_tid, tid);
  if (!ptid) return std::unexpected(ptid.error());
  std::string head = "MSRP " + *ptid + " ";
  // Request: a method (1*UPALPHA); response: 3DIGIT [SP comment] (RFC 4975 §9).
  const bool response = rest.size() >= 3 && std::all_of(rest.begin(), rest.begin() + 3, [](char x) {
    return x >= '0' && x <= '9';
  }) && (rest.size() == 3 || rest[3] == ' ');
  if (response) {
    head += std::string(rest.substr(0, 3));
    if (rest.size() > 3) c.removed(trim(rest.substr(4)));  // the comment (B14)
    ++c.msrp_responses[std::string(1, rest[0]) + "xx"];
  } else {
    if (rest.empty() || !std::all_of(rest.begin(), rest.end(), [](char x) { return x >= 'A' && x <= 'Z'; })) {
      return zeroed("malformed");
    }
    const auto rule = rules.msrp.methods.find(std::string(rest));
    if (rule == rules.msrp.methods.end()) {
      ++c.msrp_requests["other"];
      return zeroed("method");
    }
    ++c.msrp_requests[std::string(rest)];
    head += std::string(rest);
  }
  head += "\r\n";
  // The header section: lines up to an empty line (content follows) or up to the end-line.
  const std::string mark = std::string(kEnd) + std::string(tid);
  std::size_t i = eol + 2;
  std::size_t content_begin = std::string_view::npos;
  for (;;) {
    const auto e = m.find("\r\n", i);
    if (e == std::string_view::npos) return zeroed("malformed");
    const auto line = m.substr(i, e - i);
    if (line.empty()) {
      content_begin = e + 2;
      i = e + 2;
      break;
    }
    if (line.starts_with(mark)) break;  // no body: the end-line follows the headers
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) return zeroed("malformed");
    const auto name = line.substr(0, colon);
    const auto value = trim(line.substr(colon + 1));
    const auto rule = rules.msrp.headers.find(lower(name));
    i = e + 2;
    if (rule == rules.msrp.headers.end() || rule->second.action == MediaAction::remove) {
      c.count(c.msrp_headers, rule == rules.msrp.headers.end() ? "other" : rule->second.name, "remove");
      c.removed(value);
      continue;
    }
    const std::string key = rule->second.name;
    const std::string lname = lower(name);
    std::string v;
    if (lname == "to-path" || lname == "from-path") {
      for (const auto u : split(value, ' ')) {
        if (u.empty()) continue;
        auto p = sip::map_msrp_uri(u, sip);
        if (!p) return std::unexpected(p.error());
        if (!*p) return zeroed("malformed");
        v += (v.empty() ? "" : " ") + **p;
      }
      if (v.empty()) return zeroed("malformed");
    } else if (lname == "message-id") {
      if (!ident(value)) return zeroed("malformed");
      auto p = mapper.text(Category::msrp_msgid, value);
      if (!p) return std::unexpected(p.error());
      v = *p;
    } else if (lname == "status") {
      // namespace SP status-code [SP comment]: the comment is removed (B14).
      const auto f = split(value, ' ');
      if (f.size() < 2) return zeroed("malformed");
      v = std::string(f[0]) + " " + std::string(f[1]);
      if (f.size() > 2) c.removed(value.substr(f[0].size() + f[1].size() + 2));
    } else if (lname == "content-type") {
      // The media type is kept; boundary uses the 002 boundary mapping, charset is kept, every
      // other parameter is removed.
      const auto p = split(value, ';');
      v = std::string(trim(p[0]));
      for (std::size_t k = 1; k < p.size(); ++k) {
        const auto prm = trim(p[k]);
        const auto eq = prm.find('=');
        const auto pn = lower(prm.substr(0, eq));
        if (eq == std::string_view::npos) continue;
        const auto pv = prm.substr(eq + 1);
        if (pn == "boundary") {
          auto b = mapper.text(Category::boundary, pv);
          if (!b) return std::unexpected(b.error());
          v += ";boundary=" + *b;
        } else if (pn == "charset") {
          v += ";" + std::string(prm);
        } else {
          c.removed(pv);
        }
      }
    } else if (lname == "content-disposition") {
      const auto semi = value.find(';');
      if (semi != std::string_view::npos) c.removed(value.substr(semi + 1));
      v = std::string(trim(value.substr(0, semi)));
    } else {
      // Byte-Range, Success-Report, Failure-Report: kept as written when printable.
      if (!std::all_of(value.begin(), value.end(), [](char x) { return x > 0x20 && x < 0x7F; })) {
        return zeroed("malformed");
      }
      v = std::string(value);
    }
    head += std::string(name) + ": " + v + "\r\n";
    c.count(c.msrp_headers, key, rule->second.action == MediaAction::keep ? "keep" : "pseudonymise");
  }
  if (content_begin != std::string_view::npos) head += "\r\n";
  out.head_orig = i;
  out.head_out = head.size();
  // Content (FR-028): zeros of its length, up to the CRLF that precedes the end-line.
  const auto end_at = m.rfind(mark);
  if (end_at == std::string_view::npos || end_at < i) return zeroed("malformed");
  std::string tail;
  if (content_begin != std::string_view::npos) {
    if (end_at < i + 2 || m.substr(end_at - 2, 2) != "\r\n") return zeroed("malformed");
    tail.assign(end_at - 2 - i, '\0');
    tail += "\r\n";
  } else if (end_at != i) {
    return zeroed("malformed");
  }
  tail += std::string(kEnd) + *ptid + std::string(m.substr(end_at + mark.size()));
  out.bytes = head + tail;
  return out;
}

}  // namespace mcxanon::media
