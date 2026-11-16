// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/multipart.hpp"

#include "sip/limits.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace mcxanon::sip {
namespace {

bool bcharnospace(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 ||
         std::string_view("'()+_,-./:=?").find(c) != std::string_view::npos;
}

// After "--boundary": transport padding (LWSP) and CRLF; returns the offset after the CRLF.
std::optional<std::size_t> after_delimiter(std::string_view s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  if (s.substr(pos, 2) != "\r\n") return std::nullopt;
  return pos + 2;
}

}  // namespace

bool is_boundary(std::string_view b) {
  if (b.empty() || b.size() > 70) return false;
  if (!std::all_of(b.begin(), b.end(), [](char c) { return c == ' ' || bcharnospace(c); })) return false;
  return b.back() != ' ';
}

std::optional<MultipartBody> parse_multipart(std::string_view body, std::string_view boundary) {
  if (!is_boundary(boundary)) return std::nullopt;
  const std::string dash = "--" + std::string(boundary);
  const std::string delim = "\r\n" + dash;
  MultipartBody out;
  // The first delimiter may start the body; otherwise it follows a CRLF (preamble before it).
  std::size_t pos = 0;
  if (body.substr(0, dash.size()) != dash) {
    const auto first = body.find(delim);
    if (first == std::string_view::npos) return std::nullopt;
    out.preamble = true;
    pos = first + 2;
  }
  pos += dash.size();
  for (;;) {
    if (body.substr(pos, 2) == "--") {
      // close-delimiter; anything after it (beyond an optional CRLF) is the epilogue
      const auto rest = body.substr(pos + 2);
      out.epilogue = !(rest.empty() || rest == "\r\n");
      return out.parts.empty() ? std::nullopt : std::optional<MultipartBody>(std::move(out));
    }
    const auto start = after_delimiter(body, pos);
    if (!start) return std::nullopt;
    const auto next = body.find(delim, *start);
    if (next == std::string_view::npos) return std::nullopt;
    if (out.parts.size() == kMaxParts) return std::nullopt;
    const auto part = body.substr(0, next);  // headers are parsed against the whole body
    BodyPart bp;
    if (next == *start) {
      // an empty part: no headers, no body
    } else if (body.substr(*start, 2) == "\r\n") {
      bp.body = body.substr(*start + 2, next - *start - 2);  // no part headers
    } else {
      auto block = parse_header_block(part, *start);
      if (!block) return std::nullopt;
      bp.headers = std::move(block->headers);
      bp.body = body.substr(block->end, next - block->end);
    }
    out.parts.push_back(std::move(bp));
    pos = next + delim.size();
  }
}

}  // namespace mcxanon::sip
