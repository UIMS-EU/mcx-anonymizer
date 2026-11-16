// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/stream_framing.hpp"

#include "sip/limits.hpp"
#include "sip/message.hpp"

#include <cctype>

namespace mcxanon::sip {
namespace {

bool iprefix(std::string_view a, std::string_view b) {  // a is a case-insensitive prefix of b
  if (a.size() > b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// A start line still arriving (no CRLF yet): could these bytes begin a Request-Line or a
// Status-Line (RFC 3261 §7.1, §7.2)? Deciding early keeps non-SIP text streams from waiting.
bool plausible_start(std::string_view d) {
  if (d.size() >= kMaxHeaderLineBytes) return false;
  if (!d.empty() && d.back() == '\r') d.remove_suffix(1);
  for (const char c : d) {
    const auto u = static_cast<unsigned char>(c);
    if (u < 0x20 || u > 0x7E) return false;
  }
  constexpr std::string_view kVersion = "SIP/2.0";
  if (iprefix(d, "SIP/2.0 ") || iprefix("SIP/2.0 ", d)) return true;
  // RFC 3261 §25.1: token characters of a Method.
  const auto token = [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || std::string_view("-.!%*_+`'~").find(c) != std::string_view::npos;
  };
  std::size_t i = 0;
  while (i < d.size() && token(d[i])) ++i;
  if (i == d.size()) return i > 0;
  if (i == 0 || d[i] != ' ') return false;
  std::size_t j = i + 1;
  while (j < d.size() && d[j] != ' ') ++j;
  if (j == d.size()) return true;
  return iprefix(d.substr(j + 1), kVersion);
}

}  // namespace

// R3 over a stream: true or false once the first line is complete, nullopt while it may still
// become a SIP start line.
std::optional<bool> stream_start(std::string_view d) {
  if (d.find("\r\n") == std::string_view::npos) {
    return plausible_start(d) ? std::nullopt : std::optional<bool>(false);
  }
  return is_start_line(d);
}

// RFC 3261 §18.3 framing; keep-alive CRLFs (RFC 5626 §3.5.1) are kept as they are.
StreamFrame stream_frame(std::string_view d) {
  if (d.starts_with('\r')) {
    std::size_t n = 0;
    while (d.substr(n, 2) == "\r\n") n += 2;
    if (n == 0) return {d.size() < 2 ? StreamFrame::Kind::more : StreamFrame::Kind::invalid, 0};
    return {StreamFrame::Kind::verbatim, n};
  }
  const auto r = frame_stream(d);
  if (!r) {
    // A message larger than the bound is skipped by its declared length (R15).
    const auto n = declared_stream_length(d);
    if (n && *n > kMaxMessageBytes) return {StreamFrame::Kind::oversized, *n};
    return {StreamFrame::Kind::invalid, 0};
  }
  if (*r == 0) return {StreamFrame::Kind::more, 0};
  return {StreamFrame::Kind::message, *r};
}

}  // namespace mcxanon::sip
