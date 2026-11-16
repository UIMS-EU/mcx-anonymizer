// SPDX-License-Identifier: GPL-3.0-or-later
#include "sip/message.hpp"

#include "sip/limits.hpp"

#include <algorithm>
#include <cctype>

namespace mcxanon::sip {
namespace {

// RFC 3261 §25.1: token = 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~")
bool is_token_char(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 ||
         std::string_view("-.!%*_+`'~").find(c) != std::string_view::npos;
}

bool is_token(std::string_view s) { return !s.empty() && std::all_of(s.begin(), s.end(), is_token_char); }

bool iequal(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

std::unexpected<ParseError> bad(Failure f, const char* why) { return std::unexpected(ParseError{f, why}); }

// The first line, without CRLF, or nullopt when no CRLF occurs within the line bound.
std::optional<std::string_view> first_line(std::string_view data) {
  const auto limit = std::min(data.size(), kMaxHeaderLineBytes);
  const auto crlf = data.substr(0, limit).find("\r\n");
  if (crlf == std::string_view::npos) return std::nullopt;
  return data.substr(0, crlf);
}

bool is_version(std::string_view v) { return iequal(v, "SIP/2.0"); }

bool is_request_line(std::string_view line) {
  const auto sp1 = line.find(' ');
  if (sp1 == std::string_view::npos) return false;
  const auto sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos) return false;
  const auto method = line.substr(0, sp1);
  const auto uri = line.substr(sp1 + 1, sp2 - sp1 - 1);
  if (!is_token(method) || uri.empty()) return false;
  // Request-URI: no whitespace or control characters; it needs a scheme ":".
  if (std::any_of(uri.begin(), uri.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u <= 0x20 || u >= 0x7F;
      })) {
    return false;
  }
  if (uri.find(':') == std::string_view::npos) return false;
  return is_version(line.substr(sp2 + 1));
}

bool is_status_line(std::string_view line) {
  if (line.size() < 12 || !is_version(line.substr(0, 7)) || line[7] != ' ') return false;
  for (std::size_t i = 8; i < 11; ++i) {
    if (line[i] < '0' || line[i] > '9') return false;
  }
  if (line[8] < '1' || line[8] > '6' || line[11] != ' ') return false;
  // Reason-Phrase: no control characters other than HTAB.
  return std::none_of(line.begin() + 12, line.end(), [](char c) {
    const auto u = static_cast<unsigned char>(c);
    return (u < 0x20 && u != '\t') || u == 0x7F;
  });
}

bool is_wsp(char c) { return c == ' ' || c == '\t'; }

std::string_view trim(std::string_view s) {
  while (!s.empty() && is_wsp(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_wsp(s.back())) s.remove_suffix(1);
  return s;
}

}  // namespace

std::expected<HeaderBlock, ParseError> parse_header_block(std::string_view data, std::size_t pos,
                                                          bool stream) {
  // Header section (§7.3): field lines and continuation lines, ended by an empty line.
  HeaderBlock out;
  auto& m = out;
  bool ended = false;
  while (pos <= data.size()) {
    if (pos > kMaxMessageBytes) return bad(Failure::malformed, "message too large");
    const auto rest = data.substr(pos);
    const auto crlf = rest.find("\r\n");
    const auto lf = rest.find('\n');
    if (lf != std::string_view::npos && (crlf == std::string_view::npos || lf < crlf + 1)) {
      return bad(Failure::malformed, "bare LF in the header section");
    }
    if (crlf == std::string_view::npos) break;
    const auto text = rest.substr(0, crlf);
    if (text.find('\r') != std::string_view::npos) return bad(Failure::malformed, "bare CR in the header section");
    if (text.empty()) {
      pos += 2;
      ended = true;
      break;
    }
    if (is_wsp(text.front())) {
      // Continuation of the previous field (§7.3.1).
      if (m.headers.empty()) return bad(Failure::malformed, "continuation line without a field");
      auto& h = m.headers.back();
      h.line.len = pos + crlf + 2 - h.line.off;
      const auto cont = trim(text);
      if (!cont.empty()) {
        if (h.value.len == 0) {
          h.value = {pos + static_cast<std::size_t>(cont.data() - text.data()), cont.size()};
        } else {
          h.value.len = pos + static_cast<std::size_t>(cont.data() - text.data()) + cont.size() - h.value.off;
        }
        if (!h.unfolded.empty()) h.unfolded.push_back(' ');
        h.unfolded.append(cont);
      }
      if (h.line.len > kMaxHeaderLineBytes) return bad(Failure::malformed, "header field too long");
    } else {
      if (m.headers.size() == kMaxHeaders) return bad(Failure::malformed, "too many header fields");
      const auto colon = text.find(':');
      if (colon == std::string_view::npos) return bad(Failure::malformed, "header field without a colon");
      const auto name = trim(text.substr(0, colon));
      if (!is_token(name) || name.data() != text.data()) {
        return bad(Failure::malformed, "header field name is not a token");
      }
      HeaderField h;
      h.name = {pos, name.size()};
      h.line = {pos, crlf + 2};
      const auto value = trim(text.substr(colon + 1));
      h.value = {pos + (value.empty() ? text.size() : static_cast<std::size_t>(value.data() - text.data())),
                 value.size()};
      h.unfolded.assign(value);
      if (h.line.len > kMaxHeaderLineBytes) return bad(Failure::malformed, "header field too long");
      m.headers.push_back(std::move(h));
    }
    pos += crlf + 2;
  }
  if (!ended) {
    if (stream && data.size() < kMaxMessageBytes) return bad(Failure::incomplete, "header section incomplete");
    return bad(Failure::malformed, "header section not terminated");
  }
  out.end = pos;
  return out;
}

bool is_start_line(std::string_view data) {
  const auto line = first_line(data);
  if (!line) return false;
  // §7.1: "The SIP-Version string is case-insensitive".
  return is_status_line(*line) || is_request_line(*line);
}

std::expected<SipMessage, ParseError> parse_message(std::string_view data, Transport transport) {
  const bool stream = transport == Transport::stream;
  const auto line = first_line(data);
  if (!line) {
    if (stream && data.size() < kMaxHeaderLineBytes) return bad(Failure::incomplete, "start line incomplete");
    return bad(Failure::not_sip, "no SIP start line");
  }
  SipMessage m;
  if (is_status_line(*line)) {
    m.kind = MessageKind::response;
    m.status_code = (line->at(8) - '0') * 100 + (line->at(9) - '0') * 10 + (line->at(10) - '0');
    m.reason = {12, line->size() - 12};
  } else if (is_request_line(*line)) {
    m.kind = MessageKind::request;
    const auto sp1 = line->find(' ');
    const auto sp2 = line->find(' ', sp1 + 1);
    m.method = {0, sp1};
    m.request_uri = {sp1 + 1, sp2 - sp1 - 1};
  } else {
    return bad(Failure::not_sip, "no SIP start line");
  }
  if (!stream && data.size() > kMaxMessageBytes) return bad(Failure::malformed, "message too large");
  m.start_line = {0, line->size()};

  auto block = parse_header_block(data, line->size() + 2, stream);
  if (!block) return std::unexpected(block.error());
  m.headers = std::move(block->headers);
  m.header_end = block->end;

  // Content-Length (§20.14, compact form "l", §7.3.3).
  for (const auto& h : m.headers) {
    const auto name = data.substr(h.name.off, h.name.len);
    if (!iequal(name, "Content-Length") && !iequal(name, "l")) continue;
    const std::string_view v = h.unfolded;
    if (v.empty() || v.size() > 10 ||
        !std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return bad(Failure::malformed, "invalid Content-Length");
    }
    std::size_t n = 0;
    for (char c : v) n = n * 10 + static_cast<std::size_t>(c - '0');
    if (n > kMaxMessageBytes) return bad(Failure::malformed, "Content-Length too large");
    if (m.content_length && *m.content_length != n) return bad(Failure::malformed, "conflicting Content-Length");
    m.content_length = n;
  }

  const std::size_t available = data.size() - m.header_end;
  if (stream) {
    if (!m.content_length) return bad(Failure::malformed, "no Content-Length on a stream transport");
    if (*m.content_length > available) {
      if (m.header_end + *m.content_length > kMaxMessageBytes) return bad(Failure::malformed, "message too large");
      return bad(Failure::incomplete, "body incomplete");
    }
    m.body = {m.header_end, *m.content_length};
  } else if (m.content_length) {
    if (*m.content_length > available) return bad(Failure::malformed, "Content-Length exceeds the datagram");
    m.body = {m.header_end, *m.content_length};
    m.trailing = {m.body.end(), available - *m.content_length};
  } else {
    m.body = {m.header_end, available};  // §18.3: the body runs to the end of the datagram
  }
  if (m.body.end() > kMaxMessageBytes) return bad(Failure::malformed, "message too large");
  return m;
}

std::expected<std::size_t, ParseError> frame_stream(std::string_view data) {
  if (data.empty()) return std::size_t{0};
  if (!first_line(data)) {
    // A start line still arriving: plausible only if every byte so far is printable text.
    const bool text = data.size() < kMaxHeaderLineBytes &&
                      std::all_of(data.begin(), data.end(), [](char c) {
                        const auto u = static_cast<unsigned char>(c);
                        return (u >= 0x20 && u < 0x7F) || u == '\r';
                      });
    if (text) return std::size_t{0};
    return bad(Failure::not_sip, "no SIP start line");
  }
  auto m = parse_message(data, Transport::stream);
  if (!m) {
    if (m.error().kind == Failure::incomplete) return std::size_t{0};
    return std::unexpected(m.error());
  }
  return m->body.end();
}

std::optional<std::size_t> declared_stream_length(std::string_view data) {
  const auto line = first_line(data);
  if (!line || !(is_status_line(*line) || is_request_line(*line))) return std::nullopt;
  auto block = parse_header_block(data, line->size() + 2, true);
  if (!block) return std::nullopt;
  std::optional<std::size_t> n;
  for (const auto& h : block->headers) {
    const auto name = data.substr(h.name.off, h.name.len);
    if (!iequal(name, "Content-Length") && !iequal(name, "l")) continue;
    const std::string_view v = h.unfolded;
    if (v.empty() || v.size() > 10 ||
        !std::all_of(v.begin(), v.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      return std::nullopt;
    }
    std::size_t x = 0;
    for (char c : v) x = x * 10 + static_cast<std::size_t>(c - '0');
    if (n && *n != x) return std::nullopt;
    n = x;
  }
  if (!n) return std::nullopt;
  return block->end + *n;
}

}  // namespace mcxanon::sip
