// SPDX-License-Identifier: GPL-3.0-or-later
//
// SIP message framing and header section parser (RFC 3261 §7, §18.3, §25).
// The model's spans point into the input bytes; nothing is copied except the unfolded value of
// each header field.
#pragma once

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::sip {

struct Span {
  std::size_t off = 0;
  std::size_t len = 0;
  [[nodiscard]] std::size_t end() const { return off + len; }
};

enum class MessageKind { request, response };
enum class Transport { datagram, stream };

struct HeaderField {
  Span name;             // as written: full or compact form, any letter case
  Span value;            // after HCOLON and leading whitespace, up to the final CRLF (folding kept)
  Span line;             // the whole field, continuation lines and final CRLF included
  std::string unfolded;  // value with each CRLF + whitespace run folded to one SP (§7.3.1)
};

struct SipMessage {
  MessageKind kind = MessageKind::request;
  Span start_line;  // without its CRLF
  Span method;
  Span request_uri;
  int status_code = 0;
  Span reason;
  std::vector<HeaderField> headers;  // input order
  std::size_t header_end = 0;        // first byte after the empty line
  std::optional<std::size_t> content_length;
  Span body;
  Span trailing;  // datagram bytes after the body (§18.3: discarded)
};

enum class Failure {
  not_sip,     // the bytes do not start with a SIP start line
  malformed,   // a SIP start line, but framing or a bound failed
  incomplete,  // stream: more bytes are needed
};

struct ParseError {
  Failure kind = Failure::malformed;
  std::string reason;  // fixed English text, never input bytes
};

// A header section starting at `pos` (field lines, continuation lines, ended by an empty line).
// `end` is the offset after the empty line. With `stream`, running out of bytes is
// Failure::incomplete rather than malformed.
struct HeaderBlock {
  std::vector<HeaderField> headers;
  std::size_t end = 0;
};
std::expected<HeaderBlock, ParseError> parse_header_block(std::string_view data, std::size_t pos,
                                                          bool stream = false);

// Recognition: a request line `Method SP Request-URI SP SIP/2.0 CRLF` (§7.1) or a
// status line `SIP/2.0 SP 3DIGIT SP Reason-Phrase CRLF` (§7.2) at the start of `data`.
bool is_start_line(std::string_view data);

// Parses one message at the start of `data`. On a datagram the message ends at the datagram's
// end; on a stream it ends after Content-Length bytes of body (required, §18.3).
std::expected<SipMessage, ParseError> parse_message(std::string_view data, Transport transport);

// Stream framing: the length of the complete message at the start of `data`, or 0 when more
// bytes are needed. An error means the bytes cannot be framed as SIP.
std::expected<std::size_t, ParseError> frame_stream(std::string_view data);

// The length a message at the start of `data` declares (header block plus Content-Length), once
// its header block is complete, whatever its size; nullopt when it declares none. Lets a stream
// skip exactly one oversized message instead of searching for the next start line.
std::optional<std::size_t> declared_stream_length(std::string_view data);

}  // namespace mcxanon::sip
