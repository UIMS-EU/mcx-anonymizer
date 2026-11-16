// SPDX-License-Identifier: GPL-3.0-or-later
//
// HTTP/1.1 message heads (RFC 9112 §2-§5): the start line and the field lines up to the empty
// line, validated strictly (CRLF line ends, no obs-fold, token field names, bounded), and the
// message body length rules of RFC 9112 §6.3. Views into the caller's buffer.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::http {

struct Field {
  std::string_view name;
  std::string_view value;  // without surrounding whitespace (RFC 9110 §5.5)
};

struct Head {
  bool request = false;
  std::string_view method;   // request
  std::string_view target;   // request
  std::string_view version;  // "HTTP/1.1"
  int status = 0;            // response
  std::vector<Field> fields;
  std::size_t length = 0;    // bytes up to and including the empty line
};

enum class Parse { more, ok, bad };

// A request or status line of HTTP/1.x at the front of `b`; nullopt when more bytes are needed.
std::optional<bool> is_start(std::string_view b);
// The HTTP/2 connection preface (RFC 9113 §3.4) at the front of `b`; nullopt when more is needed.
std::optional<bool> is_preface(std::string_view b);
inline constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

Parse parse_head(std::string_view b, Head& out);

// RFC 9110 §5.6.2 token.
bool is_token(std::string_view s);
bool iequal(std::string_view a, std::string_view b);
std::string lower(std::string_view s);

// All values of a field, comma lists joined (RFC 9110 §5.3).
std::vector<std::string_view> values_of(const Head& h, std::string_view name);
const Field* find(const Head& h, std::string_view name);

// RFC 9112 §6.3: the framing of the body that follows a head. `request_method` is
// the method of the request a response answers, empty when unknown.
struct BodyPlan {
  enum class Kind { none, length, chunked, to_close, bad } kind = Kind::none;
  std::uint64_t length = 0;
  bool connect_tunnel = false;  // a 2xx answer to CONNECT
};
BodyPlan plan_body(const Head& h, std::string_view request_method);

// Chunked transfer coding (RFC 9112 §7.1). One chunk at the front of `b`.
struct Chunk {
  enum class Kind { more, data, last, bad } kind = Kind::more;
  std::size_t line = 0;      // the chunk-size line incl. CRLF
  std::uint64_t size = 0;    // data octets (data)
  std::size_t total = 0;     // last: the last-chunk line, trailer section and final CRLF
};
Chunk chunk_at(std::string_view b);

// The whole chunked body at the front of `b` when it is complete within `limit` octets: the
// decoded data and the encoded length.
struct Dechunked {
  enum class Kind { more, done, bad, over } kind = Kind::more;
  std::string data;
  std::size_t encoded = 0;
};
Dechunked dechunk(std::string_view b, std::size_t limit);

// The reason phrase of RFC 9110 §15 for a status code, empty for codes it does not define.
std::string_view reason_phrase(int code);

}  // namespace mcxanon::http
