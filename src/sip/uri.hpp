// SPDX-License-Identifier: GPL-3.0-or-later
//
// SIP, SIPS and tel URIs (RFC 3261 §19.1, §25.1; RFC 3966 §3) and name-addr / addr-spec with
// header parameters (RFC 3261 §20.10, §25.1). Parsing validates every character against the
// grammar; rendering writes the structure back, so nothing unvalidated is copied.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::sip {

// A `;name[=value]` parameter. For a quoted value, `value` holds the unescaped content.
struct Param {
  std::string name;  // as written
  std::optional<std::string> value;
  bool quoted = false;
};

enum class Scheme { sip, sips, tel, other };
enum class HostKind { domain, ipv4, ipv6 };

struct Uri {
  Scheme kind = Scheme::other;
  std::string scheme;               // as written
  std::optional<std::string> user;  // as written (escaped); for tel: the number
  bool had_password = false;        // the password itself is never stored (FR-009: removed)
  std::string host;                 // as written; an IPv6 reference with its brackets
  HostKind host_kind = HostKind::domain;
  std::optional<std::string> port;
  std::vector<Param> params;
  std::optional<std::string> headers;  // after "?", as written
  std::string opaque;                  // Scheme::other: everything after "scheme:"
};

std::optional<Uri> parse_uri(std::string_view text);
// Writes scheme, user, host, port, parameters and headers; never a password.
std::string render_uri(const Uri& uri);

// RFC 3986 §2.1 percent-decoding; an incomplete escape is kept as written.
std::string percent_decode(std::string_view text);

struct NameAddr {
  std::optional<std::string> display;  // unquoted, unescaped; token sequences joined by one SP
  bool display_quoted = false;
  bool angle = false;  // name-addr ("<...>") rather than addr-spec
  Uri uri;
  std::vector<Param> params;  // header parameters after the URI
};

std::optional<NameAddr> parse_name_addr(std::string_view text);
std::string render_name_addr(const NameAddr& value);

// Shared by the header value parsers.
// Parses `*( SEMI generic-param )` (RFC 3261 §25.1) from `text`, which must be empty or start
// with ';' (surrounding whitespace allowed). gen-value = token / host / quoted-string.
std::optional<std::vector<Param>> parse_params(std::string_view text);
std::string render_params(const std::vector<Param>& params);
std::string quote(std::string_view text);  // DQUOTE + quoted-pair escapes + DQUOTE
bool is_token(std::string_view s);          // RFC 3261 §25.1 token
std::string_view trim_lws(std::string_view s);

}  // namespace mcxanon::sip
