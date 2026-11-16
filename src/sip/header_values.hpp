// SPDX-License-Identifier: GPL-3.0-or-later
//
// Parsers for the closed set of header value grammars of the SIP rule set (contracts of
// feature 002, "Grammars"). Each parser validates the whole value and returns a structure
// that the rewriter renders back; a value that does not parse is malformed (FR-029).
#pragma once

#include "sip/uri.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::sip {

// Splits a comma-separated header value at commas outside quoted strings, angle brackets and
// comments; nullopt on an empty element or an unbalanced quote, bracket or comment.
std::optional<std::vector<std::string_view>> split_list(std::string_view value);

// name-addr-list, uri-list (also a single name-addr); "*" is a list of one Scheme::other URI
// whose opaque part is "*" (Contact: *, RFC 3261 §20.10).
std::optional<std::vector<NameAddr>> parse_name_addr_list(std::string_view value);

struct Via {
  std::string protocol;  // "SIP/2.0/UDP": name, version and transport tokens
  std::string host;
  HostKind host_kind = HostKind::domain;
  std::optional<std::string> port;
  std::vector<Param> params;
};
std::optional<std::vector<Via>> parse_via(std::string_view value);
std::string render_via(const Via& v);

// RFC 3261 §25.1: callid = word [ "@" word ]
std::optional<std::string> parse_call_id(std::string_view value);

struct CSeq {
  std::string number;
  std::string method;
};
std::optional<CSeq> parse_cseq(std::string_view value);

// A head followed by parameters: tokens (event types, option tags, mechanism names, access
// types, protocols), numbers, media types and session ids.
enum class HeadKind { token, number, media_type, session_id };
struct Item {
  std::string value;  // for a quoted head: the unescaped content
  bool quoted = false;
  std::vector<Param> params;
};
// A token head may also be a quoted-string (P-Visited-Network-ID, RFC 7315 §5.3).
std::optional<std::vector<Item>> parse_items(std::string_view value, HeadKind head, bool multi);
std::string render_item(const Item& item);

// credentials and challenge: auth-scheme LWS auth-param *(COMMA auth-param).
struct AuthValue {
  std::string scheme;
  std::vector<Param> params;
};
std::optional<AuthValue> parse_auth(std::string_view value);
std::string render_auth(const AuthValue& value);

struct Warning {
  std::string code;   // 3DIGIT
  std::string agent;  // hostport or pseudonym token
  std::string text;   // unquoted, unescaped
};
std::optional<std::vector<Warning>> parse_warning(std::string_view value);
std::string render_warning(const Warning& w);

struct RetryAfter {
  std::string seconds;
  std::optional<std::string> comment;  // without its outer parentheses
  std::vector<Param> params;
};
std::optional<RetryAfter> parse_retry_after(std::string_view value);
std::string render_retry_after(const RetryAfter& r);

// rfc1123-date (RFC 3261 §25.1) as seconds since 1970-01-01T00:00:00 GMT.
std::optional<std::int64_t> parse_date(std::string_view value);
std::string render_date(std::int64_t seconds);

}  // namespace mcxanon::sip
