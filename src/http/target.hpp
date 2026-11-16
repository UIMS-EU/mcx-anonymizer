// SPDX-License-Identifier: GPL-3.0-or-later
//
// Request targets, URI references and identity values of HTTP (feature 007).
// Every function returns the rewritten text, or nullopt when the value does not fit (the caller
// removes it and counts it malformed). Errors are tool failures.
#pragma once

#include "mcxanon/error.hpp"

#include "http/env.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::http {

using Opt = Result<std::optional<std::string>>;

// R9: a value naming a user, a client or a server outside a URI grammar position: SIP/tel URI ->
// the 002 URI mapping; instance URN -> the 002 instance mapping; http(s) URL -> rewrite_uri_ref;
// user@host -> sip-user@domain; a domain name -> the domain mapping; anything else -> opaque.
Opt rewrite_identity(std::string_view value, Env& env);

// A URI reference (Location, redirect_uri, iss, aud): an absolute http(s) URL (userinfo removed as
// a credential, host mapped, path by rewrite_path, query by the parameter rules, fragment opaque),
// a SIP, tel or instance URI, or a path reference.
Opt rewrite_uri_ref(std::string_view value, Env& env);

// RFC 9112 §3.2: origin-form, absolute-form, authority-form (CONNECT) and asterisk-form.
Opt rewrite_target(std::string_view target, std::string_view method, Env& env);

// An absolute path: an XCAP selector when a segment is a known AUID (003 E.7.4), otherwise each
// segment kept when it is a listed path segment (TS 33.180 §D.2), mapped as an identity when it
// decodes to one, or opaque. Octets escaped in the input stay escaped.
Opt rewrite_path(std::string_view path, Env& env);

// host [":" port] (RFC 9110 §7.2): the host by the 002 host mapping, the port kept.
Opt rewrite_authority(std::string_view authority, Env& env);

// An opaque pseudonym (length and character classes kept). Values of 1-3 characters made of
// letters, digits, ".", "_" and "-" are kept as written: they are below the
// scanner's 4-octet token threshold, and an opaque pseudonym of that length collides with other
// originals of the project.
Opt opaque_text(std::string_view value, Env& env);

// Percent-decoding (nullopt on a bad escape) and the escaping used for rewritten segments.
std::optional<std::string> percent_decode(std::string_view s);
std::string percent_encode(std::string_view s, std::string_view also_escape = {});

}  // namespace mcxanon::http
