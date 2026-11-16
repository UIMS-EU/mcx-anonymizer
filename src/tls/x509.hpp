// SPDX-License-Identifier: GPL-3.0-or-later
//
// X.509 certificates rewritten in place (RFC 5280; feature 007 FR-022):
// names by attribute type, subject and issuer alternative names,
// authority and CRL access URIs, key identifiers and the serial number pseudonymised; the subject
// public key and the signature zeroed with their lengths and algorithm identifiers kept (RSA and
// EC keys keep a decodable structure); validity, usages, constraints and policy identifiers kept;
// unknown extensions zeroed with their identifier and length kept. Every DER length follows.
#pragma once

#include "mcxanon/error.hpp"

#include "tls/der.hpp"
#include "tls/env.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::tls {

// The rewritten certificate, or nullopt when it does not decode or exceeds a bound (the caller
// zeroes it with its length kept). Errors are tool failures.
Result<std::optional<std::string>> rewrite_certificate(std::string_view der, Env& env);

// A Name (RFC 5280 §4.1.2.4) by the attribute rules, in place.
Result<bool> rewrite_name(der::Node& name, Env& env);

// R9/R20 helpers shared with the handshake code: an identity-shaped text value, a host name, and
// an opaque value (values of 1-3 characters kept).
Result<std::optional<std::string>> map_identity(std::string_view v, Env& env);
Result<std::optional<std::string>> map_opaque(std::string_view v, Env& env);

}  // namespace mcxanon::tls
