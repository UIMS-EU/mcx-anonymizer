// SPDX-License-Identifier: GPL-3.0-or-later
//
// SDP parser and rule-driven rewriter (RFC 8866 §5, §6). Lines are handled one by
// one with the allowlist of rules/sdp.yaml; every line without a rule is removed and counted.
#pragma once

#include "sip/value_map.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::sip {

// The rewritten SDP body, with the line ends of the input; nullopt when the SDP is malformed
// (the SIP message is then malformed, FR-029). Errors are tool failures.
Result<std::optional<std::string>> rewrite_sdp(std::string_view body, Context& ctx);

// The pseudonym of a CNAME (RFC 3550 §6.5.1, RFC 5576 §6.1) as a=ssrc cname gets it: "user@host"
// and "host" use their own mappings, anything else the cname category. Used for RTCP SDES CNAME
// items (feature 004, FR-010), so that both carry the same pseudonym. nullopt when it cannot be
// mapped.
Result<std::optional<std::string>> map_cname(std::string_view value, Context& ctx);

// The pseudonym of one MSRP URI as a=path gets it (host, port policy, session-id, user), for the
// To-Path and From-Path headers of MSRP (feature 004, FR-027). nullopt when it cannot be mapped.
Result<std::optional<std::string>> map_msrp_uri(std::string_view uri, Context& ctx);

}  // namespace mcxanon::sip
