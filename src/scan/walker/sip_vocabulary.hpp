// SPDX-License-Identifier: GPL-3.0-or-later
//
// Standard SIP/SDP vocabulary the output keeps on purpose: header and parameter
// names, media feature tags, ICSI values, SDP attribute names, Content-Types and SIP methods.
// The scanner's own copy, lowercase: a unit test compares it with the names of the SIP rule
// set, without sharing code with it.
#pragma once

#include <span>
#include <string_view>

namespace mcxanon::scan::detail {

std::span<const std::string_view> sip_vocabulary();

// True when `token` is case-insensitively equal to, or contained in, a vocabulary term: such
// a token cannot be searched without blocking every publication, and is reported as
// unscannable with the reason "vocabulary" (FR-032). No hit is ever suppressed.
bool in_sip_vocabulary(std::string_view token);

}  // namespace mcxanon::scan::detail
