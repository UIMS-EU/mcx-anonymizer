// SPDX-License-Identifier: GPL-3.0-or-later
//
// The mapping categories an XML rule can name,
// mapped with the SIP layer's mappings so that one identity has one pseudonym in SIP headers,
// XML bodies, SDP and floor control (FR-013, SC-003). Composite categories split a value and
// map its parts; each story adds the composites it needs.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/xml_rules.hpp"
#include "sip/value_map.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

// The pseudonym of `value` in its own text form; nullopt when the value does not fit the
// category (the caller removes it and counts it malformed). Errors are tool failures.
Result<std::optional<std::string>> map_category(XmlCategory category, std::string_view value, sip::Context& ctx);

}  // namespace mcxanon::xml
