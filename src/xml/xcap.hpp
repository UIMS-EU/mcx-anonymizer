// SPDX-License-Identifier: GPL-3.0-or-later
//
// XCAP selectors: a document selector
// (AUID / users|global / XUI or group ID / document), optionally absolute (scheme, host, port,
// XCAP root) and optionally followed by "/~~/" and a node selector. Kept: allowlisted AUIDs, the
// tree names, numbered profile names, node steps and operators. Mapped: the XUI and group IDs as
// URIs, quoted node-selector literals by kind, the host as a host, every other segment as
// `opaque`. Octets escaped in the input stay escaped. The node form of patch operations
// (RFC 5261 `sel`) is added with User Story 5.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/xml_rules.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

// Maps one part: (category, decoded value) -> pseudonym, nullopt when it does not fit.
using PartMapper = std::function<Result<std::optional<std::string>>(XmlCategory, std::string_view)>;

// An AUID the selector keeps (§E.7.4 step 3; feature 007 uses it to recognise XCAP request paths).
bool is_known_auid(std::string_view s);

// nullopt when the value cannot be split by the steps of §E.7.4 (malformed).
Result<std::optional<std::string>> rewrite_xcap_selector(std::string_view value, const PartMapper& map);

// E.7.4 step 5: an RFC 5261 patch-operation `sel` (node-selector syntax without percent-encoding):
// steps and operators kept, quoted literals mapped as in a node selector.
Result<std::optional<std::string>> rewrite_xcap_node(std::string_view value, const PartMapper& map);

}  // namespace mcxanon::xml
