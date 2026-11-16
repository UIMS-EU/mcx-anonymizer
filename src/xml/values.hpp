// SPDX-License-Identifier: GPL-3.0-or-later
//
// Value types of `keep` rules (FR-008): a kept text or attribute value must match
// its type, so that free text cannot pass through a field documented as an enumeration. Values
// are checked unescaped, with leading and trailing XML whitespace ignored (the XSD `collapse`
// facet); the bytes are kept as written.
#pragma once

#include "policy/xml_rules.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

using mcxanon::XmlTokenGrammar;
using mcxanon::XmlValueType;

using TokenGrammar = XmlTokenGrammar;
using ValueType = XmlValueType;

// True when `value` (unescaped) matches `type`.
bool matches(const ValueType& type, std::string_view value);

// Feature 007: an xs:dateTime moved by `seconds`, written in the input's form (fraction and zone
// kept); nullopt when it is not a dateTime with a four-digit year.
std::optional<std::string> shift_datetime(std::string_view value, std::int64_t seconds);

// Feature 007 (zero action): every character other than whitespace and "=" becomes "0" when the
// text is hexadecimal, "A" otherwise (zero octets in base64).
std::string zero_text(std::string_view value);

// `value` without leading and trailing XML whitespace.
std::string_view trim_xml_space(std::string_view value);

std::optional<TokenGrammar> token_grammar(std::string_view name);

}  // namespace mcxanon::xml
