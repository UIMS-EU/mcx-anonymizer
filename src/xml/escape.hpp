// SPDX-License-Identifier: GPL-3.0-or-later
//
// XML references and escaping (FR-011): only the five predefined entities and
// decimal or hexadecimal character references whose value is an XML Char (XML 1.0 [2], [66],
// [68]). Values are unescaped before they are classified or pseudonymised, and a replacement
// is escaped for the position it is written to.
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

// The unescaped text of raw character data or of a raw attribute value. For an attribute
// value, literal tab, CR and LF become spaces (XML 1.0 §3.3.3; CR LF counts once). nullopt when
// a reference is not one of the recognised forms, or a character reference is not a Char.
std::optional<std::string> unescape(std::string_view raw, bool attribute);

// Character data: '&', '<' and '>' escaped (the last one so that "]]>" cannot appear).
std::string escape_text(std::string_view text);

// An attribute value delimited by `quote` ('"' or '\''): '&', '<', the quote character, and tab,
// CR and LF (as character references, so that normalisation keeps them) escaped.
std::string escape_attr(std::string_view text, char quote);

// True when `cp` is an XML 1.0 Char ([2]).
bool is_xml_char(char32_t cp);

}  // namespace mcxanon::xml
