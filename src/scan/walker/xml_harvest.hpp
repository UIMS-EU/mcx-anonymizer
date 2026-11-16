// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's own XML harvester (feature 003, FR-019): a lenient tokenizer that
// finds the XML bodies of a SIP payload (a body starts after a blank line with '<', or at an XML
// declaration) and returns the values worth searching for: every attribute value, text value,
// CDATA section, comment, processing instruction and DTD literal, in raw and unescaped form,
// every namespace name and, in tag form ("<name", ":name>"), every element name that is not in
// the XML vocabulary (attribute names are not harvested; proposal N2). Values
// equal to or contained in the vocabulary, decimal numbers of fewer than 7 digits, booleans and
// XSD date, time and duration forms are not returned (P7). It shares no code with src/xml/
// and never fails: malformed markup is read as far as it goes.
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::scan::detail {

// With `embedded`, the URL-decoded `body` URI headers of the URIs found in values are appended
// to it (resource-lists entry URIs, R12 item 4); the caller harvests them once more.
// With `cut` (TCP: the text ends at a segment boundary), a value, comment, CDATA section or tag
// that runs to the end of the text is not harvested: it may be partial ("fals" of "false"), and
// the next segment, which carries the tail of this one, sees it whole.
std::vector<std::string> harvest_xml(std::string_view text, std::vector<std::string>* embedded = nullptr,
                                     bool cut = false);

}  // namespace mcxanon::scan::detail
