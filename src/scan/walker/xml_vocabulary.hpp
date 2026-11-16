// SPDX-License-Identifier: GPL-3.0-or-later
//
// Standard XML vocabulary the output keeps on purpose (feature 003): namespace
// names, local names, enumeration values and standard URI values of the XML rule set. The
// scanner's own copy, case as written (XML names are case-sensitive): a unit test compares it
// with the rule set, without sharing code with it. It grows with each document family.
#pragma once

#include <span>
#include <string_view>

namespace mcxanon::scan::detail {

std::span<const std::string_view> xml_vocabulary();

// True when `value` equals a vocabulary term (exact, case-sensitive).
bool in_xml_vocabulary(std::string_view value);

// True when `value` is case-insensitively equal to, or contained in, a vocabulary term. The
// output keeps those terms (namespace declarations, kept names and values), and the scanner
// searches text case-insensitively, so such a value cannot be searched without blocking every
// publication.
bool within_xml_vocabulary(std::string_view value);

// Local names whose values the XML rules keep although they are not vocabulary: free-form tokens
// (TriggerId, AreaIdentifier, hex counters) and integers whose range exceeds 6 digits (a radio
// frequency, a floor indicator). Their values are in the output on purpose, so the harvester
// does not search for them (proposal N13). Compared with the rule set by a unit test.
std::span<const std::string_view> xml_kept_value_fields();
bool xml_kept_value_field(std::string_view local);

}  // namespace mcxanon::scan::detail
