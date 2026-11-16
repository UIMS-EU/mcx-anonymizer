// SPDX-License-Identifier: GPL-3.0-or-later
//
// The text the report self-check scans (001 R22, FR-038; amended in feature 003):
// every key and string value of the report,
// one per line, except the `not_anonymised` statements and the words of the report schema
// itself (property names, enumeration values and constants) and the rule set digests. Those are fixed text compiled
// into the tool, so they cannot carry an input value, while a common word harvested from the
// input (a packet comment "location report", an XML element named "status") would match them
// and withhold every report. Names that come from the input are checked one by one before this
// (sanitise_report); a name equal to a schema word is checked there.
#pragma once

#include "mcxanon/report.hpp"

#include <string>
#include <vector>

namespace mcxanon {

// One entry per key and value: they are checked one by one, so no value is formed across the
// boundary of two (an IPv4 address 10.x.x.x is the byte 0x0A followed by three characters).
std::vector<std::string> to_json_for_self_check(const Report& report);

}  // namespace mcxanon
