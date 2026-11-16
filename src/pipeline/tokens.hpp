// SPDX-License-Identifier: GPL-3.0-or-later
// Scan tokens assembled by the pipeline (FR-031): mapping originals, values the
// anonymiser removed, deny-list entries; plus the report self-check (R22).
#pragma once

#include "mcxanon/report.hpp"
#include "mcxanon/scan.hpp"

#include "pseudo/hmac.hpp"
#include "pseudo/mapping.hpp"
#include "rewrite/pcapng_meta.hpp"

#include <string>
#include <vector>

namespace mcxanon {

std::vector<scan::Token> mapping_tokens(const Mapping& mapping);
// The text pseudonyms of the mapping, as written into captures: a text-encoded match of a
// 4-byte token inside one of them is a chance match (FR-032a).
std::vector<std::string> mapping_pseudonyms(const Mapping& mapping);
// Feature 007 (D21): the byte-string pseudonyms (nonce, uid) of 8 octets or more, as raw octets.
std::vector<std::string> mapping_byte_pseudonyms(const Mapping& mapping);
std::vector<scan::Token> removed_tokens(const std::vector<RemovedValue>& removed);
std::vector<scan::Token> secret_tokens(const Secret& secret);
Report::Scan to_report_scan(const scan::ScanResult& r);

// Replaces file names in the report that contain a token by "(redacted)", then
// checks the serialised report: true when it is free of every token.
bool sanitise_report(Report& report, const scan::Index& index);

}  // namespace mcxanon
