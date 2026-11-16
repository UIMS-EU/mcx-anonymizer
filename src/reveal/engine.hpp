// SPDX-License-Identifier: GPL-3.0-or-later
//
// Internal entry points of the reveal engine, for the library implementation and the tests.
#pragma once

#include "mcxanon/reveal.hpp"

#include "pseudo/mapping.hpp"
#include "reveal/index.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace mcxanon::reveal {

// The longest match the engine looks for, and the tail it keeps between chunks.
inline constexpr std::size_t kMaxToken = 256;

// `threshold`: how many bytes beyond the tail are buffered before a chunk is processed.
Result<Revealer> make_revealer(const Mapping& mapping, RevealOptions options = {}, std::size_t threshold = 65536);
// The same over an index built once (Index::build), shared by any number of revealers.
Result<Revealer> make_revealer(std::shared_ptr<const Index> index, RevealOptions options = {},
                               std::size_t threshold = 65536);
Result<std::string> reveal_string(const Mapping& mapping, std::string_view text, RevealOptions options = {},
                                  RevealSummary* summary = nullptr);

// The stderr summary, with at most `max_lines` candidate lines.
std::string summary_text(const RevealSummary& summary, std::size_t max_lines = 20);

// Lookup over a mapping (the project-level lookup() opens nothing else).
Result<std::vector<LookupResult>> lookup_mapping(const Mapping& mapping, std::string_view value,
                                                 LookupDirection direction, std::string* unresolved);
// The same over an index built once.
Result<std::vector<LookupResult>> lookup_index(const Index& index, std::string_view value,
                                               LookupDirection direction, std::string* unresolved);

}  // namespace mcxanon::reveal
