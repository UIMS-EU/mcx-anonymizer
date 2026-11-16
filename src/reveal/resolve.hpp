// SPDX-License-Identifier: GPL-3.0-or-later
//
// The resolver (FR-012, FR-013, FR-015, FR-015a, FR-016, FR-017a): merges
// candidates of the same source span, drops the not-searchable ones, keeps the longest of
// overlapping candidates and classifies the rest.
#pragma once

#include "mcxanon/reveal.hpp"

#include "reveal/candidate.hpp"

#include <string>
#include <vector>

namespace mcxanon::reveal {

struct Match {
  Candidate cand;      // merged; hits sorted by (category name, original), duplicates removed
  RevealKind kind = RevealKind::revealed;
  std::string ambiguity;  // as in RevealCandidate
  std::string category;   // "a|b" for several categories
  bool replace = false;   // the original is written (revealed, or ambiguous with --replace-ambiguous)
};

// `cands` are in source coordinates. Only candidates starting before `accept_before` are
// returned; later ones only compete. The result is sorted by source start.
std::vector<Match> resolve(std::vector<Candidate> cands, std::size_t accept_before, const Index& index,
                           const RevealOptions& options);

}  // namespace mcxanon::reveal
