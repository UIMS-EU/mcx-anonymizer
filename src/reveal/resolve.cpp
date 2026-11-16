// SPDX-License-Identifier: GPL-3.0-or-later
#include "reveal/resolve.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace mcxanon::reveal {
namespace {

std::string category_name(Category c) { return std::string(to_string(c)); }

void merge_into(Candidate& a, Candidate&& b) {
  const bool a_hits = !a.hits.empty(), b_hits = !b.hits.empty();
  if (a_hits && b_hits) {
    a.small_space = a.small_space && b.small_space;
  } else if (b_hits) {
    a.small_space = b.small_space;
  }
  for (auto& h : b.hits) a.hits.push_back(std::move(h));
  for (auto& f : b.forms) a.forms.push_back(std::move(f));
  if (b.shaped && !a.shaped) {
    a.shaped = true;
    a.shape_category = b.shape_category;
  }
  a.inconsistent = a.inconsistent || b.inconsistent;
  if (!a.decoded) return;
  a.decoded = b.decoded;  // prefer the raw view when both produced the span
}

bool overlaps(const Candidate& a, const Candidate& b) { return a.src_start < b.src_end && b.src_start < a.src_end; }

}  // namespace

std::vector<Match> resolve(std::vector<Candidate> cands, std::size_t accept_before, const Index& index,
                           const RevealOptions& options) {
  // 1. Merge candidates of the same span.
  std::map<std::pair<std::size_t, std::size_t>, Candidate> by_span;
  for (auto& c : cands) {
    const auto key = std::make_pair(c.src_start, c.src_end);
    auto it = by_span.find(key);
    if (it == by_span.end()) {
      by_span.emplace(key, std::move(c));
    } else {
      merge_into(it->second, std::move(c));
    }
  }
  std::vector<Candidate> groups;
  groups.reserve(by_span.size());
  for (auto& [k, c] : by_span) {
    if (c.hits.empty() && !c.shaped) continue;
    if (c.src_end - c.src_start <= 3) continue;  // FR-015a: not searched
    // Distinct hits, sorted by category name then original.
    std::sort(c.hits.begin(), c.hits.end(), [](const Hit& x, const Hit& y) {
      const auto nx = category_name(x.category), ny = category_name(y.category);
      return nx != ny ? nx < ny : x.original < y.original;
    });
    c.hits.erase(std::unique(c.hits.begin(), c.hits.end(),
                             [](const Hit& x, const Hit& y) {
                               return x.category == y.category && x.original == y.original;
                             }),
                 c.hits.end());
    groups.push_back(std::move(c));
  }
  // 2. Longest first, then leftmost; known values before unknown shapes of the same span length.
  std::vector<std::size_t> order(groups.size());
  for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::sort(order.begin(), order.end(), [&](std::size_t x, std::size_t y) {
    const auto& a = groups[x];
    const auto& b = groups[y];
    const auto la = a.src_end - a.src_start, lb = b.src_end - b.src_start;
    if (la != lb) return la > lb;
    if (a.hits.empty() != b.hits.empty()) return !a.hits.empty();
    return a.src_start < b.src_start;
  });
  std::vector<std::size_t> accepted;
  std::vector<bool> taken(groups.size(), false);
  for (auto i : order) {
    bool clash = false;
    for (auto j : accepted) {
      if (overlaps(groups[i], groups[j])) {
        clash = true;
        break;
      }
    }
    if (!clash) {
      accepted.push_back(i);
      taken[i] = true;
    }
  }
  // 3. Classify.
  std::vector<Match> out;
  for (auto i : accepted) {
    auto& c = groups[i];
    if (c.src_start >= accept_before) continue;
    Match m;
    std::set<std::string> originals;
    std::set<std::string> names;
    for (const auto& h : c.hits) {
      originals.insert(h.original);
      names.insert(category_name(h.category));
    }
    // An equally long rejected candidate overlapping this one with another original.
    bool rival = false;
    for (std::size_t j = 0; j < groups.size(); ++j) {
      if (taken[j] || groups[j].hits.empty() || !overlaps(groups[j], c)) continue;
      if (groups[j].src_end - groups[j].src_start != c.src_end - c.src_start) continue;
      for (const auto& h : groups[j].hits) {
        if (!originals.contains(h.original)) rival = true;
      }
    }
    if (c.hits.empty()) {
      m.kind = RevealKind::unknown;
      m.category = category_name(c.shape_category);
    } else {
      std::string joined;
      for (const auto& n : names) joined += (joined.empty() ? "" : "|") + n;
      m.category = joined;
      bool also_original = false;
      for (const auto& f : c.forms) also_original = also_original || index.is_original_form(f);
      if (also_original) {
        m.ambiguity = "pseudonym-and-original";
      } else if (originals.size() > 1 || rival || c.inconsistent) {
        m.ambiguity = "overlap";
      } else if (c.small_space) {
        m.ambiguity = "small-space";
      } else if (c.src_end - c.src_start <= 6) {
        m.ambiguity = "short";
      }
      if (m.ambiguity.empty()) {
        m.kind = RevealKind::revealed;
        m.replace = true;
      } else {
        m.kind = RevealKind::ambiguous;
        m.replace = options.replace_ambiguous && m.ambiguity != "pseudonym-and-original";
      }
    }
    m.cand = std::move(c);
    out.push_back(std::move(m));
  }
  std::sort(out.begin(), out.end(), [](const Match& a, const Match& b) { return a.cand.src_start < b.cand.src_start; });
  return out;
}

}  // namespace mcxanon::reveal
