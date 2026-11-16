// SPDX-License-Identifier: GPL-3.0-or-later
#include "scan/matcher.hpp"

#include <algorithm>
#include <cstring>

namespace mcxanon::scan::detail {
namespace {

constexpr int kMinBitmapBits = 16;
constexpr int kMaxBitmapBits = 27;

std::uint8_t fold(std::uint8_t c) { return (c >= 'A' && c <= 'Z') ? static_cast<std::uint8_t>(c + 32) : c; }
std::uint32_t word(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
std::uint32_t fword(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(fold(p[0])) << 24) | (static_cast<std::uint32_t>(fold(p[1])) << 16) |
         (static_cast<std::uint32_t>(fold(p[2])) << 8) | fold(p[3]);
}

// The most selective 4-byte window: most distinct byte values, no zero / 0xFF
// bytes if possible, the later window on ties (address tails vary the most).
std::size_t choose_anchor(const std::vector<std::uint8_t>& b) {
  std::size_t best = 0;
  int best_score = -1;
  for (std::size_t i = 0; i + 4 <= b.size(); ++i) {
    int distinct = 0;
    int plain = 0;
    for (std::size_t j = 0; j < 4; ++j) {
      bool seen = false;
      for (std::size_t k = 0; k < j; ++k) seen = seen || b[i + k] == b[i + j];
      distinct += seen ? 0 : 1;
      plain += (b[i + j] != 0x00 && b[i + j] != 0xFF) ? 1 : 0;
    }
    const int score = distinct * 8 + plain * 2;
    if (score >= best_score) {
      best_score = score;
      best = i;
    }
  }
  return best;
}

}  // namespace

Matcher::Matcher(const std::vector<Pattern>& patterns) {
  for (const auto& p : patterns) add(p);
  seal();
}

void Matcher::reserve(std::size_t exact, std::size_t folded, std::size_t bytes) {
  entries_.reserve(exact + folded);
  arena_.reserve(bytes);
  exact_.by_anchor.reserve(exact);
  folded_.by_anchor.reserve(folded);
}

void Matcher::add(const Pattern& p) {
  if (p.bytes.size() < kMinPattern || p.bytes.size() > 0xFFFF) return;
  Entry e;
  e.offset = static_cast<std::uint32_t>(arena_.size());
  e.len = static_cast<std::uint16_t>(p.bytes.size());
  e.token = p.token;
  e.fold = p.fold;
  e.short_binary = p.short_binary;
  e.digits = p.digits;
  auto it = std::find(encodings_.begin(), encodings_.end(), p.encoding);
  if (it == encodings_.end()) {
    encodings_.push_back(p.encoding);
    it = encodings_.end() - 1;
  }
  e.encoding = static_cast<std::uint8_t>(it - encodings_.begin());
  std::vector<std::uint8_t> bytes = p.bytes;
  if (p.fold) {
    for (auto& c : bytes) c = fold(c);
  }
  e.anchor = static_cast<std::uint16_t>(choose_anchor(bytes));
  arena_.insert(arena_.end(), bytes.begin(), bytes.end());
  Set& s = p.fold ? folded_ : exact_;
  const std::uint32_t w = word(bytes.data() + e.anchor);
  s.by_anchor.emplace_back(w, static_cast<std::uint32_t>(entries_.size()));
  entries_.push_back(e);
  max_len_ = std::max<std::size_t>(max_len_, e.len);
  max_anchor_ = std::max<std::size_t>(max_anchor_, e.anchor);
}

void Matcher::seal() {
  std::sort(exact_.by_anchor.begin(), exact_.by_anchor.end());
  std::sort(folded_.by_anchor.begin(), folded_.by_anchor.end());
  exact_.by_anchor.shrink_to_fit();
  folded_.by_anchor.shrink_to_fit();
  const std::size_t n = exact_.by_anchor.size() + folded_.by_anchor.size();
  int bits = kMinBitmapBits;
  while (bits < kMaxBitmapBits && (std::size_t{1} << bits) < n * 64) ++bits;
  shift_ = 32 - bits;
  bitmap_.assign((std::size_t{1} << bits) / 64, 0);
  for (const Set* s : {&exact_, &folded_}) {
    for (const auto& [w, entry] : s->by_anchor) {
      const std::uint32_t k = slot(w, s->salt);
      bitmap_[k >> 6] |= std::uint64_t{1} << (k & 63);
    }
  }
}

void Matcher::scan_set(const Set& s, bool is_fold, std::span<const std::uint8_t> data, std::size_t starts_before,
                       std::uint64_t base, const std::function<void(std::size_t, std::uint64_t)>& on_match) const {
  if (s.by_anchor.empty() || data.size() < kMinPattern) return;
  const std::uint8_t* d = data.data();
  // Without seal() there is no bitmap: every position is then checked (slower, never fewer hits).
  const bool filter = !bitmap_.empty();
  // Anchors of matches starting before `starts_before` lie before starts_before + max_anchor.
  const std::size_t last = std::min(data.size() - kMinPattern + 1, starts_before + max_anchor_);
  for (std::size_t i = 0; i < last; ++i) {
    const std::uint32_t w = is_fold ? fword(d + i) : word(d + i);
    if (filter) {
      const std::uint32_t k = slot(w, s.salt);
      if (((bitmap_[k >> 6] >> (k & 63)) & 1u) == 0) continue;
    }
    auto lo = std::lower_bound(s.by_anchor.begin(), s.by_anchor.end(), std::make_pair(w, std::uint32_t{0}));
    for (; lo != s.by_anchor.end() && lo->first == w; ++lo) {
      const Entry& e = entries_[lo->second];
      if (i < e.anchor) continue;
      const std::size_t start = i - e.anchor;
      if (start >= starts_before || start + e.len > data.size()) continue;
      const std::uint8_t* p = arena_.data() + e.offset;
      bool eq = true;
      if (is_fold) {
        for (std::size_t j = 0; j < e.len && eq; ++j) eq = fold(d[start + j]) == p[j];
      } else {
        eq = std::memcmp(d + start, p, e.len) == 0;
      }
      // A digit-bounded pattern must not touch another digit (number tokens).
      if (eq && e.digits) {
        const auto is_digit = [](std::uint8_t c) { return c >= '0' && c <= '9'; };
        if ((start > 0 && is_digit(d[start - 1])) ||
            (start + e.len < data.size() && is_digit(d[start + e.len]))) {
          eq = false;
        }
      }
      if (eq) on_match(lo->second, base + start);
    }
  }
}

void Matcher::scan(std::span<const std::uint8_t> data, std::size_t starts_before, std::uint64_t base,
                   const std::function<void(std::size_t, std::uint64_t)>& on_match) const {
  scan_set(exact_, false, data, starts_before, base, on_match);
  scan_set(folded_, true, data, starts_before, base, on_match);
}

void StreamScanner::feed(std::span<const std::uint8_t> chunk,
                         const std::function<void(std::size_t, std::uint64_t)>& on_match) {
  const std::size_t keep = m_.max_len() > 0 ? m_.max_len() - 1 : 0;
  buf_.insert(buf_.end(), chunk.begin(), chunk.end());
  // Matches starting in the last `keep` bytes are found in the next round.
  if (buf_.size() <= keep) return;
  const std::size_t starts_before = buf_.size() - keep;
  m_.scan(buf_, starts_before, base_, on_match);
  buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(starts_before));
  base_ += starts_before;
}

void StreamScanner::finish(const std::function<void(std::size_t, std::uint64_t)>& on_match) {
  m_.scan(buf_, buf_.size(), base_, on_match);
  base_ += buf_.size();
  buf_.clear();
}

}  // namespace mcxanon::scan::detail
