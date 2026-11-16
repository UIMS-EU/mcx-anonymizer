// SPDX-License-Identifier: GPL-3.0-or-later
//
// Multi-pattern matcher. Every pattern is indexed by its most selective 4-byte
// window (its anchor), not by its first bytes: patterns such as an IPv4 address
// embedded in IPv6 start with ten zero bytes, which would otherwise match at
// every position of a zeroed payload. One bitmap of anchors (shared by both
// sets, with a salted hash for the folded one; 2^16 to 2^27 bits, about 64 bits
// per pattern) rejects almost every position; candidates are verified against a sorted anchor table. Patterns are
// stored in one arena. Two sets: exact and ASCII case-folded.
#pragma once

#include "scan/patterns.hpp"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon::scan::detail {

class Matcher {
 public:
  Matcher() = default;
  explicit Matcher(const std::vector<Pattern>& patterns);
  void reserve(std::size_t exact, std::size_t folded, std::size_t bytes);
  void add(const Pattern& p);
  // Sorts the anchor tables and builds the bitmap; call after the last add().
  void seal();

  [[nodiscard]] std::size_t size() const { return entries_.size(); }
  [[nodiscard]] std::size_t max_len() const { return max_len_; }
  [[nodiscard]] std::uint32_t token(std::size_t i) const { return entries_[i].token; }
  [[nodiscard]] std::size_t length(std::size_t i) const { return entries_[i].len; }
  [[nodiscard]] bool short_binary(std::size_t i) const { return entries_[i].short_binary; }
  [[nodiscard]] std::string_view encoding(std::size_t i) const { return encodings_[entries_[i].encoding]; }

  // Reports every match whose start lies in [0, starts_before) of `data`;
  // `base` is the stream offset of data[0].
  void scan(std::span<const std::uint8_t> data, std::size_t starts_before, std::uint64_t base,
            const std::function<void(std::size_t, std::uint64_t)>& on_match) const;

 private:
  struct Entry {
    std::uint32_t offset = 0;  // into arena_
    std::uint16_t len = 0;
    std::uint16_t anchor = 0;  // offset of the anchor window within the pattern
    std::uint32_t token = 0;
    std::uint8_t encoding = 0;
    bool fold = false;
    bool short_binary = false;
    bool digits = false;
  };
  struct Set {
    std::uint32_t salt = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> by_anchor;  // (anchor word, entry)
  };
  [[nodiscard]] std::uint32_t slot(std::uint32_t w, std::uint32_t salt) const {
    return ((w ^ salt) * 0x9E3779B1u) >> shift_;
  }
  void scan_set(const Set& s, bool fold, std::span<const std::uint8_t> data, std::size_t starts_before,
                std::uint64_t base, const std::function<void(std::size_t, std::uint64_t)>& on_match) const;

  std::vector<std::uint8_t> arena_;
  std::vector<Entry> entries_;
  std::vector<std::string> encodings_;
  std::vector<std::uint64_t> bitmap_;  // built by seal()
  int shift_ = 32;
  Set exact_{0, {}};
  Set folded_{0x5BD1E995u, {}};
  std::size_t max_len_ = 0;
  std::size_t max_anchor_ = 0;
};

// Feeds a stream in chunks; keeps max_len-1 bytes so matches across chunk
// boundaries are found exactly once.
class StreamScanner {
 public:
  explicit StreamScanner(const Matcher& m) : m_(m) {}
  void feed(std::span<const std::uint8_t> chunk, const std::function<void(std::size_t, std::uint64_t)>& on_match);
  void finish(const std::function<void(std::size_t, std::uint64_t)>& on_match);

 private:
  const Matcher& m_;
  std::vector<std::uint8_t> buf_;
  std::uint64_t base_ = 0;
};

}  // namespace mcxanon::scan::detail
