// SPDX-License-Identifier: GPL-3.0-or-later
//
// The reveal index: built once from a read-only view of the project
// mapping. It holds a reverse index (family, pseudonym) -> entries, the originals by family for
// `lookup --original`, the normalised text forms of every original (for the
// pseudonym-and-original ambiguity), and the exact-string patterns of the text categories for
// the scanner's multi-pattern matcher.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "pseudo/category.hpp"
#include "pseudo/mapping.hpp"
#include "scan/matcher.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mcxanon::reveal {

struct Entry {
  Category category = Category::mac;
  Bytes original;
  Bytes pseudonym;
};

enum class Escape : std::uint8_t { none, percent, xml };

// One exact-string pattern: the pseudonym of `entry`, possibly written with an escape scheme.
// How a matched pseudonym is written, so the original is written the same way (feature 005: the
// byte categories nonce and uid appear as hex, uid also as base64).
enum class PatternForm { text, hex, base64 };

struct PatternInfo {
  std::uint32_t entry = 0;
  Escape escape = Escape::none;
  PatternForm form = PatternForm::text;
};

// A text category whose pseudonym is searched as an exact string: every text
// category except the ones a recogniser handles (domain chains, telephone numbers, IMEIs and
// SDP session ids, which are digit strings).
bool exact_searchable(Category c);
// Case-insensitive pseudonyms: lowercase hex by construction or canonicalised to lowercase.
// sip_user is excluded (an RFC 3261 user part is case-sensitive).
bool folded(Category c);
// Small value-space categories (FR-015).
bool small_space(Category c);
// A text category (as opposed to an address or a binary value category).
bool is_text(Category c);

std::string lower(std::string_view s);
std::string as_string(ByteView b);

class Index {
 public:
  static Result<Index> build(const Mapping& mapping);

  [[nodiscard]] const std::vector<Entry>& entries() const { return entries_; }
  [[nodiscard]] const Entry& entry(std::uint32_t i) const { return entries_[i]; }

  // Entry indices whose pseudonym (respectively original) in `family` equals `key` (the
  // canonical bytes; lowercase for folded text categories).
  [[nodiscard]] std::span<const std::uint32_t> by_pseudonym(Family f, ByteView key) const;
  [[nodiscard]] std::span<const std::uint32_t> by_original(Family f, ByteView key) const;
  [[nodiscard]] std::span<const std::uint32_t> by_pseudonym(Family f, std::string_view key) const;
  [[nodiscard]] std::span<const std::uint32_t> by_original(Family f, std::string_view key) const;

  // True when the normalised text (see normalise_forms) is the text form of an original.
  [[nodiscard]] bool is_original_form(std::string_view normalised) const;

  [[nodiscard]] const scan::detail::Matcher& matcher() const { return matcher_; }
  [[nodiscard]] const PatternInfo& pattern(std::uint32_t token) const { return patterns_[token]; }
  [[nodiscard]] std::size_t max_pattern() const { return max_pattern_; }
  [[nodiscard]] std::uint64_t not_searchable() const { return not_searchable_; }

 private:
  static std::string key(Family f, ByteView b);
  std::vector<Entry> entries_;
  std::unordered_map<std::string, std::vector<std::uint32_t>> by_pseudonym_;
  std::unordered_map<std::string, std::vector<std::uint32_t>> by_original_;
  std::unordered_set<std::string> original_forms_;
  std::vector<PatternInfo> patterns_;
  scan::detail::Matcher matcher_;
  std::size_t max_pattern_ = 0;
  std::uint64_t not_searchable_ = 0;
};

// The normalised forms of a value, used for the pseudonym-and-original check: lowercase text;
// for addresses their canonical text (dotted IPv4, RFC 5952 IPv6, colon MAC); for binary
// values decimal and lowercase hex without padding.
std::vector<std::string> original_forms(const Entry& e);

// Text forms of a value of a category as `project show-map` prints them, but with the raw bytes
// of text categories (no escaping).
std::string text_form(Category c, ByteView b);

}  // namespace mcxanon::reveal
