// SPDX-License-Identifier: GPL-3.0-or-later
//
// Persistent, append-only mapping from originals to pseudonyms, per category.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "pseudo/category.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace mcxanon {

struct MappingEntry {
  Category category = Category::mac;
  Bytes original;
  Bytes pseudonym;
  std::uint32_t counter = 0;    // HMAC counter used to resolve collisions
  std::uint32_t runs_seen = 0;  // informational
};

class Mapping {
 public:
  [[nodiscard]] const MappingEntry* find(Category c, ByteView original) const;
  [[nodiscard]] bool pseudonym_taken(Category c, ByteView pseudonym) const;
  // True when `value` is a pseudonym issued in any category of c's family.
  [[nodiscard]] bool is_issued_pseudonym(Category c, ByteView value) const;
  // True when `value` is an original of any category of c's family.
  [[nodiscard]] bool is_known_original(Category c, ByteView value) const;
  // Append-only: an existing original, or a pseudonym already issued in the
  // category, is a defect (ErrorCode::internal).
  Result<const MappingEntry*> insert(MappingEntry e);
  void mark_seen(Category c, ByteView original);
  [[nodiscard]] std::size_t size() const { return entries_.size(); }
  [[nodiscard]] const std::map<std::pair<Category, Bytes>, MappingEntry>& entries() const {
    return entries_;
  }

  // Deterministic JSON: entries sorted by
  // (category name, original).
  [[nodiscard]] std::string to_json() const;
  static Result<Mapping> from_json(std::string_view text);

 private:
  std::map<std::pair<Category, Bytes>, MappingEntry> entries_;
  std::map<std::pair<Category, Bytes>, Bytes> by_pseudonym_;          // (category, pseudonym)
  std::map<std::pair<Family, Bytes>, int> pseudonyms_by_family_;       // count
  std::map<std::pair<Family, Bytes>, int> originals_by_family_;        // count
};

}  // namespace mcxanon
