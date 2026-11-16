// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/mapping.hpp"

#include "bytes/hex.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <vector>

namespace mcxanon {

const MappingEntry* Mapping::find(Category c, ByteView original) const {
  const auto it = entries_.find({c, Bytes(original.begin(), original.end())});
  return it == entries_.end() ? nullptr : &it->second;
}

bool Mapping::pseudonym_taken(Category c, ByteView pseudonym) const {
  return by_pseudonym_.contains({c, Bytes(pseudonym.begin(), pseudonym.end())});
}

bool Mapping::is_issued_pseudonym(Category c, ByteView value) const {
  return pseudonyms_by_family_.contains({family_of(c), Bytes(value.begin(), value.end())});
}

bool Mapping::is_known_original(Category c, ByteView value) const {
  return originals_by_family_.contains({family_of(c), Bytes(value.begin(), value.end())});
}

Result<const MappingEntry*> Mapping::insert(MappingEntry e) {
  const auto key = std::make_pair(e.category, e.original);
  if (entries_.contains(key)) {
    return fail(ErrorCode::internal, "mapping entry already exists (mapping is append-only)");
  }
  if (by_pseudonym_.contains({e.category, e.pseudonym})) {
    return fail(ErrorCode::internal, "pseudonym already issued in this category");
  }
  const Family f = family_of(e.category);
  by_pseudonym_[{e.category, e.pseudonym}] = e.original;
  ++pseudonyms_by_family_[{f, e.pseudonym}];
  ++originals_by_family_[{f, e.original}];
  auto [it, inserted] = entries_.emplace(key, std::move(e));
  (void)inserted;
  return &it->second;
}

void Mapping::mark_seen(Category c, ByteView original) {
  const auto it = entries_.find({c, Bytes(original.begin(), original.end())});
  if (it != entries_.end()) ++it->second.runs_seen;
}

namespace {

void append_hex(std::string& out, const Bytes& b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  for (const auto c : b) {
    out += kDigits[c >> 4];
    out += kDigits[c & 15];
  }
}

}  // namespace

// Written directly, without a JSON document of the whole mapping (the document
// and its growing text were the peak of a run's memory). The text is exactly what
// nlohmann::json::dump(2) writes for {"entries": [...], "format": 5}: keys in alphabetical
// order, two-space indent. Category names and hex digits need no JSON escaping.
std::string Mapping::to_json() const {
  std::vector<const MappingEntry*> sorted;
  sorted.reserve(entries_.size());
  for (const auto& [k, v] : entries_) sorted.push_back(&v);
  std::sort(sorted.begin(), sorted.end(), [](const MappingEntry* a, const MappingEntry* b) {
    const auto ca = to_string(a->category);
    const auto cb = to_string(b->category);
    if (ca != cb) return ca < cb;
    return a->original < b->original;
  });
  // Format 2 (feature 002): text categories; originals and pseudonyms stay hex for every
  // category, because a percent-decoded original need not be UTF-8.
  std::size_t size = 64;
  for (const auto* e : sorted) {
    size += 160 + to_string(e->category).size() + 2 * (e->original.size() + e->pseudonym.size());
  }
  std::string out;
  out.reserve(size);
  if (sorted.empty()) {
    out += "{\n  \"entries\": [],\n  \"format\": 5\n}\n";
    return out;
  }
  out += "{\n  \"entries\": [";
  bool first = true;
  for (const auto* e : sorted) {
    out += first ? "\n" : ",\n";
    first = false;
    out += "    {\n      \"category\": \"";
    out += to_string(e->category);
    out += "\",\n      \"counter\": ";
    out += std::to_string(e->counter);
    out += ",\n      \"original\": \"";
    append_hex(out, e->original);
    out += "\",\n      \"pseudonym\": \"";
    append_hex(out, e->pseudonym);
    out += "\",\n      \"runs_seen\": ";
    out += std::to_string(e->runs_seen);
    out += "\n    }";
  }
  out += "\n  ],\n  \"format\": 5\n}\n";
  return out;
}

Result<Mapping> Mapping::from_json(std::string_view text) {
  const auto doc = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  const auto bad = [](const char* what) {
    return fail(ErrorCode::input, std::string("mapping file is corrupt: ") + what);
  };
  if (doc.is_discarded() || !doc.is_object()) return bad("not a JSON object");
  // Formats 1 (feature 001), 2 (feature 002), 3 (feature 004) and 4 (feature 003) load unchanged; the first
  // save writes format 5 (feature 005: the key management categories).
  if (!doc.contains("format") || !doc["format"].is_number_unsigned() || doc["format"] < 1 || doc["format"] > 5) {
    return bad("unsupported format");
  }
  if (!doc.contains("entries") || !doc["entries"].is_array()) return bad("no entries array");
  Mapping m;
  for (const auto& e : doc["entries"]) {
    if (!e.is_object()) return bad("entry is not an object");
    for (const char* k : {"category", "original", "pseudonym"}) {
      if (!e.contains(k) || !e[k].is_string()) return bad("entry field missing");
    }
    for (const char* k : {"counter", "runs_seen"}) {
      if (!e.contains(k) || !e[k].is_number_unsigned()) return bad("entry counter missing");
    }
    auto cat = category_from_string(e["category"].get<std::string>());
    auto orig = from_hex(e["original"].get<std::string>());
    auto pseudo = from_hex(e["pseudonym"].get<std::string>());
    if (!cat || !orig || !pseudo) return bad("entry value invalid");
    const auto counter = e["counter"].get<std::uint64_t>();
    const auto runs = e["runs_seen"].get<std::uint64_t>();
    if (counter > UINT32_MAX || runs > UINT32_MAX) return bad("counter out of range");
    auto ins = m.insert(MappingEntry{*cat, std::move(*orig), std::move(*pseudo),
                                     static_cast<std::uint32_t>(counter),
                                     static_cast<std::uint32_t>(runs)});
    if (!ins) return bad("duplicate entry");
  }
  return m;
}

}  // namespace mcxanon
