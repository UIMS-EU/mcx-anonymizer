// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reveal: maps the pseudonyms of a project that appear in any text (an analyst's findings, a
// tshark export, an AI answer) back to their originals, locally, and looks up single values in
// both directions. Only the project mapping is read; nothing is ever written to the project and
// no pseudonym is ever issued. Every output of this header contains ORIGINAL values.
#pragma once

#include "mcxanon/error.hpp"
#include "mcxanon/project.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

struct RevealOptions {
  bool replace_ambiguous = false;  // also replace small-space, short and overlap candidates
  bool annotate = false;           // write original⟦pseudonym⟧ for every revealed value
};

enum class RevealKind { revealed, ambiguous, unknown };

// An ambiguous or unknown candidate (revealed values are only counted).
struct RevealCandidate {
  RevealKind kind = RevealKind::ambiguous;
  std::string ambiguity;  // "small-space", "short", "overlap", "pseudonym-and-original", or empty
  std::uint64_t line = 0;    // 1-based
  std::uint64_t column = 0;  // 1-based, in bytes
  std::string category;      // as `project show-map` names it; "a|b" for several
  std::string matched;       // the text as it appears in the input
  std::string original;      // the original it would map to; empty for unknown
};

struct RevealSummary {
  std::map<std::string, std::uint64_t> revealed;
  std::map<std::string, std::uint64_t> ambiguous;
  std::map<std::string, std::uint64_t> unknown;
  std::uint64_t not_searchable = 0;  // mapping entries whose pseudonym is 1 to 3 bytes long
  std::uint64_t bytes_in = 0;
  std::uint64_t bytes_out = 0;
  std::vector<RevealCandidate> candidates;  // in input order
};

using RevealSink = std::function<Result<void>(std::span<const std::uint8_t>)>;

class Revealer {
 public:
  // Builds the index from the project's mapping; the project may be closed afterwards.
  static Result<Revealer> create(const Project& project, RevealOptions options = {});

  Revealer(Revealer&&) noexcept;
  Revealer& operator=(Revealer&&) noexcept;
  Revealer(const Revealer&) = delete;
  Revealer& operator=(const Revealer&) = delete;
  ~Revealer();

  // Streams input; the sink receives the output bytes in order. Any chunking of the input
  // gives the same output and summary.
  Result<void> feed(std::span<const std::uint8_t> chunk, const RevealSink& sink);
  Result<void> finish(const RevealSink& sink);
  [[nodiscard]] const RevealSummary& summary() const;

  struct Impl;
  explicit Revealer(std::unique_ptr<Impl> impl);  // used by the library; Impl is opaque

 private:
  std::unique_ptr<Impl> impl_;
};

// A whole text at once.
Result<std::string> reveal_text(const Project& project, std::string_view text, RevealOptions options = {},
                                RevealSummary* summary = nullptr);

struct RevealFileRequest {
  std::optional<std::filesystem::path> input;   // nullopt or "-": stdin
  std::optional<std::filesystem::path> output;  // nullopt or "-": stdout
  std::optional<std::filesystem::path> report_path;
  bool overwrite = false;
  RevealOptions options;
  std::string project_name;  // for the report; filled from the project by the Project overload
};

// Reads the input, writes the output (owner-only file) and the optional JSON report.
// Errors: usage (output is the input, an existing file without `overwrite`), input (unreadable
// input or unwritable output).
Result<RevealSummary> reveal_file(const Project& project, const RevealFileRequest& request);
// The same with a revealer built beforehand, so that the project can be closed before the input
// is read (the project lock is not held while a long input streams).
Result<RevealSummary> reveal_file(Revealer& revealer, const RevealFileRequest& request);

// The JSON report (format 1) of a run.
std::string reveal_report_json(const RevealSummary& summary, std::string_view project_name,
                               const RevealOptions& options);

enum class LookupDirection { to_original, to_pseudonym };

struct LookupResult {
  std::string category;  // as `project show-map` names it, or "composite"
  std::string query;     // the part of the queried value that was resolved
  std::string counterpart;
};

// Empty: not found. With to_pseudonym, a composite resolves only when every identity component
// is known; otherwise the result is empty and `unresolved` (when given) names the missing part.
Result<std::vector<LookupResult>> lookup(const Project& project, std::string_view value, LookupDirection direction,
                                         std::string* unresolved = nullptr);

}  // namespace mcxanon
