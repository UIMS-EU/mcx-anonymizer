// SPDX-License-Identifier: GPL-3.0-or-later
//
// The rule-driven, byte-range rewriter of one XML body. The output is the input with edits applied: whole elements, attributes,
// comments and processing instructions removed, or values replaced. Every byte outside an edit
// is the input's byte (FR-010), and whole-item edits keep the document well-formed.
#pragma once

#include "mcxanon/error.hpp"

#include "policy/xml_rules.hpp"
#include "xml/counters.hpp"
#include "xml/limits.hpp"
#include "xml/reader.hpp"

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon::xml {

// Why a whole body is emptied (FR-003, FR-004, FR-007, P1).
enum class EmptyReason : std::uint8_t { malformed, encoding, limit, dtd, root, encrypted };

std::string_view to_string(EmptyReason r);

struct Outcome {
  bool rewritten = false;
  std::string bytes;                       // the rewritten body (rewritten only)
  EmptyReason reason = EmptyReason::malformed;  // why it was emptied (not rewritten)
};

// Maps values for the rewriter; implemented over the SIP layer's mappings in the pipeline and
// by fakes in tests.
class ValueMapper {
 public:
  virtual ~ValueMapper() = default;
  // The pseudonym of the unescaped `value` under `category`, unescaped; nullopt when the value
  // does not fit the category (the caller removes it and counts it malformed). Errors are tool
  // failures (a pseudonym collision).
  virtual Result<std::optional<std::string>> map(XmlCategory category, std::string_view value) = 0;
  // A value removed by a rule: kept in memory as a scan token (FR-015, FR-017).
  virtual void removed(std::string_view value) = 0;
  // An attribute whose rule embeds a body (resource-lists entry@uri, FR-014a). The default maps
  // it as a plain URI.
  virtual Result<std::optional<std::string>> map_embedding(XmlCategory category, std::string_view value,
                                                           std::size_t depth) {
    (void)depth;
    return map(category, value);
  }
};

struct RewriteOptions {
  bool verify = false;       // re-read every output (tests and fuzzing)
  bool passthrough = false;  // feature 005: --encrypted passthrough copies EncryptedData as it is
  std::int64_t time_shift_s = 0;  // feature 007: datetime-shifted values (KMS times, FR-015)
};

class BodyRewriter {
 public:
  BodyRewriter(const XmlRuleSet& rules, Counters& counters, RewriteOptions options = {})
      : rules_(rules), counters_(counters), options_(options) {}

  // `depth` is the embedding depth (0 for a SIP body or multipart part, 1 inside an entry URI).
  Result<Outcome> rewrite(std::string_view content_type, std::string_view charset, std::string_view body,
                          ValueMapper& mapper, std::size_t depth = 0);

 private:
  const XmlRuleSet& rules_;
  Counters& counters_;
  RewriteOptions options_;
  std::array<Reader, kMaxEmbedDepth + 1> readers_;
  Reader verify_reader_;
};

}  // namespace mcxanon::xml
