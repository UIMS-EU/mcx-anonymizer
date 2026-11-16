// SPDX-License-Identifier: GPL-3.0-or-later
//
// Counters of the XML layer. Keys are
// namespace names and local names as they appear in the input; the report applies the 002
// report-name redaction to names without rules.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <tuple>

namespace mcxanon::xml {

struct Counters {
  using Actions = std::map<std::string, std::uint64_t>;
  std::map<std::string, Actions> bodies;                                  // Content-Type -> outcome -> n
  std::map<std::pair<std::string, std::string>, Actions> elements;        // (ns, local) -> action -> n
  std::map<std::tuple<std::string, std::string, std::string, std::string>, Actions> attributes;  // (ns, element, attr ns, attr)
  std::map<std::string, std::uint64_t> removed_namespaces;                // namespace without rules -> n
  std::uint64_t comments = 0;
  std::uint64_t processing_instructions = 0;
  std::uint64_t encrypted = 0;                                            // xenc:EncryptedData subtrees
  // Feature 005 (FR-016, FR-017): EncryptedData kept by the rules, copied in passthrough mode, and
  // the elements and attributes removed inside kept ones.
  std::uint64_t encrypted_kept = 0;
  std::uint64_t encrypted_passed_through = 0;
  std::uint64_t encrypted_removed_parts = 0;
  Actions embedded;                                                       // outcome -> n
  // Feature 008 (FR-004): declarations whose non-standard prefix was renamed, by namespace name.
  std::map<std::string, std::uint64_t> prefixes_rewritten;

  void merge(const Counters& o) {
    for (const auto& [k, m] : o.bodies) for (const auto& [a, n] : m) bodies[k][a] += n;
    for (const auto& [k, m] : o.elements) for (const auto& [a, n] : m) elements[k][a] += n;
    for (const auto& [k, m] : o.attributes) for (const auto& [a, n] : m) attributes[k][a] += n;
    for (const auto& [k, n] : o.removed_namespaces) removed_namespaces[k] += n;
    comments += o.comments;
    processing_instructions += o.processing_instructions;
    encrypted += o.encrypted;
    encrypted_kept += o.encrypted_kept;
    encrypted_passed_through += o.encrypted_passed_through;
    encrypted_removed_parts += o.encrypted_removed_parts;
    for (const auto& [a, n] : o.embedded) embedded[a] += n;
    for (const auto& [k, n] : o.prefixes_rewritten) prefixes_rewritten[k] += n;
  }
};

}  // namespace mcxanon::xml
