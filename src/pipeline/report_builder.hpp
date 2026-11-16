// SPDX-License-Identifier: GPL-3.0-or-later
// Assembles the run report from the request, the rule set and the run summary.
#pragma once

#include "mcxanon/anonymize.hpp"
#include "mcxanon/report.hpp"

#include "pipeline/anonymizer.hpp"
#include "policy/ruleset.hpp"

#include <optional>

namespace mcxanon {

class ReportBuilder {
 public:
  explicit ReportBuilder(const AnonymizeFileRequest& request);
  void input_format(CaptureFormat f) { input_format_ = f; }
  void ruleset(const RuleSet& rs);
  void truncated_tail(std::uint64_t n) { tail_ = n; }
  void scan(Report::Scan s) { scan_ = std::move(s); }
  void deny_entries(std::uint64_t n) { deny_ = n; }
  [[nodiscard]] Report build(const RunSummary* summary, const std::optional<Error>& error) const;

 private:
  const AnonymizeFileRequest& request_;
  std::optional<CaptureFormat> input_format_;
  std::string rs_name_, rs_version_, rs_digest_;
  std::uint64_t tail_ = 0;
  std::uint64_t deny_ = 0;
  Report::Scan scan_;
};

std::string_view result_name(ErrorCode code);

}  // namespace mcxanon
