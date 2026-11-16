// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/anonymize.hpp"
#include "mcxanon/version.hpp"

#include "pipeline/tokens.hpp"
#include "pseudo/atomic_file.hpp"
#include "pseudo/project_impl.hpp"

#include <iterator>
#include <optional>

namespace mcxanon {

Result<Report> scan_capture(Project& project, const ScanFileRequest& request) {
  Report r;
  r.command = "scan";
  r.tool_version = std::string(tool_version);
  r.ruleset_name = std::string(ruleset_name);
  r.ruleset_version = std::string(ruleset_version);
  r.ruleset_digest = std::string(ruleset_digest);
  r.files.input = request.file.string();
  r.options.encrypted = request.encrypted == EncryptedMode::passthrough ? "passthrough" : "ciphertext";
  const auto report_path = request.report_path
                               ? *request.report_path
                               : std::filesystem::path(request.file.string() + ".scan.json");
  // The project secret is searched too: it must never appear anywhere.
  std::vector<scan::Token> tokens = secret_tokens(project.impl().secret);
  {
    auto m = mapping_tokens(project.impl().mapping);
    tokens.insert(tokens.end(), std::make_move_iterator(m.begin()), std::make_move_iterator(m.end()));
  }
  std::optional<scan::Index> index;  // built once, shared by the scan and the report check
  const auto finish = [&](const std::optional<Error>& e) -> Result<Report> {
    if (e) {
      r.status.exit_code = static_cast<int>(e->code);
      r.status.result = e->code == ErrorCode::leak ? "leak_found"
                        : e->code == ErrorCode::usage ? "usage_error" : "input_error";
      r.status.message = e->message;
    } else {
      r.status.result = "clean";
    }
    if (!index) index.emplace(std::move(tokens), mapping_pseudonyms(project.impl().mapping), mapping_byte_pseudonyms(project.impl().mapping));
    if (!sanitise_report(r, *index)) {
      Report minimal;
      minimal.command = "scan";
      minimal.files.input = "(redacted)";
      minimal.status = {70, "internal_failure", "the report would contain a sensitive value; withheld"};
      (void)atomic_write(report_path, to_json(minimal));
      return fail(ErrorCode::internal, "the report would contain a sensitive value");
    }
    (void)atomic_write(report_path, to_json(r));
    if (e) return std::unexpected(*e);
    return r;
  };
  if (request.deny_list) {
    auto d = scan::load_deny_list(*request.deny_list);
    if (!d) return finish(d.error());
    r.options.deny_list_entries = d->size();
    tokens.insert(tokens.end(), d->begin(), d->end());
  }
  index.emplace(std::move(tokens), mapping_pseudonyms(project.impl().mapping), mapping_byte_pseudonyms(project.impl().mapping));
  auto result = scan::scan_file(request.file, *index,
                                scan::ScanOptions{request.encrypted == EncryptedMode::passthrough});
  if (!result) return finish(result.error());
  r.scan = to_report_scan(*result);
  if (!result->hits.empty()) {
    return finish(Error{ErrorCode::leak, std::to_string(result->hits.size()) + " residual leak(s) found"});
  }
  return finish(std::nullopt);
}

}  // namespace mcxanon
