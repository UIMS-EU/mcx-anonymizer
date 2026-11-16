// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/anonymize.hpp"
#include "mcxanon/version.hpp"

#include "capture/reader.hpp"
#include "capture/writer.hpp"
#include "pipeline/anonymizer.hpp"
#include "pipeline/output_file.hpp"
#include "pipeline/report_builder.hpp"
#include "pipeline/testing.hpp"
#include "pipeline/tokens.hpp"
#include "pseudo/atomic_file.hpp"
#include "pseudo/fsutil.hpp"
#include "pseudo/project_impl.hpp"

#include <iterator>
#include <optional>

namespace mcxanon {
namespace {

std::filesystem::path report_path_for(const AnonymizeFileRequest& r) {
  if (r.report_path) return *r.report_path;
  return std::filesystem::path(r.output.string() + ".report.json");
}

Result<void> validate(const AnonymizeFileRequest& r) {
  if (r.output.empty()) return fail(ErrorCode::usage, "no output file given");
  // The input is read twice (anonymiser, then the scanner's own harvest), so it
  // must be a regular file, not a pipe or a device.
  if (fsutil::exists(r.input) && !fsutil::is_regular_file(r.input)) {
    return fail(ErrorCode::usage, "the input must be a regular file (not a pipe or a device)");
  }
  if (fsutil::exists(r.output)) {
    if (fsutil::same_file(r.input, r.output)) {
      return fail(ErrorCode::usage, "the output must not be the input file");
    }
    if (!r.overwrite) {
      return fail(ErrorCode::usage, "the output file exists; use --overwrite to replace it");
    }
  }
  if (r.input.lexically_normal() == r.output.lexically_normal()) {
    return fail(ErrorCode::usage, "the output must not be the input file");
  }
  return {};
}

}  // namespace

namespace testing {

Result<Report> anonymize_file_with_hooks(Project& project, const AnonymizeFileRequest& request,
                                         const Hooks& hooks) {
  if (auto v = validate(request); !v) return std::unexpected(v.error());
  ReportBuilder rb(request);
  const auto report_path = report_path_for(request);
  // Report self-check (R22): first against the secret and the deny list, after
  // the anonymisation against every token of the output scan (one shared index).
  std::optional<scan::Index> checker;
  std::vector<scan::Token> deny;
  // Writes a report that passed the self-check (R22); otherwise a minimal status report.
  const auto write_report = [&](Report r) -> Result<void> {
    if (!checker) {
      auto basic = secret_tokens(project.impl().secret);
      basic.insert(basic.end(), deny.begin(), deny.end());
      checker.emplace(std::move(basic));
    }
    if (!sanitise_report(r, *checker)) {
      Report minimal = rb.build(nullptr, Error{ErrorCode::internal,
                                               "the report would contain a sensitive value; withheld"});
      minimal.files.input = "(redacted)";
      (void)atomic_write(report_path, to_json(minimal));
      return fail(ErrorCode::internal, "the report would contain a sensitive value; nothing was published");
    }
    return atomic_write(report_path, to_json(r));
  };
  const auto finish_error = [&](const Error& e, const RunSummary* s) -> Result<Report> {
    (void)write_report(rb.build(s, e));
    return std::unexpected(e);
  };

  if (request.deny_list) {
    auto d = scan::load_deny_list(*request.deny_list);
    if (!d) return finish_error(d.error(), nullptr);
    deny = std::move(*d);
    rb.deny_entries(deny.size());
  }

  auto reader = CaptureReader::open(request.input);
  if (!reader) return finish_error(reader.error(), nullptr);
  rb.input_format(reader->format());

  Result<RuleSet> rules = hooks.ruleset_override ? Result<RuleSet>(*hooks.ruleset_override)
                                                 : load_embedded_ruleset();
  if (!rules) return finish_error(rules.error(), nullptr);
  rb.ruleset(*rules);

  remove_stale_unpublished(request.output);
  auto file = UnpublishedFile::create(request.output);
  if (!file) return finish_error(file.error(), nullptr);
  auto writer = CaptureWriter::to_fd(file->fd());

  RunSummary summary;
  {
    // The anonymiser's per-flow state is released before the scan builds its index.
    auto anon = Anonymizer::create(project, request.options, reader->format(), std::move(*rules),
                                   hooks.sip_ruleset_override);
    if (!anon) return finish_error(anon.error(), nullptr);
    anon->set_test_sip_passthrough(hooks.sip_passthrough);
    anon->set_test_xml_passthrough(hooks.xml_passthrough);
    anon->set_test_web_passthrough(hooks.web_passthrough);
    for (;;) {
      auto rec = reader->next();
      if (!rec) return finish_error(rec.error(), &anon->summary());
      if (!rec->has_value()) break;
      auto out = anon->process(**rec);
      if (!out) return finish_error(out.error(), &anon->summary());
      for (const auto& o : *out) {
        if (auto w = writer.write(o); !w) return finish_error(w.error(), &anon->summary());
      }
    }
    auto fin = anon->finish();
    if (!fin) return finish_error(fin.error(), &anon->summary());
    for (const auto& o : fin->records) {
      if (auto w = writer.write(o); !w) return finish_error(w.error(), &fin->summary);
    }
    if (auto w = writer.finish(); !w) return finish_error(w.error(), &fin->summary);
    summary = std::move(fin->summary);
  }
  if (hooks.suppress_removed_values) summary.removed_values.clear();
  rb.truncated_tail(reader->truncated_tail_bytes());

  // The mapping is durable before anything becomes visible (FR-029).
  if (auto s = project.impl().save_mapping(); !s) return finish_error(s.error(), &summary);

  // Independent residual-leak scan of the unpublished output (FR-030..FR-033).
  // The project secret is searched too: it must never appear anywhere.
  scan::HarvestStats harvest_stats;
  {
    std::vector<scan::Token> tokens = secret_tokens(project.impl().secret);
    const auto append = [&tokens](std::vector<scan::Token>&& more) {
      tokens.insert(tokens.end(), std::make_move_iterator(more.begin()), std::make_move_iterator(more.end()));
    };
    append(mapping_tokens(project.impl().mapping));
    auto harvested = scan::harvest_input(request.input, &harvest_stats);
    if (!harvested) return finish_error(harvested.error(), &summary);
    append(std::move(*harvested));
    append(removed_tokens(summary.removed_values));
    tokens.insert(tokens.end(), deny.begin(), deny.end());
    checker.emplace(std::move(tokens), mapping_pseudonyms(project.impl().mapping),
                    mapping_byte_pseudonyms(project.impl().mapping));
  }
  // Feature 005 (FR-018): with --encrypted passthrough, hits wholly inside the elements copied as
  // they were are warnings; everything else still fails the run.
  auto scanned = scan::scan_fd(file->fd(), *checker,
                               scan::ScanOptions{request.options.encrypted == EncryptedMode::passthrough});
  if (!scanned) return finish_error(scanned.error(), &summary);
  {
    auto report_scan = to_report_scan(*scanned);
    report_scan.skipped_input_fragments = harvest_stats.fragments;  // feature 008 (FR-001)
    rb.scan(std::move(report_scan));
  }
  if (!scanned->hits.empty()) {
    return finish_error(Error{ErrorCode::leak, std::to_string(scanned->hits.size()) +
                                                   " residual leak(s) found; nothing was published "
                                                   "(see the report)"},
                        &summary);
  }

  if (hooks.fail_before_publish) {
    return finish_error(Error{ErrorCode::internal, "simulated failure before publication"}, &summary);
  }
  Report report = rb.build(&summary, std::nullopt);
  Report checked = report;
  if (!sanitise_report(checked, *checker)) {
    return finish_error(Error{ErrorCode::internal,
                              "the report would contain a sensitive value; nothing was published"},
                        nullptr);
  }
  if (auto p = file->publish(request.overwrite); !p) return finish_error(p.error(), &summary);
  if (auto w = atomic_write(report_path, to_json(checked)); !w) return std::unexpected(w.error());
  return checked;
}

}  // namespace testing

void write_failure_report(const AnonymizeFileRequest& request, const Error& error) {
  ReportBuilder rb(request);
  (void)atomic_write(report_path_for(request), to_json(rb.build(nullptr, error)));
}

Result<Report> anonymize_file(Project& project, const AnonymizeFileRequest& request) {
  try {
    return testing::anonymize_file_with_hooks(project, request, testing::Hooks{});
  } catch (const std::exception& e) {
    return fail(ErrorCode::internal, std::string("internal error: ") + e.what());
  }
}

}  // namespace mcxanon
