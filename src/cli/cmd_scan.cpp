// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/commands.hpp"
#include "mcxanon/anonymize.hpp"

#include <cstdio>
#include <memory>

namespace mcxanon::cli {

void register_scan_command(CLI::App& app, const GlobalOptions& g,
                           std::vector<std::pair<CLI::App*, Command>>& commands) {
  struct Args {
    std::string project, file, deny, report, encrypted = "ciphertext";
  };
  auto a = std::make_shared<Args>();
  CLI::App* sub = app.add_subcommand("scan", "scan a capture for residual leaks");
  sub->add_option("--project", a->project, "project name")->required();
  sub->add_option("file", a->file, "capture to scan")->required();
  sub->add_option("--deny-list", a->deny, "file of words that must never appear");
  sub->add_option("--report", a->report, "report path (default <file>.scan.json)");
  sub->add_option("--encrypted", a->encrypted,
                  "passthrough: hits inside MIKEY carriers and EncryptedData are warnings (default ciphertext)")
      ->check(CLI::IsMember({"ciphertext", "passthrough"}));
  commands.emplace_back(sub, [&g, a]() -> Result<void> {
    auto project = open_project(g, a->project);
    if (!project) return std::unexpected(project.error());
    ScanFileRequest req;
    req.file = a->file;
    if (!a->deny.empty()) req.deny_list = a->deny;
    if (!a->report.empty()) req.report_path = a->report;
    if (a->encrypted == "passthrough") req.encrypted = EncryptedMode::passthrough;
    auto r = scan_capture(*project, req);
    if (!r) return std::unexpected(r.error());
    std::fprintf(stderr, "mcxanon: scan clean (%llu tokens, %llu patterns, %llu suppressed chance matches)\n",
                 static_cast<unsigned long long>(r->scan.tokens), static_cast<unsigned long long>(r->scan.patterns),
                 static_cast<unsigned long long>(r->scan.suppressed_chance_matches));
    if (!r->scan.warnings.empty()) {
      std::fprintf(stderr, "mcxanon: passthrough: %zu warning(s) inside key management messages and encrypted XML "
                           "elements (see the report)\n", r->scan.warnings.size());
    }
    return {};
  });
}

}  // namespace mcxanon::cli
