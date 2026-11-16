// SPDX-License-Identifier: GPL-3.0-or-later
//
// mcxanon reveal (feature 006): the project's pseudonyms in any text mapped
// back to the originals, locally.
#include "cli/commands.hpp"
#include "mcxanon/reveal.hpp"
#include "reveal/engine.hpp"

#include <cstdio>
#include <memory>

namespace mcxanon::cli {

const char* const kRevealBanner = "mcxanon: the output contains ORIGINAL values; do not share it with the analyst\n";

void register_reveal_command(CLI::App& app, const GlobalOptions& g,
                             std::vector<std::pair<CLI::App*, Command>>& commands) {
  struct Args {
    std::string project, input, output, report;
    bool overwrite = false, replace_ambiguous = false, annotate = false, quiet = false;
  };
  auto a = std::make_shared<Args>();
  CLI::App* sub = app.add_subcommand("reveal", "map the project's pseudonyms in a text back to the originals");
  sub->add_option("--project", a->project, "project name")->required();
  sub->add_option("input", a->input, "text to reveal (default or '-': stdin)");
  sub->add_option("-o,--output", a->output, "output file (default or '-': stdout), owner-only");
  sub->add_flag("--overwrite", a->overwrite, "replace an existing output or report file");
  sub->add_flag("--replace-ambiguous", a->replace_ambiguous,
                "also replace ambiguous candidates (small value spaces, short values, overlaps)");
  sub->add_flag("--annotate", a->annotate, "write original⟦pseudonym⟧ for every revealed value");
  sub->add_option("--report", a->report, "write a JSON report (contains original values), owner-only");
  sub->add_flag("--quiet", a->quiet, "no summary on stderr");
  commands.emplace_back(sub, [&g, a]() -> Result<void> {
    std::fputs(kRevealBanner, stderr);
    RevealFileRequest req;
    if (!a->input.empty()) req.input = a->input;
    if (!a->output.empty()) req.output = a->output;
    if (!a->report.empty()) req.report_path = a->report;
    req.overwrite = a->overwrite;
    req.options.replace_ambiguous = a->replace_ambiguous;
    req.options.annotate = a->annotate;
    req.project_name = a->project;
    std::optional<Revealer> revealer;
    {
      // The project lock is held only while the mapping is loaded (P3).
      auto project = open_project(g, a->project);
      if (!project) return std::unexpected(project.error());
      if (project->mapping_size() == 0) {
        std::fputs("mcxanon: warning: the project mapping is empty; nothing can be revealed\n", stderr);
      }
      auto r = Revealer::create(*project, req.options);
      if (!r) return std::unexpected(r.error());
      revealer.emplace(std::move(*r));
    }
    auto s = reveal_file(*revealer, req);
    if (!s) return std::unexpected(s.error());
    if (!a->quiet) std::fputs(reveal::summary_text(*s).c_str(), stderr);
    return {};
  });
}

}  // namespace mcxanon::cli
