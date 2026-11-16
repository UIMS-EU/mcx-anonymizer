// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/commands.hpp"
#include "mcxanon/version.hpp"

#include <cstdio>
#include <exception>
#include <string>

namespace {

std::string version_text() {
  return std::string("mcxanon ") + std::string(mcxanon::tool_version) + "\nrule set " +
         std::string(mcxanon::ruleset_name) + " " + std::string(mcxanon::ruleset_version) + " " +
         std::string(mcxanon::ruleset_digest);
}

int run(int argc, char** argv) {
  using namespace mcxanon;
  CLI::App app{"mcxanon - anonymizer for Mission Critical (MCPTT/MCData/MCVideo) captures"};
  app.set_version_flag("--version", version_text());
  app.require_subcommand(1);
  cli::GlobalOptions global;
  app.add_option("--data-dir", global.data_dir, "data directory holding the projects");
  app.add_flag("--wait", global.wait, "wait for a project in use instead of failing");
  app.add_option("--passphrase-file", global.passphrase_file, "file holding the project passphrase");

  std::vector<std::pair<CLI::App*, cli::Command>> commands;
  cli::register_project_commands(app, global, commands);
  cli::register_anonymize_command(app, global, commands);
  cli::register_scan_command(app, global, commands);
  cli::register_reveal_command(app, global, commands);

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    const int rc = app.exit(e);
    return rc == 0 ? 0 : static_cast<int>(ErrorCode::usage);
  }
  for (auto& [sub, cmd] : commands) {
    if (sub->parsed()) {
      auto r = cmd();
      if (!r) {
        std::fprintf(stderr, "mcxanon: error: %s\n", r.error().message.c_str());
        return static_cast<int>(r.error().code);
      }
      return 0;
    }
  }
  std::fputs(app.help().c_str(), stderr);
  return static_cast<int>(ErrorCode::usage);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "mcxanon: internal error: %s\n", e.what());
  } catch (...) {
    std::fputs("mcxanon: internal error\n", stderr);
  }
  return static_cast<int>(mcxanon::ErrorCode::internal);
}
