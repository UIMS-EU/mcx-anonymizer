// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcxanon/error.hpp"
#include "mcxanon/project.hpp"

#include <CLI/CLI.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace mcxanon::cli {

struct GlobalOptions {
  std::string data_dir;  // --data-dir
  bool wait = false;     // --wait: wait for the project lock
  std::string passphrase_file;  // --passphrase-file
};

// A registered command runs after parsing and returns the process result.
using Command = std::function<Result<void>()>;

Result<DataDirResolution> resolve_data_dir_for(const GlobalOptions& g);
// Opens a project, asking for the passphrase when it is encrypted.
Result<Project> open_project(const GlobalOptions& g, const std::string& name);

void register_project_commands(CLI::App& app, const GlobalOptions& g,
                               std::vector<std::pair<CLI::App*, Command>>& commands);
void register_anonymize_command(CLI::App& app, const GlobalOptions& g,
                                std::vector<std::pair<CLI::App*, Command>>& commands);
void register_scan_command(CLI::App& app, const GlobalOptions& g,
                           std::vector<std::pair<CLI::App*, Command>>& commands);
void register_reveal_command(CLI::App& app, const GlobalOptions& g,
                             std::vector<std::pair<CLI::App*, Command>>& commands);

// The warning every command that prints original values starts with (feature 006).
extern const char* const kRevealBanner;

}  // namespace mcxanon::cli
