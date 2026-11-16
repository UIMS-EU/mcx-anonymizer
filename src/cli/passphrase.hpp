// SPDX-License-Identifier: GPL-3.0-or-later
// Passphrase sources: --passphrase-file > MCXANON_PASSPHRASE > interactive prompt.
#pragma once

#include "mcxanon/error.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace mcxanon::cli {

struct PassphraseInputs {
  std::optional<std::filesystem::path> file;
  std::optional<std::string> env;
  // Prompts without echo; empty when there is no terminal.
  std::function<Result<std::string>(const char*)> prompt;
};

PassphraseInputs passphrase_inputs_from_environment(const std::string& file_option);
// `confirm`: ask twice (new passphrase) when prompting.
Result<std::string> get_passphrase(const PassphraseInputs& in, bool confirm);

}  // namespace mcxanon::cli
