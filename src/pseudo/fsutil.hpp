// SPDX-License-Identifier: GPL-3.0-or-later
//
// Small POSIX file-system helpers. Unlike the error_code overloads of
// std::filesystem they are not noexcept, so an allocation failure becomes an
// ordinary exception (caught at the API boundary) instead of std::terminate.
#pragma once

#include "mcxanon/error.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace mcxanon::fsutil {

bool exists(const std::filesystem::path& p);
bool is_directory(const std::filesystem::path& p);
bool is_regular_file(const std::filesystem::path& p);
// Same device and inode.
bool same_file(const std::filesystem::path& a, const std::filesystem::path& b);
// mkdir -p with the given mode for every directory it creates.
Result<void> make_directories(const std::filesystem::path& p, unsigned mode);
// Unlinks regular files of `dir` whose name satisfies `match`.
void remove_files(const std::filesystem::path& dir, const std::function<bool(const std::string&)>& match);
std::optional<std::filesystem::path> executable_dir();

}  // namespace mcxanon::fsutil
