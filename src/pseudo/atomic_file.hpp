// SPDX-License-Identifier: GPL-3.0-or-later
//
// Atomic replacement of small files (write
// protocol): temporary file 0600, fsync, rename, fsync of the directory.
#pragma once

#include "mcxanon/error.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace mcxanon {

// Test seam: simulate a failing write.
struct WriteFaults {
  std::optional<std::size_t> fail_after_bytes;
};

Result<void> atomic_write(const std::filesystem::path& target, std::string_view data,
                          const WriteFaults* faults = nullptr);
Result<std::string> read_small_file(const std::filesystem::path& path);
// True when neither group nor others have any access to `path`.
Result<bool> is_owner_only(const std::filesystem::path& path);

}  // namespace mcxanon
