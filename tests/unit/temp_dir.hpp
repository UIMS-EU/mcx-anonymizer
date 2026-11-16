// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace mcxanon::test {

// A private temporary directory removed at scope exit.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "mcxanon-test-XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) throw std::runtime_error("mkdtemp failed");
    path_ = tmpl;
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    std::error_code ec;
    std::filesystem::permissions(path_, std::filesystem::perms::owner_all, ec);
    std::filesystem::remove_all(path_, ec);
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace mcxanon::test
