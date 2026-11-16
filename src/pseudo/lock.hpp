// SPDX-License-Identifier: GPL-3.0-or-later
//
// Exclusive advisory lock on a project (FR-028). Taking the lock also removes
// stale temporary files left in the project directory by a crash.
#pragma once

#include "mcxanon/error.hpp"

#include <filesystem>

namespace mcxanon {

class ProjectLock {
 public:
  static Result<ProjectLock> acquire(const std::filesystem::path& lock_file, bool wait);
  ProjectLock(ProjectLock&& o) noexcept;
  ProjectLock& operator=(ProjectLock&& o) noexcept;
  ProjectLock(const ProjectLock&) = delete;
  ProjectLock& operator=(const ProjectLock&) = delete;
  ~ProjectLock();

 private:
  explicit ProjectLock(int fd) : fd_(fd) {}
  int fd_ = -1;
};

}  // namespace mcxanon
