// SPDX-License-Identifier: GPL-3.0-or-later
//
// An output file that is not visible until it is published.
#pragma once

#include "mcxanon/error.hpp"

#include <filesystem>

namespace mcxanon {

class UnpublishedFile {
 public:
  // Creates the file in the directory of `destination`.
  static Result<UnpublishedFile> create(const std::filesystem::path& destination);
  UnpublishedFile(UnpublishedFile&& o) noexcept;
  UnpublishedFile& operator=(UnpublishedFile&&) = delete;
  UnpublishedFile(const UnpublishedFile&) = delete;
  UnpublishedFile& operator=(const UnpublishedFile&) = delete;
  ~UnpublishedFile();  // abandons the file unless published

  [[nodiscard]] int fd() const { return fd_; }
  // Makes the file visible at the destination (replacing it when `overwrite`).
  Result<void> publish(bool overwrite);
  [[nodiscard]] bool anonymous() const { return hidden_.empty(); }

 private:
  UnpublishedFile(int fd, std::filesystem::path dest, std::filesystem::path hidden)
      : fd_(fd), dest_(std::move(dest)), hidden_(std::move(hidden)) {}
  void abandon();
  int fd_ = -1;
  std::filesystem::path dest_;
  std::filesystem::path hidden_;  // fallback name; empty for an anonymous O_TMPFILE
  bool published_ = false;
};

// Removes stale fallback files ".<name>.mcxanon-tmp-<hex>" next to `destination`.
void remove_stale_unpublished(const std::filesystem::path& destination);

}  // namespace mcxanon
