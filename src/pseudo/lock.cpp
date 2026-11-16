// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/lock.hpp"

#include "pseudo/fsutil.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <unistd.h>

namespace mcxanon {

Result<ProjectLock> ProjectLock::acquire(const std::filesystem::path& lock_file, bool wait) {
  const int fd = ::open(lock_file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    return fail(ErrorCode::input, "cannot open project lock: " + std::string(std::strerror(errno)));
  }
  int rc = 0;
  do {
    rc = ::flock(fd, LOCK_EX | (wait ? 0 : LOCK_NB));
  } while (rc != 0 && errno == EINTR);
  if (rc != 0) {
    const int err = errno;
    ::close(fd);
    if (err == EWOULDBLOCK) {
      return fail(ErrorCode::busy,
                  "the project is in use by another mcxanon run; retry later or use --wait");
    }
    return fail(ErrorCode::input, "cannot lock project: " + std::string(std::strerror(err)));
  }
  // Remove temporaries of an interrupted earlier run (pattern "<name>.tmp-<hex>").
  fsutil::remove_files(lock_file.parent_path(),
                       [](const std::string& name) { return name.find(".tmp-") != std::string::npos; });
  return ProjectLock(fd);
}

ProjectLock::ProjectLock(ProjectLock&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

ProjectLock& ProjectLock::operator=(ProjectLock&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

ProjectLock::~ProjectLock() {
  if (fd_ >= 0) ::close(fd_);  // closing the descriptor releases the flock
}

}  // namespace mcxanon
