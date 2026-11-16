// SPDX-License-Identifier: GPL-3.0-or-later
#include "pipeline/output_file.hpp"

#include "bytes/hex.hpp"
#include "pseudo/fsutil.hpp"

#include <openssl/rand.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>

namespace mcxanon {
namespace {

std::filesystem::path dir_of(const std::filesystem::path& p) {
  return p.has_parent_path() ? p.parent_path() : std::filesystem::path(".");
}

std::string hidden_prefix(const std::filesystem::path& dest) {
  return "." + dest.filename().string() + ".mcxanon-tmp-";
}

Result<std::filesystem::path> random_hidden(const std::filesystem::path& dest) {
  std::array<std::uint8_t, 8> rnd{};
  if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    return fail(ErrorCode::internal, "random number generator failed");
  }
  return dir_of(dest) / (hidden_prefix(dest) + to_hex(rnd));
}

}  // namespace

void remove_stale_unpublished(const std::filesystem::path& destination) {
  const std::string prefix = hidden_prefix(destination);
  fsutil::remove_files(dir_of(destination),
                       [&](const std::string& n) { return n.rfind(prefix, 0) == 0; });
}

Result<UnpublishedFile> UnpublishedFile::create(const std::filesystem::path& destination) {
  const auto dir = dir_of(destination);
#ifdef O_TMPFILE
  const int fd = ::open(dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
  if (fd >= 0) return UnpublishedFile(fd, destination, {});
#endif
  auto hidden = random_hidden(destination);
  if (!hidden) return std::unexpected(hidden.error());
  const int hfd = ::open(hidden->c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (hfd < 0) {
    return fail(ErrorCode::input, "cannot create the output in " + dir.string() + ": " +
                                      std::strerror(errno));
  }
  return UnpublishedFile(hfd, destination, *hidden);
}

UnpublishedFile::UnpublishedFile(UnpublishedFile&& o) noexcept
    : fd_(o.fd_), dest_(std::move(o.dest_)), hidden_(std::move(o.hidden_)),
      published_(o.published_) {
  o.fd_ = -1;
  o.published_ = true;
}

UnpublishedFile::~UnpublishedFile() { abandon(); }

void UnpublishedFile::abandon() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  if (!published_ && !hidden_.empty()) ::unlink(hidden_.c_str());
  published_ = true;
}

Result<void> UnpublishedFile::publish(bool overwrite) {
  if (published_) return fail(ErrorCode::internal, "output already published");
  if (::fchmod(fd_, 0600) != 0) {
    return fail(ErrorCode::input, std::string("chmod failed: ") + std::strerror(errno));
  }
  if (hidden_.empty()) {
    const std::string proc = "/proc/self/fd/" + std::to_string(fd_);
    if (!overwrite) {
      if (::linkat(AT_FDCWD, proc.c_str(), AT_FDCWD, dest_.c_str(), AT_SYMLINK_FOLLOW) != 0) {
        return fail(ErrorCode::input, "cannot publish the output: " + std::string(std::strerror(errno)));
      }
    } else {
      auto tmp = random_hidden(dest_);
      if (!tmp) return std::unexpected(tmp.error());
      if (::linkat(AT_FDCWD, proc.c_str(), AT_FDCWD, tmp->c_str(), AT_SYMLINK_FOLLOW) != 0 ||
          ::rename(tmp->c_str(), dest_.c_str()) != 0) {
        const int err = errno;
        ::unlink(tmp->c_str());
        return fail(ErrorCode::input, "cannot publish the output: " + std::string(std::strerror(err)));
      }
    }
  } else {
    if (!overwrite) {
      if (::link(hidden_.c_str(), dest_.c_str()) != 0) {
        return fail(ErrorCode::input, "cannot publish the output: " + std::string(std::strerror(errno)));
      }
      ::unlink(hidden_.c_str());
    } else if (::rename(hidden_.c_str(), dest_.c_str()) != 0) {
      return fail(ErrorCode::input, "cannot publish the output: " + std::string(std::strerror(errno)));
    }
  }
  published_ = true;
  const int dfd = ::open(dir_of(dest_).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
  ::close(fd_);
  fd_ = -1;
  return {};
}

}  // namespace mcxanon
