// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/fsutil.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace mcxanon::fsutil {

bool exists(const std::filesystem::path& p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0;
}

bool is_directory(const std::filesystem::path& p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const std::filesystem::path& p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool same_file(const std::filesystem::path& a, const std::filesystem::path& b) {
  struct stat sa {};
  struct stat sb {};
  return ::stat(a.c_str(), &sa) == 0 && ::stat(b.c_str(), &sb) == 0 && sa.st_dev == sb.st_dev &&
         sa.st_ino == sb.st_ino;
}

Result<void> make_directories(const std::filesystem::path& p, unsigned mode) {
  if (p.empty() || fsutil::is_directory(p)) return {};
  if (p.has_parent_path() && p.parent_path() != p) {
    if (auto r = make_directories(p.parent_path(), mode); !r) return r;
  }
  if (::mkdir(p.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST) {
    return fail(ErrorCode::input, "cannot create directory " + p.string() + ": " + std::strerror(errno));
  }
  return {};
}

void remove_files(const std::filesystem::path& dir, const std::function<bool(const std::string&)>& match) {
  DIR* d = ::opendir(dir.empty() ? "." : dir.c_str());
  if (d == nullptr) return;
  const int dfd = ::dirfd(d);
  while (const dirent* e = ::readdir(d)) {
    const std::string name = e->d_name;
    if (name == "." || name == ".." || !match(name)) continue;
    struct stat st {};
    if (::fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)) {
      ::unlinkat(dfd, e->d_name, 0);
    }
  }
  ::closedir(d);
}

std::optional<std::filesystem::path> executable_dir() {
  std::array<char, 4096> buf{};
  const ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
  if (n <= 0) return std::nullopt;
  return std::filesystem::path(std::string(buf.data(), static_cast<std::size_t>(n))).parent_path();
}

}  // namespace mcxanon::fsutil
