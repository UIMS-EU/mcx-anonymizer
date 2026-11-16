// SPDX-License-Identifier: GPL-3.0-or-later
#include "pseudo/atomic_file.hpp"

#include "bytes/hex.hpp"

#include <openssl/rand.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace mcxanon {
namespace {

Result<void> errno_fail(const std::string& what) {
  return fail(ErrorCode::input, what + ": " + std::strerror(errno));
}

Result<void> write_all(int fd, std::string_view data, const WriteFaults* faults) {
  std::size_t limit = data.size();
  if (faults != nullptr && faults->fail_after_bytes) {
    limit = std::min(limit, *faults->fail_after_bytes);
  }
  std::size_t done = 0;
  while (done < limit) {
    const ssize_t n = ::write(fd, data.data() + done, limit - done);
    if (n < 0) {
      if (errno == EINTR) continue;
      return errno_fail("write failed");
    }
    done += static_cast<std::size_t>(n);
  }
  if (limit < data.size()) return fail(ErrorCode::input, "write failed (simulated)");
  return {};
}

}  // namespace

Result<void> atomic_write(const std::filesystem::path& target, std::string_view data,
                          const WriteFaults* faults) {
  std::array<std::uint8_t, 6> rnd{};
  if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    return fail(ErrorCode::internal, "random number generator failed");
  }
  const std::filesystem::path tmp = target.string() + ".tmp-" + to_hex(rnd);
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) return errno_fail("cannot create " + tmp.filename().string());
  auto ok = write_all(fd, data, faults);
  if (ok && ::fsync(fd) != 0) ok = errno_fail("fsync failed");
  ::close(fd);
  if (ok && ::rename(tmp.c_str(), target.c_str()) != 0) ok = errno_fail("rename failed");
  if (!ok) {
    ::unlink(tmp.c_str());
    return ok;
  }
  const std::filesystem::path dir = target.has_parent_path() ? target.parent_path() : ".";
  const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
  return {};
}

Result<std::string> read_small_file(const std::filesystem::path& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return fail(ErrorCode::input, "cannot read " + path.filename().string() + ": " +
                                      std::strerror(errno));
  }
  std::string out;
  std::array<char, 65536> buf{};
  for (;;) {
    const ssize_t n = ::read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      return fail(ErrorCode::input, "read failed: " + std::string(std::strerror(errno)));
    }
    if (n == 0) break;
    out.append(buf.data(), static_cast<std::size_t>(n));
  }
  ::close(fd);
  return out;
}

Result<bool> is_owner_only(const std::filesystem::path& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) {
    return fail(ErrorCode::input, "cannot stat " + path.filename().string() + ": " +
                                      std::strerror(errno));
  }
  return (st.st_mode & 077u) == 0;
}

}  // namespace mcxanon
