// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/writer.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace mcxanon {
namespace {
constexpr std::size_t kBufferSize = 1u << 20;
}

CaptureWriter CaptureWriter::to_fd(int fd) {
  CaptureWriter w;
  w.fd_ = fd;
  w.buffer_.reserve(kBufferSize);
  return w;
}

Result<CaptureWriter> CaptureWriter::create(const std::filesystem::path& path) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    return fail(ErrorCode::input, "cannot create " + path.filename().string() + ": " +
                                      std::strerror(errno));
  }
  CaptureWriter w = to_fd(fd);
  w.owns_fd_ = true;
  return w;
}

CaptureWriter CaptureWriter::to_memory() {
  CaptureWriter w;
  w.in_memory_ = true;
  return w;
}

CaptureWriter::CaptureWriter(CaptureWriter&& o) noexcept
    : fd_(o.fd_), owns_fd_(o.owns_fd_), in_memory_(o.in_memory_),
      buffer_(std::move(o.buffer_)), memory_(std::move(o.memory_)) {
  o.fd_ = -1;
  o.owns_fd_ = false;
}

CaptureWriter& CaptureWriter::operator=(CaptureWriter&& o) noexcept {
  if (this != &o) {
    if (owns_fd_ && fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    owns_fd_ = o.owns_fd_;
    in_memory_ = o.in_memory_;
    buffer_ = std::move(o.buffer_);
    memory_ = std::move(o.memory_);
    o.fd_ = -1;
    o.owns_fd_ = false;
  }
  return *this;
}

CaptureWriter::~CaptureWriter() {
  if (owns_fd_ && fd_ >= 0) ::close(fd_);
}

Result<void> CaptureWriter::write(ByteView bytes) {
  if (in_memory_) {
    memory_.insert(memory_.end(), bytes.begin(), bytes.end());
    return {};
  }
  if (buffer_.size() + bytes.size() > kBufferSize) {
    if (auto r = flush(); !r) return r;
  }
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  return {};
}

Result<void> CaptureWriter::flush() {
  std::size_t done = 0;
  while (done < buffer_.size()) {
    const ssize_t n = ::write(fd_, buffer_.data() + done, buffer_.size() - done);
    if (n < 0) {
      if (errno == EINTR) continue;
      return fail(ErrorCode::input, std::string("write error: ") + std::strerror(errno));
    }
    done += static_cast<std::size_t>(n);
  }
  buffer_.clear();
  return {};
}

Result<void> CaptureWriter::finish() {
  if (in_memory_) return {};
  if (auto r = flush(); !r) return r;
  if (::fsync(fd_) != 0) return fail(ErrorCode::input, std::string("fsync failed: ") + std::strerror(errno));
  return {};
}

}  // namespace mcxanon
