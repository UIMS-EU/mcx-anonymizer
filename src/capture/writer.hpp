// SPDX-License-Identifier: GPL-3.0-or-later
//
// Buffered capture writer. Records are written byte for byte; building the
// records is the caller's job.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "capture/record.hpp"

#include <filesystem>

namespace mcxanon {

class CaptureWriter {
 public:
  // Writes to an already open file descriptor (not closed by the writer).
  static CaptureWriter to_fd(int fd);
  static Result<CaptureWriter> create(const std::filesystem::path& path);
  static CaptureWriter to_memory();

  CaptureWriter(CaptureWriter&&) noexcept;
  CaptureWriter& operator=(CaptureWriter&&) noexcept;
  ~CaptureWriter();

  Result<void> write(const Record& r) { return write(ByteView(r.bytes)); }
  Result<void> write(ByteView bytes);
  // Flushes the buffer (and fsyncs a file).
  Result<void> finish();
  [[nodiscard]] const Bytes& memory() const { return memory_; }

 private:
  CaptureWriter() = default;
  Result<void> flush();
  int fd_ = -1;
  bool owns_fd_ = false;
  bool in_memory_ = false;
  Bytes buffer_;
  Bytes memory_;
};

}  // namespace mcxanon
