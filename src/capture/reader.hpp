// SPDX-License-Identifier: GPL-3.0-or-later
//
// Streaming capture reader: yields one Record at a time with constant memory
// (one record buffer, a 1 MiB read buffer).
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "capture/pcap.hpp"
#include "capture/pcapng.hpp"
#include "capture/record.hpp"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace mcxanon {

class ByteSource;

class CaptureReader {
 public:
  static Result<CaptureReader> open(const std::filesystem::path& path);
  static Result<CaptureReader> from_memory(Bytes data);

  CaptureReader(CaptureReader&&) noexcept;
  CaptureReader& operator=(CaptureReader&&) noexcept;
  ~CaptureReader();

  [[nodiscard]] CaptureFormat format() const { return format_; }
  // Next record, std::nullopt at the end of the file. A record that is cut off
  // by the end of the file ends the stream; its size is truncated_tail_bytes().
  Result<std::optional<Record>> next();
  [[nodiscard]] std::uint64_t truncated_tail_bytes() const { return tail_; }
  // pcap only: the file header (valid after the first record).
  [[nodiscard]] const PcapFileHeader& pcap_header() const { return pcap_header_; }
  // pcapng only: interfaces of the current section, in IDB order.
  [[nodiscard]] const std::vector<InterfaceInfo>& interfaces() const { return interfaces_; }

 private:
  explicit CaptureReader(std::unique_ptr<ByteSource> src);
  Result<void> init();
  Result<std::optional<Record>> next_pcap();
  Result<std::optional<Record>> next_pcapng();

  std::unique_ptr<ByteSource> src_;
  CaptureFormat format_ = CaptureFormat::pcap;
  PcapFileHeader pcap_header_;
  bool header_done_ = false;
  bool seen_shb_ = false;
  Endian section_endian_ = Endian::little;
  std::vector<InterfaceInfo> interfaces_;
  std::uint64_t offset_ = 0;
  std::uint64_t frames_ = 0;
  std::uint64_t tail_ = 0;
  bool ended_ = false;
};

}  // namespace mcxanon
