// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bounded reader over untrusted bytes. Every read returns a Result; a failed
// read does not advance the position.
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"

#include <cstddef>
#include <cstdint>

namespace mcxanon {

class Reader {
 public:
  explicit Reader(ByteView data, Endian e = Endian::big) : data_(data), endian_(e) {}

  [[nodiscard]] std::size_t offset() const { return pos_; }
  [[nodiscard]] std::size_t remaining() const { return data_.size() - pos_; }
  [[nodiscard]] bool empty() const { return pos_ == data_.size(); }
  void set_endian(Endian e) { endian_ = e; }

  Result<std::uint8_t> u8();
  Result<std::uint16_t> u16();
  Result<std::uint32_t> u32();
  Result<std::uint64_t> u64();
  Result<ByteView> bytes(std::size_t n);
  Result<void> skip(std::size_t n);

 private:
  Result<void> need(std::size_t n) const;
  ByteView data_;
  Endian endian_;
  std::size_t pos_ = 0;
};

}  // namespace mcxanon
