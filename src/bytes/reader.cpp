// SPDX-License-Identifier: GPL-3.0-or-later
#include "bytes/reader.hpp"

#include <string>

namespace mcxanon {

Result<void> Reader::need(std::size_t n) const {
  if (remaining() < n) {
    return fail(ErrorCode::input, "truncated data: need " + std::to_string(n) +
                                      " byte(s) at offset " + std::to_string(pos_) + ", have " +
                                      std::to_string(remaining()));
  }
  return {};
}

Result<std::uint8_t> Reader::u8() {
  if (auto r = need(1); !r) return std::unexpected(r.error());
  return data_[pos_++];
}

Result<std::uint16_t> Reader::u16() {
  if (auto r = need(2); !r) return std::unexpected(r.error());
  const auto v = load16(data_, pos_, endian_);
  pos_ += 2;
  return v;
}

Result<std::uint32_t> Reader::u32() {
  if (auto r = need(4); !r) return std::unexpected(r.error());
  const auto v = load32(data_, pos_, endian_);
  pos_ += 4;
  return v;
}

Result<std::uint64_t> Reader::u64() {
  if (auto r = need(8); !r) return std::unexpected(r.error());
  const auto v = load64(data_, pos_, endian_);
  pos_ += 8;
  return v;
}

Result<ByteView> Reader::bytes(std::size_t n) {
  if (auto r = need(n); !r) return std::unexpected(r.error());
  const ByteView v = data_.subspan(pos_, n);
  pos_ += n;
  return v;
}

Result<void> Reader::skip(std::size_t n) {
  if (auto r = need(n); !r) return r;
  pos_ += n;
  return {};
}

}  // namespace mcxanon
