// SPDX-License-Identifier: GPL-3.0-or-later
// Byte builders for capture-format unit tests.
#pragma once

#include "bytes/bytes.hpp"
#include "bytes/endian.hpp"

#include <cstdint>
#include <initializer_list>
#include <string_view>

namespace mcxanon::test {

class Buf {
 public:
  explicit Buf(Endian e = Endian::little) : e_(e) {}
  Buf& u8(std::uint8_t v) { b_.push_back(v); return *this; }
  Buf& u16(std::uint16_t v) { grow(2); store16(b_, b_.size() - 2, v, e_); return *this; }
  Buf& u32(std::uint32_t v) { grow(4); store32(b_, b_.size() - 4, v, e_); return *this; }
  Buf& u64(std::uint64_t v) { grow(8); store64(b_, b_.size() - 8, v, e_); return *this; }
  Buf& raw(ByteView v) { b_.insert(b_.end(), v.begin(), v.end()); return *this; }
  Buf& raw(std::initializer_list<std::uint8_t> v) { b_.insert(b_.end(), v); return *this; }
  Buf& str(std::string_view s) { b_.insert(b_.end(), s.begin(), s.end()); return *this; }
  Buf& pad4() { while (b_.size() % 4 != 0) b_.push_back(0); return *this; }
  [[nodiscard]] const Bytes& bytes() const { return b_; }
  [[nodiscard]] std::size_t size() const { return b_.size(); }

 private:
  void grow(std::size_t n) { b_.resize(b_.size() + n); }
  Endian e_;
  Bytes b_;
};

inline Bytes cat(std::initializer_list<ByteView> parts) {
  Bytes out;
  for (auto p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

// pcapng option TLV (value padded to 32 bits).
inline Bytes opt(Endian e, std::uint16_t code, std::string_view value) {
  Buf b(e);
  b.u16(code).u16(static_cast<std::uint16_t>(value.size())).str(value).pad4();
  return b.bytes();
}
inline Bytes opt_end(Endian e) { return Buf(e).u16(0).u16(0).bytes(); }

// Generic pcapng block: type, body (already padded), total length at both ends.
inline Bytes block(Endian e, std::uint32_t type, ByteView body) {
  const auto total = static_cast<std::uint32_t>(12 + body.size());
  Buf b(e);
  b.u32(type).u32(total).raw(body).u32(total);
  return b.bytes();
}

inline Bytes shb(Endian e, ByteView options = {}) {
  Buf body(e);
  body.u32(0x1A2B3C4D).u16(1).u16(0).u64(0xFFFFFFFFFFFFFFFFull).raw(options);
  return block(e, 0x0A0D0D0A, body.bytes());
}

inline Bytes idb(Endian e, std::uint16_t linktype, std::uint32_t snaplen, ByteView options = {}) {
  Buf body(e);
  body.u16(linktype).u16(0).u32(snaplen).raw(options);
  return block(e, 1, body.bytes());
}

inline Bytes epb(Endian e, std::uint32_t ifid, std::uint64_t ts, ByteView data,
                 ByteView options = {}) {
  Buf body(e);
  body.u32(ifid)
      .u32(static_cast<std::uint32_t>(ts >> 32))
      .u32(static_cast<std::uint32_t>(ts & 0xFFFFFFFFu))
      .u32(static_cast<std::uint32_t>(data.size()))
      .u32(static_cast<std::uint32_t>(data.size()))
      .raw(data)
      .pad4()
      .raw(options);
  return block(e, 6, body.bytes());
}

}  // namespace mcxanon::test
