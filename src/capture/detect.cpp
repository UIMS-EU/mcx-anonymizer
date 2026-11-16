// SPDX-License-Identifier: GPL-3.0-or-later
#include "capture/detect.hpp"

#include <algorithm>
#include <array>
#include <string>

namespace mcxanon {
namespace {

bool starts_with(ByteView head, std::initializer_list<std::uint8_t> magic) {
  return head.size() >= magic.size() && std::equal(magic.begin(), magic.end(), head.begin());
}

}  // namespace

Result<CaptureFormat> detect_format(ByteView head) {
  struct Compressed { std::initializer_list<std::uint8_t> magic; const char* name; };
  const std::array<Compressed, 5> compressed{{{{0x1f, 0x8b}, "gzip"},
                                              {{0x28, 0xb5, 0x2f, 0xfd}, "zstd"},
                                              {{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, "xz"},
                                              {{'B', 'Z', 'h'}, "bzip2"},
                                              {{0x04, 0x22, 0x4d, 0x18}, "lz4"}}};
  for (const auto& c : compressed) {
    if (starts_with(head, c.magic)) {
      return fail(ErrorCode::input, std::string("the input is compressed (") + c.name +
                                        "); decompress first");
    }
  }
  if (head.size() < 4) return fail(ErrorCode::input, "file too short to be a capture");
  // pcap (draft-ietf-opsawg-pcap-09 §4.1): microsecond and nanosecond, both byte orders.
  if (starts_with(head, {0xA1, 0xB2, 0xC3, 0xD4}) || starts_with(head, {0xD4, 0xC3, 0xB2, 0xA1}) ||
      starts_with(head, {0xA1, 0xB2, 0x3C, 0x4D}) || starts_with(head, {0x4D, 0x3C, 0xB2, 0xA1})) {
    return CaptureFormat::pcap;
  }
  // pcapng SHB block type 0x0A0D0D0A is a palindrome (draft-ietf-opsawg-pcapng-06 §4.1).
  if (starts_with(head, {0x0A, 0x0D, 0x0D, 0x0A})) return CaptureFormat::pcapng;
  return fail(ErrorCode::input, "unknown file format (not pcap or pcapng)");
}

}  // namespace mcxanon
