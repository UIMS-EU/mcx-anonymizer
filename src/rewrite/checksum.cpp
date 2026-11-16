// SPDX-License-Identifier: GPL-3.0-or-later
#include "rewrite/checksum.hpp"

#include <array>

namespace mcxanon {

std::uint32_t inet_accumulate(ByteView data, std::uint32_t acc) {
  std::uint64_t sum = acc;
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) {
    sum += static_cast<std::uint32_t>((data[i] << 8) | data[i + 1]);
  }
  if (i < data.size()) sum += static_cast<std::uint32_t>(data[i] << 8);
  while (sum >> 32) sum = (sum & 0xFFFFFFFFu) + (sum >> 32);
  return static_cast<std::uint32_t>(sum);
}

std::uint16_t inet_fold_sum(std::uint32_t acc) {
  while (acc >> 16) acc = (acc & 0xFFFFu) + (acc >> 16);
  return static_cast<std::uint16_t>(acc);
}

std::uint16_t inet_checksum(ByteView data) {
  return static_cast<std::uint16_t>(~inet_fold_sum(inet_accumulate(data)));
}

std::uint16_t inet_update16(std::uint16_t hc, std::uint16_t old_word, std::uint16_t new_word) {
  std::uint32_t sum = static_cast<std::uint16_t>(~hc);
  sum += static_cast<std::uint16_t>(~old_word);
  sum += new_word;
  return static_cast<std::uint16_t>(~inet_fold_sum(sum));
}

namespace {

constexpr std::array<std::uint32_t, 256> make_table(std::uint32_t poly) {
  std::array<std::uint32_t, 256> t{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1u) ? (poly ^ (c >> 1)) : (c >> 1);
    t[i] = c;
  }
  return t;
}

constexpr auto kCrc32Table = make_table(0xEDB88320u);   // reflected 0x04C11DB7
constexpr auto kCrc32cTable = make_table(0x82F63B78u);  // reflected 0x1EDC6F41 (Castagnoli)

std::uint32_t crc(const std::array<std::uint32_t, 256>& table, ByteView data) {
  std::uint32_t c = 0xFFFFFFFFu;
  for (auto b : data) c = table[(c ^ b) & 0xFFu] ^ (c >> 8);
  return c ^ 0xFFFFFFFFu;
}

}  // namespace

std::uint32_t crc32_ethernet(ByteView data) { return crc(kCrc32Table, data); }
std::uint32_t crc32c(ByteView data) { return crc(kCrc32cTable, data); }

}  // namespace mcxanon
