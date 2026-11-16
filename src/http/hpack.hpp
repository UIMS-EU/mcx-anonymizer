// SPDX-License-Identifier: GPL-3.0-or-later
//
// HPACK (RFC 7541; feature 007): a decoder for the input's header blocks with the
// dynamic table of one direction, and an encoder whose output never touches the receiver's
// dynamic table: every field is a literal without indexing (§6.2.2) with an indexed name when
// the static table has the name, and raw (non-Huffman) strings.
#pragma once

#include <cstddef>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcxanon::http {

struct HeaderField {
  std::string name;
  std::string value;
};

class HpackDecoder {
 public:
  // nullopt on any error: a bad index, integer, string or Huffman padding, a size update that is
  // not at the start or exceeds the bound, or a decoded list over the bound. After an error the
  // table state is unknown: the caller stops decoding this direction.
  std::optional<std::vector<HeaderField>> decode(std::string_view block);
  [[nodiscard]] std::size_t table_size() const { return size_; }

 private:
  bool add(std::string name, std::string value);
  std::optional<std::pair<std::string, std::string>> entry(std::size_t index) const;
  std::deque<std::pair<std::string, std::string>> table_;
  std::size_t size_ = 0;
  std::size_t max_ = 4096;  // SETTINGS_HEADER_TABLE_SIZE initial value (RFC 9113 §6.5.2)
};

std::string hpack_encode(const std::vector<HeaderField>& fields);

// RFC 7541 §5.2 and Appendix B: nullopt on an EOS symbol, padding longer than 7 bits or not all
// ones, or a code that is not in the table.
std::optional<std::string> huffman_decode(std::string_view s);
std::string huffman_encode(std::string_view s);  // used by tests and fixtures only

}  // namespace mcxanon::http
