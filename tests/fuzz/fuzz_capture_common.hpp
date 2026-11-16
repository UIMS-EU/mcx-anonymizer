// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "capture/reader.hpp"
#include "capture/writer.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace mcxanon::fuzz {

// Reads every record; whatever is read must write back byte for byte.
inline void read_capture(const std::uint8_t* data, std::size_t size) {
  auto reader = CaptureReader::from_memory(Bytes(data, data + size));
  if (!reader) return;
  auto writer = CaptureWriter::to_memory();
  std::size_t total = 0;
  for (int i = 0; i < 100000; ++i) {
    auto rec = reader->next();
    if (!rec || !rec->has_value()) break;
    total += (*rec)->bytes.size();
    if (!writer.write(**rec)) std::abort();
  }
  if (writer.memory().size() != total) std::abort();
  for (std::size_t i = 0; i < total; ++i) {
    if (writer.memory()[i] != data[i]) std::abort();  // records are a prefix of the input
  }
}

}  // namespace mcxanon::fuzz
