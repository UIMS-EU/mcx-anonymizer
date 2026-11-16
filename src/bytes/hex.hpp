// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcxanon/error.hpp"

#include "bytes/bytes.hpp"

#include <string>
#include <string_view>

namespace mcxanon {

std::string to_hex(ByteView b, bool upper = false);
Result<Bytes> from_hex(std::string_view s);

}  // namespace mcxanon
