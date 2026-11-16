// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "dissect/catalogue.hpp"

#include <cstdint>
#include <string_view>

namespace mcxanon {

enum class Fid : std::uint16_t {
#define FIELD(ident, name, kind) ident,
#include "dissect/fields.def"
#undef FIELD
  count_
};

std::string_view field_name(Fid f);
FieldKind field_kind(Fid f);

}  // namespace mcxanon
