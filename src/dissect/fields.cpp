// SPDX-License-Identifier: GPL-3.0-or-later
#include "dissect/fields.hpp"

#include <array>

namespace mcxanon {
namespace {
struct Entry {
  std::string_view name;
  FieldKind kind;
};
constexpr std::array<Entry, static_cast<std::size_t>(Fid::count_)> kFields{{
#define FIELD(ident, name, kind) {name, FieldKind::kind},
#include "dissect/fields.def"
#undef FIELD
}};
}  // namespace

std::string_view field_name(Fid f) { return kFields[static_cast<std::size_t>(f)].name; }
FieldKind field_kind(Fid f) { return kFields[static_cast<std::size_t>(f)].kind; }

const Catalogue& Catalogue::builtin() {
  static const Catalogue c = [] {
    Catalogue cat;
    for (const auto& e : kFields) cat.add({std::string(e.name), e.kind});
    return cat;
  }();
  return c;
}

}  // namespace mcxanon
