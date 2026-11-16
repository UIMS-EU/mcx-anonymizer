// SPDX-License-Identifier: GPL-3.0-or-later
#include "dissect/catalogue.hpp"

#include <algorithm>

namespace mcxanon {

void Catalogue::add(FieldDecl decl) { decls_.push_back(std::move(decl)); }

const FieldDecl* Catalogue::find(std::string_view id) const {
  const auto it =
      std::find_if(decls_.begin(), decls_.end(), [&](const FieldDecl& d) { return d.id == id; });
  return it == decls_.end() ? nullptr : &*it;
}

}  // namespace mcxanon
