// SPDX-License-Identifier: GPL-3.0-or-later
//
// The FieldId catalogue: every field a dissector (or the pcapng metadata
// handling) can emit, with its kind. The rule set must classify exactly these
// fields; the kind limits which actions a rule may choose.
#pragma once

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

enum class FieldKind {
  address_mac,
  address_ipv4,
  address_ipv6,
  vlan,
  port,
  numeric,
  length,
  checksum,
  option,
  payload,
  opaque,
  pcapng_block,
  pcapng_option,
};

struct FieldDecl {
  std::string id;
  FieldKind kind = FieldKind::opaque;
};

class Catalogue {
 public:
  void add(FieldDecl decl);
  [[nodiscard]] const FieldDecl* find(std::string_view id) const;
  [[nodiscard]] std::span<const FieldDecl> all() const { return decls_; }
  // The catalogue of everything this build can emit.
  static const Catalogue& builtin();

 private:
  std::vector<FieldDecl> decls_;
};

}  // namespace mcxanon
