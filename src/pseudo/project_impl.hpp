// SPDX-License-Identifier: GPL-3.0-or-later
// Internal state of an open project.
#pragma once

#include "mcxanon/project.hpp"

#include "pseudo/crypto.hpp"
#include "pseudo/hmac.hpp"
#include "pseudo/lock.hpp"
#include "pseudo/mapping.hpp"

#include <filesystem>
#include <string>

namespace mcxanon {

struct Project::Impl {
  Impl(std::string n, std::filesystem::path d, ProjectLock l)
      : name(std::move(n)), dir(std::move(d)), lock(std::move(l)) {}
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;
  ~Impl();

  std::string name;
  std::filesystem::path dir;
  ProjectLock lock;
  Secret secret{};
  Mapping mapping;
  bool encrypted = false;
  KdfParams kdf;
  Key key{};

  [[nodiscard]] std::filesystem::path file(const char* f) const { return dir / f; }
  Result<void> save_mapping() const;
};

}  // namespace mcxanon
