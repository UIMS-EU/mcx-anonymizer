// SPDX-License-Identifier: GPL-3.0-or-later
//
// Projects: a per-customer secret and pseudonym mapping kept in a local data
// directory. Nothing in a project ever appears in any output.
#pragma once

#include "mcxanon/error.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcxanon {

enum class Platform { linux_like, macos, windows };
enum class DataDirSource { flag, env, portable, platform };

// Inputs of the data-directory resolution; normally filled from the
// environment, injectable for tests.
struct DataDirOptions {
  std::optional<std::filesystem::path> explicit_dir;  // --data-dir
  std::optional<std::string> env_dir;                 // MCXANON_DATA_DIR
  std::optional<std::filesystem::path> executable_dir;
  std::optional<std::string> xdg_data_home;
  std::optional<std::string> home;
  std::optional<std::string> appdata;
  Platform platform = Platform::linux_like;
};

struct DataDirResolution {
  std::filesystem::path path;
  DataDirSource source = DataDirSource::platform;
};

// Precedence: --data-dir, MCXANON_DATA_DIR, an existing mcxanon-data/ next to
// the executable, then the platform's per-user application data directory.
Result<DataDirResolution> resolve_data_dir(const DataDirOptions& options);
DataDirOptions data_dir_options_from_environment();
std::string_view to_string(DataDirSource source);

// Project names: 1-64 characters from [A-Za-z0-9._-], not "." or "..".
bool is_valid_project_name(std::string_view name);

// True for a mapping category name as `project show-map --category` accepts it (mac, ipv4, ...,
// and the text categories sip-user, domain, tel, ...).
bool is_mapping_category(std::string_view name);

struct ProjectInfo {
  std::string name;
  bool encrypted = false;
  std::optional<std::size_t> entries;  // mapping size, plain projects only
};

// One mapping entry for local inspection (`project show-map`).
struct MappingRow {
  std::string category;
  std::string original;
  std::string pseudonym;
  std::uint32_t counter = 0;
  std::uint32_t runs_seen = 0;
};

class Project {
 public:
  // Creates projects/<name>/ with a fresh 256-bit secret and an empty mapping;
  // with a passphrase, the secret and the mapping are encrypted at rest.
  static Result<Project> create(const DataDirResolution& where, std::string_view name,
                                std::optional<std::string_view> passphrase = std::nullopt);
  // Opens and locks an existing project (the passphrase is needed when encrypted).
  static Result<Project> open(const DataDirResolution& where, std::string_view name,
                              bool wait_for_lock,
                              std::optional<std::string_view> passphrase = std::nullopt);
  static Result<bool> is_encrypted(const DataDirResolution& where, std::string_view name);
  static Result<std::vector<ProjectInfo>> list(const DataDirResolution& where);

  Project(Project&&) noexcept;
  Project& operator=(Project&&) noexcept;
  Project(const Project&) = delete;
  Project& operator=(const Project&) = delete;
  ~Project();

  [[nodiscard]] const std::string& name() const;
  [[nodiscard]] const std::filesystem::path& directory() const;
  [[nodiscard]] std::size_t mapping_size() const;
  [[nodiscard]] bool encrypted() const;
  [[nodiscard]] std::vector<MappingRow> mapping_rows() const;

  struct Impl;
  Impl& impl() { return *impl_; }
  [[nodiscard]] const Impl& impl() const { return *impl_; }

 private:
  explicit Project(std::unique_ptr<Impl> impl);
  static Result<Project> create_unguarded(const DataDirResolution& where, std::string_view name,
                                          std::optional<std::string_view> passphrase);
  static Result<Project> open_unguarded(const DataDirResolution& where, std::string_view name,
                                        bool wait_for_lock, std::optional<std::string_view> passphrase);
  std::unique_ptr<Impl> impl_;
};

}  // namespace mcxanon
