// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"
#include "mcxanon/project.hpp"

#include "pseudo/atomic_file.hpp"
#include "pseudo/datadir.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <filesystem>
#include <fstream>
#include <sys/stat.h>

using namespace mcxanon;
namespace fs = std::filesystem;

namespace {
unsigned mode_of(const fs::path& p) {
  struct stat st {};
  REQUIRE(::stat(p.c_str(), &st) == 0);
  return st.st_mode & 0777u;
}
std::string slurp(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), {}};
}
}  // namespace

TEST_CASE("data directory precedence: flag > env > portable > platform", "[project][datadir]") {
  test::TempDir tmp;
  const fs::path portable_parent = tmp.path() / "bin";
  fs::create_directories(portable_parent / "mcxanon-data");
  DataDirOptions o;
  o.platform = Platform::linux_like;
  o.home = (tmp.path() / "home").string();
  o.executable_dir = portable_parent;
  o.env_dir = (tmp.path() / "env").string();
  o.explicit_dir = tmp.path() / "flag";

  auto r = resolve_data_dir(o);
  REQUIRE(r.has_value());
  CHECK(r->source == DataDirSource::flag);
  CHECK(r->path == tmp.path() / "flag");

  o.explicit_dir.reset();
  r = resolve_data_dir(o);
  CHECK(r->source == DataDirSource::env);

  o.env_dir.reset();
  r = resolve_data_dir(o);
  CHECK(r->source == DataDirSource::portable);
  CHECK(r->path == portable_parent / "mcxanon-data");

  fs::remove(portable_parent / "mcxanon-data");
  o.xdg_data_home = (tmp.path() / "xdg").string();
  r = resolve_data_dir(o);
  CHECK(r->source == DataDirSource::platform);
  CHECK(r->path == tmp.path() / "xdg" / "mcxanon");

  o.xdg_data_home.reset();
  r = resolve_data_dir(o);
  CHECK(r->path == tmp.path() / "home" / ".local" / "share" / "mcxanon");

  o.platform = Platform::macos;
  r = resolve_data_dir(o);
  CHECK(r->path == tmp.path() / "home" / "Library" / "Application Support" / "mcxanon");

  o.platform = Platform::windows;
  o.appdata = (tmp.path() / "AppData" / "Roaming").string();
  r = resolve_data_dir(o);
  CHECK(r->path == tmp.path() / "AppData" / "Roaming" / "mcxanon");
}

TEST_CASE("a portable directory that is not writable is an error", "[project][datadir]") {
  if (::geteuid() == 0) SKIP("permission checks do not apply to root");
  test::TempDir tmp;
  const fs::path p = tmp.path() / "mcxanon-data";
  fs::create_directories(p);
  fs::permissions(p, fs::perms::owner_read | fs::perms::owner_exec);
  DataDirOptions o;
  o.platform = Platform::linux_like;
  o.home = tmp.path().string();
  o.executable_dir = tmp.path();
  auto r = resolve_data_dir(o);
  fs::permissions(p, fs::perms::owner_all);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::input);
}

TEST_CASE("project create makes owner-only files and refuses an existing project",
          "[project]") {
  test::TempDir tmp;
  const DataDirResolution where{tmp.path() / "data", DataDirSource::flag};
  auto p = Project::create(where, "acme");
  REQUIRE(p.has_value());
  const fs::path dir = tmp.path() / "data" / "projects" / "acme";
  CHECK(p->directory() == dir);
  CHECK(mode_of(dir) == 0700u);
  for (const char* f : {"project.json", "project.secret", "mapping.map.json", "lock"}) {
    INFO(f);
    REQUIRE(fs::exists(dir / f));
    CHECK(mode_of(dir / f) == 0600u);
  }
  CHECK(fs::file_size(dir / "project.secret") == 32);
  CHECK(slurp(dir / "project.json").find("\"encrypted\": false") != std::string::npos);
  CHECK(slurp(dir / "mapping.map.json").find("\"entries\": []") != std::string::npos);

  auto again = Project::create(where, "acme");
  REQUIRE_FALSE(again.has_value());
  CHECK(again.error().code == ErrorCode::usage);
}

TEST_CASE("two projects get different secrets", "[project]") {
  test::TempDir tmp;
  const DataDirResolution where{tmp.path(), DataDirSource::flag};
  REQUIRE(Project::create(where, "a").has_value());
  REQUIRE(Project::create(where, "b").has_value());
  CHECK(slurp(tmp.path() / "projects" / "a" / "project.secret") !=
        slurp(tmp.path() / "projects" / "b" / "project.secret"));
}

TEST_CASE("project names are validated", "[project]") {
  test::TempDir tmp;
  const DataDirResolution where{tmp.path(), DataDirSource::flag};
  auto bad = GENERATE(as<std::string>{}, "", "..", ".", "a/b", "../x", "with space", "über",
                      std::string(65, 'a'), "a\\b");
  auto r = Project::create(where, bad);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::usage);
  CHECK(Project::create(where, "Good.name_1-x").has_value());
}

TEST_CASE("open loads a project and fails on missing or badly permissioned files",
          "[project]") {
  test::TempDir tmp;
  const DataDirResolution where{tmp.path(), DataDirSource::flag};
  {
    auto p = Project::create(where, "acme");
    REQUIRE(p.has_value());
  }
  {
    auto p = Project::open(where, "acme", /*wait_for_lock=*/false);
    REQUIRE(p.has_value());
    CHECK(p->name() == "acme");
    CHECK(p->mapping_size() == 0);
  }
  auto missing = Project::open(where, "nobody", false);
  REQUIRE_FALSE(missing.has_value());
  CHECK(missing.error().code == ErrorCode::input);
  CHECK(missing.error().message.find("project init") != std::string::npos);

  const fs::path secret = tmp.path() / "projects" / "acme" / "project.secret";
  fs::permissions(secret, fs::perms::group_read, fs::perm_options::add);
  auto loose = Project::open(where, "acme", false);
  REQUIRE_FALSE(loose.has_value());
  CHECK(loose.error().code == ErrorCode::input);
  fs::permissions(secret, fs::perms::group_read, fs::perm_options::remove);

  fs::resize_file(secret, 31);
  auto short_secret = Project::open(where, "acme", false);
  REQUIRE_FALSE(short_secret.has_value());
  CHECK(short_secret.error().code == ErrorCode::input);
}

TEST_CASE("atomic write leaves no partial file when interrupted", "[project][atomic]") {
  test::TempDir tmp;
  const fs::path target = tmp.path() / "file.json";
  REQUIRE(atomic_write(target, "original").has_value());
  CHECK(mode_of(target) == 0600u);

  WriteFaults faults;
  faults.fail_after_bytes = 3;
  const std::string big(1000, 'x');
  auto r = atomic_write(target, big, &faults);
  REQUIRE_FALSE(r.has_value());
  CHECK(slurp(target) == "original");
  std::size_t files = 0;
  for (const auto& e : fs::directory_iterator(tmp.path())) {
    (void)e;
    ++files;
  }
  CHECK(files == 1);  // no temporary left behind

  REQUIRE(atomic_write(target, big).has_value());
  CHECK(slurp(target) == big);
}
