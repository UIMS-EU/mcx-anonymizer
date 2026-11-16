// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reveal never writes the project (FR-004, SC-003).
#include "mcxanon/project.hpp"
#include "mcxanon/reveal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

using namespace mcxanon;
namespace fs = std::filesystem;

namespace {
std::string slurp(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}
}  // namespace

TEST_CASE("reveal and lookup leave the project files untouched", "[reveal][project]") {
  const fs::path dir = fs::temp_directory_path() / ("mcxanon-reveal-ro-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir);
  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
  DataDirResolution where{dir, DataDirSource::flag};
  {
    auto p = Project::create(where, "ro");
    REQUIRE(p.has_value());
  }
  const fs::path pd = dir / "projects" / "ro";
  const auto secret = slurp(pd / "project.secret");
  const auto mapping = slurp(pd / "mapping.map.json");
  const auto t1 = fs::last_write_time(pd / "project.secret");
  const auto t2 = fs::last_write_time(pd / "mapping.map.json");
  std::optional<Revealer> rv;
  {
    auto p = Project::open(where, "ro", false);
    REQUIRE(p.has_value());
    auto r = Revealer::create(*p);
    REQUIRE(r.has_value());
    rv.emplace(std::move(*r));
    auto l = lookup(*p, "10.0.0.1", LookupDirection::to_pseudonym);
    REQUIRE(l.has_value());
    CHECK(l->empty());
  }
  // The revealer outlives the project.
  std::string out;
  const RevealSink sink = [&](std::span<const std::uint8_t> b) -> Result<void> {
    out.append(reinterpret_cast<const char*>(b.data()), b.size());
    return {};
  };
  const std::string in = "nothing to reveal here";
  REQUIRE(rv->feed(std::span(reinterpret_cast<const std::uint8_t*>(in.data()), in.size()), sink).has_value());
  REQUIRE(rv->finish(sink).has_value());
  CHECK(out == in);
  CHECK(slurp(pd / "project.secret") == secret);
  CHECK(slurp(pd / "mapping.map.json") == mapping);
  CHECK(fs::last_write_time(pd / "project.secret") == t1);
  CHECK(fs::last_write_time(pd / "mapping.map.json") == t2);
  fs::remove_all(dir);
}
