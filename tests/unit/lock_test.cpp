// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "pseudo/lock.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <thread>

using namespace mcxanon;
namespace fs = std::filesystem;

TEST_CASE("an exclusive lock makes a second acquirer busy", "[lock]") {
  test::TempDir tmp;
  const fs::path lock = tmp.path() / "lock";
  auto first = ProjectLock::acquire(lock, /*wait=*/false);
  REQUIRE(first.has_value());
  auto second = ProjectLock::acquire(lock, false);
  REQUIRE_FALSE(second.has_value());
  CHECK(second.error().code == ErrorCode::busy);
}

TEST_CASE("the lock is released on destruction", "[lock]") {
  test::TempDir tmp;
  const fs::path lock = tmp.path() / "lock";
  { auto first = ProjectLock::acquire(lock, false); REQUIRE(first.has_value()); }
  CHECK(ProjectLock::acquire(lock, false).has_value());
}

TEST_CASE("wait mode blocks until release", "[lock]") {
  test::TempDir tmp;
  const fs::path lock = tmp.path() / "lock";
  auto acquired = ProjectLock::acquire(lock, false);
  REQUIRE(acquired.has_value());
  std::optional<ProjectLock> first(std::move(*acquired));
  std::atomic<bool> got{false};
  std::thread t([&] {
    auto second = ProjectLock::acquire(lock, /*wait=*/true);
    got = second.has_value();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  CHECK_FALSE(got.load());
  first.reset();
  t.join();
  CHECK(got.load());
}

TEST_CASE("stale temporary files are removed when the lock is taken", "[lock]") {
  test::TempDir tmp;
  std::ofstream(tmp.path() / "mapping.map.json.tmp-1a2b3c") << "partial";
  std::ofstream(tmp.path() / "mapping.map.json") << "{}";
  auto l = ProjectLock::acquire(tmp.path() / "lock", false);
  REQUIRE(l.has_value());
  CHECK_FALSE(fs::exists(tmp.path() / "mapping.map.json.tmp-1a2b3c"));
  CHECK(fs::exists(tmp.path() / "mapping.map.json"));
}
