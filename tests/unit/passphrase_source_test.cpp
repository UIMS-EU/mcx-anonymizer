// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/passphrase.hpp"
#include "temp_dir.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>

using namespace mcxanon;
using namespace mcxanon::cli;

TEST_CASE("passphrase precedence: file > environment > prompt", "[passphrase]") {
  test::TempDir tmp;
  const auto file = tmp.path() / "pw.txt";
  std::ofstream(file) << "from-file\n";
  PassphraseInputs in;
  in.file = file;
  in.env = "from-env";
  in.prompt = [](const char*) -> Result<std::string> { return std::string("from-prompt"); };
  CHECK(*get_passphrase(in, false) == "from-file");  // trailing newline stripped
  in.file.reset();
  CHECK(*get_passphrase(in, false) == "from-env");
  in.env.reset();
  CHECK(*get_passphrase(in, false) == "from-prompt");
}

TEST_CASE("a new passphrase is asked twice and must match", "[passphrase]") {
  PassphraseInputs in;
  int n = 0;
  in.prompt = [&](const char*) -> Result<std::string> { return std::string(++n == 1 ? "a-long-one" : "different"); };
  auto r = get_passphrase(in, true);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::usage);
}

TEST_CASE("no source and no terminal is an input error; empty passphrases are rejected", "[passphrase]") {
  PassphraseInputs in;
  auto r = get_passphrase(in, false);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().code == ErrorCode::input);
  in.env = "";
  CHECK_FALSE(get_passphrase(in, false).has_value());
  test::TempDir tmp;
  in.env.reset();
  in.file = tmp.path() / "missing";
  CHECK_FALSE(get_passphrase(in, false).has_value());
}
