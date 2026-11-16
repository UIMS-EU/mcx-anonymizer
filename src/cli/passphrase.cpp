// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/passphrase.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <termios.h>
#include <unistd.h>

namespace mcxanon::cli {
namespace {

Result<std::string> tty_prompt(const char* text) {
  std::FILE* tty = std::fopen("/dev/tty", "r+");
  if (tty == nullptr) return fail(ErrorCode::input, "a passphrase is needed but there is no terminal");
  std::fputs(text, tty);
  std::fflush(tty);
  termios old{};
  const int fd = ::fileno(tty);
  const bool have = ::tcgetattr(fd, &old) == 0;
  if (have) {
    termios quiet = old;
    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    ::tcsetattr(fd, TCSAFLUSH, &quiet);
  }
  std::string line;
  for (int c = std::fgetc(tty); c != EOF && c != '\n'; c = std::fgetc(tty)) line.push_back(static_cast<char>(c));
  if (have) ::tcsetattr(fd, TCSAFLUSH, &old);
  std::fputs("\n", tty);
  std::fclose(tty);
  return line;
}

}  // namespace

PassphraseInputs passphrase_inputs_from_environment(const std::string& file_option) {
  PassphraseInputs in;
  if (!file_option.empty()) in.file = file_option;
  if (const char* e = std::getenv("MCXANON_PASSPHRASE")) in.env = std::string(e);  // NOLINT(concurrency-mt-unsafe)
  if (::isatty(STDIN_FILENO) != 0) in.prompt = tty_prompt;
  return in;
}

Result<std::string> get_passphrase(const PassphraseInputs& in, bool confirm) {
  std::string pw;
  if (in.file) {
    std::ifstream f(*in.file, std::ios::binary);
    if (!f) return fail(ErrorCode::input, "cannot read the passphrase file " + in.file->filename().string());
    std::getline(f, pw);
    if (!pw.empty() && pw.back() == '\r') pw.pop_back();
  } else if (in.env) {
    pw = *in.env;
  } else if (in.prompt) {
    auto a = in.prompt("Passphrase: ");
    if (!a) return std::unexpected(a.error());
    if (confirm) {
      auto b = in.prompt("Repeat passphrase: ");
      if (!b) return std::unexpected(b.error());
      if (*a != *b) return fail(ErrorCode::usage, "the passphrases do not match");
    }
    pw = *a;
  } else {
    return fail(ErrorCode::input,
                "a passphrase is needed: use --passphrase-file, MCXANON_PASSPHRASE or a terminal");
  }
  if (pw.empty()) return fail(ErrorCode::usage, "the passphrase must not be empty");
  return pw;
}

}  // namespace mcxanon::cli
