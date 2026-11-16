// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/scan.hpp"

#include <fstream>
#include <string>

namespace mcxanon::scan {

Result<std::vector<Token>> load_deny_list(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return fail(ErrorCode::usage, "cannot read the deny-list " + path.filename().string());
  std::vector<Token> out;
  std::string line;
  std::size_t n = 0;
  while (std::getline(in, line)) {
    ++n;
    const auto first = line.find_first_not_of(" \t\r");
    if (first == std::string::npos || line[first] == '#') continue;
    const auto last = line.find_last_not_of(" \t\r");
    const std::string entry = line.substr(first, last - first + 1);
    if (entry.size() < 4) {
      return fail(ErrorCode::usage, "deny-list " + path.filename().string() + " line " + std::to_string(n) +
                                        ": entries must have at least 4 characters");
    }
    out.push_back(Token{TokenCategory::deny, std::vector<std::uint8_t>(entry.begin(), entry.end()),
                        "deny#" + std::to_string(n)});
  }
  return out;
}

}  // namespace mcxanon::scan
