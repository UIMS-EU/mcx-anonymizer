// SPDX-License-Identifier: GPL-3.0-or-later
// The scanner's own framing walker and harvester over arbitrary files, with and without the
// pseudonym list that covers text-encoded matches of 4-byte tokens.
#include "mcxanon/scan.hpp"

#include <cstdio>
#include <string>
#include <unistd.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const mcxanon::scan::Index tokens(std::vector<mcxanon::scan::Token>{
      {mcxanon::scan::TokenCategory::ipv4, {10, 1, 2, 3}, "a"},
      {mcxanon::scan::TokenCategory::mac, {0, 1, 2, 3, 4, 5}, "b"},
      {mcxanon::scan::TokenCategory::deny, {'s', 'e', 'c', 'r', 'e', 't'}, "c"}});
  static const mcxanon::scan::Index covered(
      std::vector<mcxanon::scan::Token>{{mcxanon::scan::TokenCategory::ipv4, {10, 1, 2, 3}, "a"},
                                        {mcxanon::scan::TokenCategory::binary, {0x12, 0x34, 0x56, 0x78}, "d"},
                                        {mcxanon::scan::TokenCategory::string, {'c', 'a', 'n', 'a', 'r', 'y'}, "e"}},
      std::vector<std::string>{"d-0a010203", "0a010203", "x0A010203y", "305419896", "u-305419896",
                               std::string(1024, '0'), "abcd"});
  char path[] = "/tmp/mcxanon-fuzz-XXXXXX";
  const int fd = ::mkstemp(path);
  if (fd < 0) return 0;
  if (::write(fd, data, size) != static_cast<ssize_t>(size)) {
    ::close(fd);
    ::unlink(path);
    return 0;
  }
  (void)mcxanon::scan::scan_fd(fd, tokens);
  (void)mcxanon::scan::scan_fd(fd, covered);
  (void)mcxanon::scan::scan_file(path, covered);
  ::close(fd);
  (void)mcxanon::scan::harvest_input(path);
  (void)mcxanon::scan::scan_bytes({data, size}, tokens);
  ::unlink(path);
  return 0;
}
