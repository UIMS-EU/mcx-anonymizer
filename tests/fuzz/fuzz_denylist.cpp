// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/scan.hpp"

#include <cstdio>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  char path[] = "/tmp/mcxanon-fuzz-XXXXXX";
  const int fd = ::mkstemp(path);
  if (fd < 0) return 0;
  if (::write(fd, data, size) == static_cast<ssize_t>(size)) {
    auto t = mcxanon::scan::load_deny_list(path);
    if (t) (void)mcxanon::scan::scan_bytes({data, size}, *t);
  }
  ::close(fd);
  ::unlink(path);
  return 0;
}
