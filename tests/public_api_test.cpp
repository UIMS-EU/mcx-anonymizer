// SPDX-License-Identifier: GPL-3.0-or-later
// FR-044: the public API reports failures as values. Failure of large
// allocations (>= 64 KiB: I/O buffers, records, the mapping) is injected through
// a replaced global operator new; no exception may escape. (Small allocations
// are not failed: some third-party destructors allocate and are noexcept, so a
// failure there terminates any program, not only this one.)
#include "mcxanon/anonymize.hpp"
#include "mcxanon/error.hpp"
#include "mcxanon/project.hpp"
#include "mcxanon/report.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <new>
#include <unistd.h>

namespace {
std::atomic<long> g_countdown{-1};  // -1: never fail
}

void* operator new(std::size_t n) {
  if (n >= 65536 && g_countdown.load() >= 0 && g_countdown.fetch_sub(1) == 0) throw std::bad_alloc();
  if (void* p = std::malloc(n == 0 ? 1 : n)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

int main() {
  namespace fs = std::filesystem;
  char tmpl[] = "/tmp/mcxanon-api-XXXXXX";
  if (::mkdtemp(tmpl) == nullptr) return 2;
  const fs::path dir(tmpl);
  const mcxanon::DataDirResolution where{dir / "data", mcxanon::DataDirSource::flag};
  // A minimal pcap with one Ethernet/IPv4/UDP packet.
  const unsigned char pcap[] = {
      0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
      1, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 42, 0, 0, 0,
      0, 1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 10, 8, 0,
      0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
      0, 1, 0, 2, 0, 8, 0, 0};
  std::ofstream(dir / "in.pcap", std::ios::binary).write(reinterpret_cast<const char*>(pcap), sizeof pcap);

  int failures = 0;
  int outcomes = 0;
  for (long n = 0; n < 12; ++n) {
    try {
      g_countdown = n;
      auto created = mcxanon::Project::create(where, "p" + std::to_string(n));
      g_countdown = -1;
      if (!created) {
        if (created.error().code != mcxanon::ErrorCode::internal) ++failures;
        continue;
      }
      mcxanon::AnonymizeFileRequest req;
      req.input = dir / "in.pcap";
      req.output = dir / ("out" + std::to_string(n) + ".pcap");
      g_countdown = n;
      auto r = mcxanon::anonymize_file(*created, req);
      g_countdown = -1;
      ++outcomes;
      if (!r && r.error().code != mcxanon::ErrorCode::internal &&
          r.error().code != mcxanon::ErrorCode::input) {
        ++failures;
      }
    } catch (...) {
      g_countdown = -1;
      std::fprintf(stderr, "exception escaped the public API at allocation %ld\n", n);
      ++failures;
    }
  }
  g_countdown = -1;
  std::error_code ec;
  fs::remove_all(dir, ec);
  std::printf("public API: %d runs, %d failures\n", outcomes, failures);
  if (outcomes == 0) ++failures;
  return failures == 0 ? 0 : 1;
}
