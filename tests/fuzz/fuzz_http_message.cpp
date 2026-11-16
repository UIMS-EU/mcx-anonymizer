// SPDX-License-Identifier: GPL-3.0-or-later
// HTTP/1.1 (feature 007, FR-001 to FR-006): any byte stream fed to the web session
// as one direction (first byte: bit 0 server, bits 1-2 the segment size) never crashes, hangs or
// grows without bound; the head parser, chunk reader and dechunker never read past their input.
#include "fuzz_web_common.hpp"
#include "http/message.hpp"
#include "http/session.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint8_t sel = data[0];
  const std::string_view b(reinterpret_cast<const char*>(data + 1), size - 1);
  http::Head head;
  (void)http::parse_head(b, head);
  const auto c = http::chunk_at(b);
  (void)c;
  const auto d = http::dechunk(b, 1u << 20);
  (void)d;
  fuzz_web::Env env;
  auto conn = std::make_shared<stream::Connection>();
  if ((sel & 1) != 0) {
    for (const char* m : {"GET", "HEAD", "POST", "PUT", "CONNECT", "GET", "DELETE", "GET"}) conn->methods.emplace_back(m);
  }
  auto s = http::open_web_session(*env.http, conn, http::Start::http1);
  static constexpr std::size_t kSeg[] = {1400, 1, 7, 65535};
  (void)fuzz_web::drive(*s, b, kSeg[(sel >> 1) & 3]);
  return 0;
}
