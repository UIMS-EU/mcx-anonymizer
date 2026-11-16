// SPDX-License-Identifier: GPL-3.0-or-later
// HTTP/2 over cleartext (feature 007, FR-007): any byte stream fed to the h2 session
// (first byte: bit 0 server side, bits 1-2 the segment size) never crashes, hangs or grows
// without bound, whatever the frames, padding, CONTINUATION sequences or header blocks.
#include "fuzz_web_common.hpp"
#include "http/h2.hpp"
#include "http/session.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint8_t sel = data[0];
  const std::string_view b(reinterpret_cast<const char*>(data + 1), size - 1);
  fuzz_web::Env env;
  auto conn = std::make_shared<stream::Connection>();
  conn->h2_preface = (sel & 1) != 0;
  auto s = http::open_web_session(*env.http, conn, (sel & 1) != 0 ? http::Start::h2_server : http::Start::h2_client);
  static constexpr std::size_t kSeg[] = {1400, 1, 9, 65535};
  (void)fuzz_web::drive(*s, b, kSeg[(sel >> 1) & 3]);
  return 0;
}
