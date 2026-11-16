// SPDX-License-Identifier: GPL-3.0-or-later
// TLS in the clear (feature 007, FR-018 to FR-023): a client and a server
// direction sharing one connection (the first two octets: the length of the client part, the
// third: the segment size) never crash, hang or grow without bound, whatever the record lengths,
// handshake fragmentation, extensions or certificates.
#include "fuzz_web_common.hpp"
#include "tls/handshake.hpp"
#include "tls/session.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 3) return 0;
  const std::size_t split = std::min<std::size_t>(size - 3, static_cast<std::size_t>(data[0]) << 8 | data[1]);
  static constexpr std::size_t kSeg[] = {1400, 1, 5, 65535};
  const std::size_t seg = kSeg[data[2] & 3];
  const std::string_view b(reinterpret_cast<const char*>(data + 3), size - 3);
  fuzz_web::Env env;
  auto conn = std::make_shared<stream::Connection>();
  auto client = tls::open_tls_session(*env.tls, conn);
  auto server = tls::open_tls_session(*env.tls, conn);
  (void)fuzz_web::drive(*client, b.substr(0, split), seg);
  (void)fuzz_web::drive(*server, b.substr(split), seg);
  // The hello parsers alone, on the raw body.
  auto c2 = std::make_shared<stream::Connection>();
  (void)tls::rewrite_hello(b, (data[2] & 4) != 0, *c2, *env.tls);
  return 0;
}
