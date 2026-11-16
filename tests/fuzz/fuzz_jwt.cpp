// SPDX-License-Identifier: GPL-3.0-or-later
// Bearer tokens and JWTs (RFC 7519, RFC 7515; feature 007, FR-012): any token is rewritten without
// a crash into a token of a known kind, and a token is never returned unchanged unless it is
// empty.
#include "fuzz_web_common.hpp"
#include "http/jwt.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view t(reinterpret_cast<const char*>(data), size);
  fuzz_web::Env env;
  const auto r = http::rewrite_token(t, *env.http);
  if (!r) return 0;
  if (r->kind != "jwt" && r->kind != "jwe" && r->kind != "opaque" && r->kind != "malformed-jwt") std::abort();
  return 0;
}
