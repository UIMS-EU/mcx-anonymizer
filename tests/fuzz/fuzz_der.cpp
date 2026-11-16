// SPDX-License-Identifier: GPL-3.0-or-later
// DER and X.509 (RFC 5280, X.690; feature 007, FR-021): any input either fails to parse or is DER
// that writes back to the same octets; a certificate rewrite either refuses or yields DER that
// parses again.
#include "fuzz_web_common.hpp"
#include "tls/der.hpp"
#include "tls/x509.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view b(reinterpret_cast<const char*>(data), size);
  const auto n = tls::der::parse(b);
  if (n && tls::der::write(*n) != b) std::abort();  // DER is canonical: parse and write are inverse
  (void)tls::der::parse(b, false);
  fuzz_web::Env env;
  const auto r = tls::rewrite_certificate(b, *env.tls);
  if (r && r->has_value() && !tls::der::parse(**r)) std::abort();
  return 0;
}
