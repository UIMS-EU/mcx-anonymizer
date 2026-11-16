// SPDX-License-Identifier: GPL-3.0-or-later
// The MIKEY carrier encodings (feature 005, FR-021): base64 with its line layout, binary, and
// hexBinary with its case and surrounding whitespace. The first byte selects the carrier and, for
// bodies, the Content-Transfer-Encoding; whatever decodes must re-encode to bytes that decode to
// the same message, with no crash, hang or sanitizer report.
#include "mikey/carrier.hpp"
#include "policy/mikey_rules.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

using namespace mcxanon;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const MikeyRuleSet rules = [] {
    auto r = load_embedded_mikey_ruleset();
    if (!r) std::abort();
    return *r;
  }();
  if (size == 0) return 0;
  const auto kind = static_cast<sip::MikeyCarrierKind>(data[0] % 4);
  constexpr std::string_view kCte[] = {"", "base64", "binary", "x-token"};
  const std::string_view cte = kCte[(data[0] >> 2) % 4];
  const std::string_view value(reinterpret_cast<const char*>(data) + 1, size - 1);
  const auto form = mikey::decode_carrier(kind, value, cte, rules);
  if (!form) return 0;
  const std::string again = mikey::encode_carrier(*form, form->bytes);
  const auto back = mikey::decode_carrier(kind, again, cte, rules);
  if (!back || back->bytes != form->bytes) std::abort();
  return 0;
}
