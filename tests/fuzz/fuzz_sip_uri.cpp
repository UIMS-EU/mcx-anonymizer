// SPDX-License-Identifier: GPL-3.0-or-later
// URIs, name-addr and every header value grammar; a parsed URI must render and parse again.
#include "sip/header_values.hpp"
#include "sip/render.hpp"
#include "sip/uri.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace mcxanon::sip;
  const std::string_view in(reinterpret_cast<const char*>(data), size);
  if (auto u = parse_uri(in)) {
    if (!parse_uri(render_uri(*u))) std::abort();
  }
  if (auto n = parse_name_addr(in)) (void)render_name_addr(*n);
  (void)parse_name_addr_list(in);
  (void)parse_via(in);
  (void)parse_call_id(in);
  (void)parse_cseq(in);
  for (auto k : {HeadKind::token, HeadKind::number, HeadKind::media_type, HeadKind::session_id}) {
    (void)parse_items(in, k, true);
  }
  (void)parse_auth(in);
  (void)parse_warning(in);
  (void)parse_retry_after(in);
  if (auto d = parse_date(in)) (void)render_date(*d);
  (void)parse_params(in);
  (void)percent_decode(in);
  if (auto a = parse_address_text(in)) (void)format_address(*a);
  return 0;
}
