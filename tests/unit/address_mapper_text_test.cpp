// SPDX-License-Identifier: GPL-3.0-or-later
//
// The rewriter's view of the text categories: MapperAdapter forwards every
// text method to the Pseudonymiser, so the SIP layer and the packet rewriter share one
// mapping. (Equality of text-form and binary address pseudonyms through the SIP text
// address parser is tested in sip_text_address_test.)
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(3 * i + 5);
  return s;
}
}  // namespace

TEST_CASE("MapperAdapter text methods equal direct Pseudonymiser calls", "[pseudo][adapter]") {
  const auto s = secret();
  Mapping m1, m2;
  Pseudonymiser direct(s, m1);
  Pseudonymiser behind(s, m2);
  MapperAdapter adapter(behind);
  AddressMapper& mapper = adapter;
  for (auto c : {Category::sip_user, Category::display_name, Category::call_id, Category::tag,
                 Category::branch, Category::entity_tag, Category::charging_id,
                 Category::digest, Category::cell_id, Category::boundary,
                 Category::msrp_session, Category::reg_token, Category::cname}) {
    INFO(to_string(c));
    CHECK(*mapper.text(c, "Value-17") == *direct.text(c, "Value-17"));
  }
  CHECK(*mapper.text(Category::imei, "35209900176148") ==
        *direct.text(Category::imei, "35209900176148"));
  CHECK(*mapper.text(Category::uuid, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6") ==
        *direct.text(Category::uuid, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
  CHECK(*mapper.text(Category::session_id, "ab30317f1a784dc48ff824d0d3715d86") ==
        *direct.text(Category::session_id, "ab30317f1a784dc48ff824d0d3715d86"));
  CHECK(*mapper.text(Category::sdp_sess, "2890844526") ==
        *direct.text(Category::sdp_sess, "2890844526"));
  CHECK(*mapper.domain("mcx.example.net") == *direct.domain("mcx.example.net"));
  CHECK(*mapper.tel("+48 601 234 567") == *direct.tel("+48 601 234 567"));
  CHECK(*mapper.sdp_version("2890844526", "2890842807") ==
        *direct.sdp_version("2890844526", "2890842807"));
  CHECK(*mapper.spi(0x01020304u) == *direct.spi(0x01020304u));
  CHECK(*mapper.ssrc(0x01020304u) == *direct.ssrc(0x01020304u));
  // text() of domain and tel delegates to their dedicated forms.
  CHECK(*mapper.text(Category::domain, "ims.example.net") == *direct.domain("ims.example.net"));
  CHECK(*mapper.text(Category::tel, "+48601234567") == *direct.tel("+48601234567"));
}

TEST_CASE("the adapter's address methods share the binary mapping", "[pseudo][adapter]") {
  const auto s = secret();
  Mapping m1, m2;
  Pseudonymiser direct(s, m1);
  Pseudonymiser behind(s, m2);
  MapperAdapter adapter(behind);
  CHECK(*adapter.ipv4(0x0A2D0C22u) == *direct.ipv4(0x0A2D0C22u));
  Ipv6Addr a{0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x10};
  CHECK(*adapter.ipv6(a) == *direct.ipv6(a));
  // An address pseudonymised through the adapter is the same mapping entry the packet
  // rewriter uses: a second call reuses it.
  CHECK(*adapter.ipv4(0x0A2D0C22u) == *adapter.ipv4(0x0A2D0C22u));
  CHECK(behind.stats().new_entries.at("ipv4") == 1);
}
