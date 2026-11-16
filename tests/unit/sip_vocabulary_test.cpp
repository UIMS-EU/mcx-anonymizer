// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's vocabulary table equals the names of the SIP rule set; tokens
// in it are unscannable with reason "vocabulary", never searched, and never suppress a hit.
#include "mcxanon/scan.hpp"

#include "bytes/bytes.hpp"
#include "policy/sip_rules.hpp"
#include "scan/walker/sip_vocabulary.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <set>
#include <string>

using namespace mcxanon;

namespace {
std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}
}  // namespace

TEST_CASE("the scanner vocabulary equals the names of the SIP rule set", "[scan][vocabulary]") {
  auto rs = load_embedded_sip_ruleset();
  REQUIRE(rs.has_value());
  std::set<std::string> expected;
  for (const auto& h : rs->headers) {
    expected.insert(lower(h.name));
    for (const auto& a : h.aliases) expected.insert(lower(a));
    for (const auto& p : h.params) expected.insert(lower(p.name));
  }
  for (const auto& p : rs->uri.params) expected.insert(lower(p.name));
  for (const auto& k : rs->uri.keep) expected.insert(lower(k.value));
  for (const auto& s : rs->uri.schemes) expected.insert(lower(s));
  for (const auto& a : rs->sdp_attributes) {
    expected.insert(lower(a.name));
    if (a.format) expected.insert(lower(*a.format));
    for (const auto& p : a.fmtp_params) expected.insert(lower(p.name));
  }
  for (const auto& l : rs->sdp_lines) {
    for (const auto& v : l.keep_values) expected.insert(lower(v));
  }
  for (const auto& b : rs->bodies) expected.insert(lower(b.content_type));
  for (const auto& t : rs->feature_tags) expected.insert(lower(t.name));
  // SIP methods (RFC 3261 §7.1 and the method RFCs of rules/SOURCES.md).
  for (const char* m : {"INVITE", "ACK", "OPTIONS", "BYE", "CANCEL", "REGISTER", "PRACK", "UPDATE",
                        "MESSAGE", "REFER", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO"}) {
    expected.insert(lower(m));
  }
  std::set<std::string> actual;
  for (auto t : scan::detail::sip_vocabulary()) actual.insert(std::string(t));
  for (const auto& e : expected) {
    INFO("missing from the scanner vocabulary: " << e);
    CHECK(actual.contains(e));
  }
  for (const auto& a : actual) {
    INFO("not a name of the rule set: " << a);
    CHECK(expected.contains(a));
  }
}

TEST_CASE("vocabulary tokens are unscannable, short tokens too", "[scan][vocabulary]") {
  CHECK(scan::detail::in_sip_vocabulary("mcptt"));    // inside +g.3gpp.mcptt
  CHECK(scan::detail::in_sip_vocabulary("MCDATA"));   // case-insensitive, inside a Content-Type
  CHECK(scan::detail::in_sip_vocabulary("invite"));
  CHECK_FALSE(scan::detail::in_sip_vocabulary("alice.nowak"));
  const std::vector<scan::Token> t{
      {scan::TokenCategory::string, Bytes{'m', 'c', 'p', 't', 't'}, "u-1"},
      {scan::TokenCategory::string, Bytes{'a', 'l', 'i', 'c', 'e'}, "u-2"},
      {scan::TokenCategory::string, Bytes{'a', 'b'}, "u-3"},
      {scan::TokenCategory::deny, Bytes{'m', 'c', 'p', 't', 't'}, "deny#1"}};
  const scan::Index ix(t);
  const std::string data = "+g.3gpp.mcptt alice";
  const auto r = scan::scan_bytes({reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}, ix);
  CHECK(r.unscannable_by_category.at("string/vocabulary") == 1);
  CHECK(r.unscannable_by_category.at("string/short") == 1);
  // alice is found, and a deny-list entry is searched even when it is vocabulary.
  REQUIRE(r.hits.size() == 2);
  CHECK(std::any_of(r.hits.begin(), r.hits.end(), [](const scan::Hit& h) { return h.label == "u-2"; }));
  CHECK(std::any_of(r.hits.begin(), r.hits.end(), [](const scan::Hit& h) { return h.label == "deny#1"; }));
}
