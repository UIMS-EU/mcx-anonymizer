// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scanner's XML vocabulary table equals the namespace names, local names,
// enumeration values and standard URI values of the embedded XML rule set. The scanner never
// reads the rules; only this test does.
#include "mcxanon/scan.hpp"

#include "bytes/bytes.hpp"
#include "policy/xml_rules.hpp"
#include "scan/walker/xml_vocabulary.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <vector>

using namespace mcxanon;

TEST_CASE("the scanner XML vocabulary equals the names and values of the XML rule set", "[scan][xml][vocabulary]") {
  auto rs = load_embedded_xml_ruleset();
  REQUIRE(rs.has_value());
  std::set<std::string> expected;
  const auto values = [&](const XmlItemRule& r) {
    if (!r.value) return;
    if (r.value->kind == XmlValueType::Kind::enumeration || r.value->kind == XmlValueType::Kind::std_uri) {
      for (const auto& v : r.value->values) expected.insert(v);
    }
  };
  for (const auto& [ct, d] : rs->documents) {
    for (const auto& root : d.roots) {
      expected.insert(root.ns);
      expected.insert(root.local);
    }
  }
  for (const auto& [name, ns] : rs->namespaces) {
    expected.insert(name);
    for (const auto& [local, rules] : ns.elements) {
      expected.insert(local);
      for (const auto& e : rules) {
        for (const auto& p : e.parents) expected.insert(p);
        values(e.rule);
      }
    }
    for (const auto& a : ns.attributes) {
      if (a.element != "*") expected.insert(a.element);
      if (!a.ns.empty()) expected.insert(a.ns);
      expected.insert(a.local);
      values(a.rule);
    }
  }
  std::set<std::string> actual;
  for (auto t : scan::detail::xml_vocabulary()) actual.insert(std::string(t));
  for (const auto& e : expected) {
    INFO("missing from the scanner XML vocabulary: " << e);
    CHECK(actual.contains(e));
  }
  for (const auto& a : actual) {
    INFO("not a name or value of the XML rule set: " << a);
    CHECK(expected.contains(a));
  }
}

TEST_CASE("xml vocabulary lookup is exact and case-sensitive", "[scan][xml][vocabulary]") {
  CHECK(scan::detail::in_xml_vocabulary("urn:3gpp:ns:mcpttInfo:1.0"));
  CHECK(scan::detail::in_xml_vocabulary("mcpttinfo"));
  CHECK_FALSE(scan::detail::in_xml_vocabulary("MCPTTINFO"));
  CHECK_FALSE(scan::detail::in_xml_vocabulary("alice.nowak"));
}

TEST_CASE("xml vocabulary containment is case-insensitive", "[scan][xml][vocabulary]") {
  // The GKTP namespace declaration stays in the output; a removed element named GKTP must not be
  // searched for (it would match inside "urn:3gpp:ns:mcpttGKTP:1.0").
  CHECK(scan::detail::within_xml_vocabulary("GKTP"));
  CHECK(scan::detail::within_xml_vocabulary("MCPTTINFO"));
  CHECK_FALSE(scan::detail::within_xml_vocabulary("alice.nowak"));
}

TEST_CASE("string tokens inside the XML vocabulary are unscannable", "[scan][xml][vocabulary]") {
  // A user part "alias" seen earlier in the project must not hit the kept element name
  // functional-alias-URI (002, extended to the XML vocabulary).
  const std::vector<scan::Token> t{{scan::TokenCategory::string, Bytes{'a', 'l', 'i', 'a', 's'}, "u-1"},
                                   {scan::TokenCategory::deny, Bytes{'a', 'l', 'i', 'a', 's'}, "deny#1"}};
  const scan::Index ix(t);
  const std::string data = "<functional-alias-URI type=\"Normal\">";
  const auto r = scan::scan_bytes({reinterpret_cast<const std::uint8_t*>(data.data()), data.size()}, ix);
  CHECK(r.unscannable_by_category.at("string/vocabulary") == 1);
  REQUIRE(r.hits.size() == 1);  // the deny-list entry is still searched
  CHECK(r.hits[0].label == "deny#1");
}

TEST_CASE("the kept-value field table equals the rule set's free tokens and wide integers", "[scan][xml][vocabulary]") {
  auto rs = load_embedded_xml_ruleset();
  REQUIRE(rs.has_value());
  std::set<std::string> expected;
  const auto kept = [](const XmlItemRule& r) {
    if (r.action != XmlAction::keep || !r.value) return false;
    const auto& v = *r.value;
    if (v.kind == XmlValueType::Kind::token) {
      return v.grammar == XmlTokenGrammar::trigger_id || v.grammar == XmlTokenGrammar::hex_counter ||
             v.grammar == XmlTokenGrammar::ncname || v.grammar == XmlTokenGrammar::rfc_token;
    }
    return v.kind == XmlValueType::Kind::integer && (v.max > 999999 || v.min < -999999);
  };
  for (const auto& [name, ns] : rs->namespaces) {
    for (const auto& [local, rules] : ns.elements) {
      for (const auto& e : rules) {
        if (kept(e.rule)) expected.insert(local);
      }
    }
    for (const auto& a : ns.attributes) {
      if (kept(a.rule)) expected.insert(a.local);
    }
  }
  std::set<std::string> actual;
  for (auto t : scan::detail::xml_kept_value_fields()) actual.insert(std::string(t));
  CHECK(actual == expected);
}
