// SPDX-License-Identifier: GPL-3.0-or-later
//
// The report self-check (001 R22, FR-038) as amended by feature 003: the fixed `not_anonymised`
// statements are not scanned (they are compiled into the tool), every other part is; XML key
// parts that contain a scan token become "(invalid-name)", the standard parts stay readable.
#include "mcxanon/report.hpp"
#include "mcxanon/scan.hpp"

#include "pipeline/tokens.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {
scan::Index index_of(std::initializer_list<std::string> words) {
  std::vector<scan::Token> t;
  int n = 0;
  for (const auto& w : words) t.push_back({scan::TokenCategory::string, Bytes(w.begin(), w.end()), "input:xml#" + std::to_string(++n)});
  return scan::Index(t);
}
}  // namespace

TEST_CASE("a word of the fixed statements does not withhold the report", "[report][selfcheck]") {
  Report r;
  const auto ix = index_of({"documents", "location report"});
  CHECK(sanitise_report(r, ix));
  CHECK(to_json(r).find("kept documents") != std::string::npos);  // the statement is still there
}

TEST_CASE("a word of the report schema does not withhold the report", "[report][selfcheck]") {
  Report r;
  r.status.result = "published";
  CHECK(sanitise_report(r, index_of({"status", "input", "published", "format"})));
}

TEST_CASE("a short hex value does not hit the rule set digests", "[report][selfcheck]") {
  Report r;
  r.xml_ruleset = {"mcxanon-xml", "1.0.0", "71b5" + std::string(60, 'a')};
  CHECK(sanitise_report(r, index_of({"71b5"})));
}

TEST_CASE("no value is formed across two report strings", "[report][selfcheck]") {
  // 10.112.97.116 is "\npat": a newline before a key starting "pat" must not hit.
  Report r;
  r.status.message = "path";
  const std::vector<scan::Token> t{{scan::TokenCategory::ipv4, Bytes{10, 112, 97, 116}, "ip"}};
  CHECK(sanitise_report(r, scan::Index(t)));
}

TEST_CASE("an input word in a variable part still withholds the report", "[report][selfcheck]") {
  Report r;
  r.status.message = "error near documents";
  CHECK_FALSE(sanitise_report(r, index_of({"documents"})));
}

TEST_CASE("xml key parts with a scan token are redacted part by part", "[report][selfcheck][xml]") {
  Report r;
  XmlReport x;
  x.elements["urn:3gpp:ns:mcpttInfo:1.0 secret-element-x"]["unknown"] = 2;
  x.attributes["urn:3gpp:ns:mcpttInfo:1.0 mcpttinfo @secret-attr-y"]["unknown"] = 1;
  x.removed.namespaces["(invalid-name)"] = 1;
  r.xml = x;
  REQUIRE(sanitise_report(r, index_of({"secret-element-x", "secret-attr-y"})));
  CHECK(r.xml->elements.at("urn:3gpp:ns:mcpttInfo:1.0 (invalid-name)").at("unknown") == 2);
  CHECK(r.xml->attributes.at("urn:3gpp:ns:mcpttInfo:1.0 mcpttinfo @(invalid-name)").at("unknown") == 1);
}
