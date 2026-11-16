// SPDX-License-Identifier: GPL-3.0-or-later
//
// Report format 4 (feature 003). Schema conformance of a fully
// populated report is checked by the CTest report-schema (tests/report_sample_main.cpp).
#include "mcxanon/report.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>

using namespace mcxanon;

namespace {
Report with_xml() {
  Report r;
  r.xml_ruleset = {"mcxanon-xml", "1.0.0", std::string(64, 'c')};
  XmlReport x;
  x.bodies["application/vnd.3gpp.mcptt-info+xml"]["rewritten"] = 12;
  x.bodies["application/vnd.3gpp.mcptt-info+xml"]["malformed"] = 1;
  x.elements["urn:3gpp:ns:mcpttInfo:1.0 session-type"]["keep"] = 12;
  x.elements["urn:3gpp:ns:mcpttInfo:1.0 mcpttURI"]["pseudonymise"] = 12;
  x.attributes["urn:3gpp:ns:mcpttInfo:1.0 mcptt-request-uri @ type"]["keep"] = 12;
  x.removed.namespaces["(invalid-name)"] = 2;
  x.removed.comments = 1;
  x.removed.encrypted = 4;
  x.embedded["rewritten"] = 2;
  r.xml = x;
  return r;
}
}  // namespace

TEST_CASE("report format 4 carries the xml ruleset and the xml object", "[report][format4]") {
  const auto j = nlohmann::json::parse(to_json(with_xml()));
  CHECK(j["format"] == 6);  // feature 007
  CHECK(j["xml_ruleset"]["name"] == "mcxanon-xml");
  const auto& x = j["xml"];
  CHECK(x["bodies"]["application/vnd.3gpp.mcptt-info+xml"]["rewritten"] == 12);
  CHECK(x["elements"]["urn:3gpp:ns:mcpttInfo:1.0 mcpttURI"]["pseudonymise"] == 12);
  CHECK(x["attributes"]["urn:3gpp:ns:mcpttInfo:1.0 mcptt-request-uri @ type"]["keep"] == 12);
  CHECK(x["removed"]["namespaces"]["(invalid-name)"] == 2);
  CHECK(x["removed"]["comments"] == 1);
  CHECK(x["removed"]["processing_instructions"] == 0);
  CHECK(x["removed"]["encrypted"] == 4);
  CHECK(x["embedded"]["rewritten"] == 2);
  CHECK(x["limits"]["max_depth"] == 32);
  CHECK(x["limits"]["max_elements"] == 10000);
  CHECK(x["limits"]["max_attributes"] == 64);
  CHECK(x["limits"]["max_name_bytes"] == 256);
  CHECK(x["limits"]["max_value_bytes"] == 65536);
  CHECK(x["limits"]["max_body_bytes"] == 1048576);
  CHECK(x["limits"]["max_embed_depth"] == 1);
}

TEST_CASE("report format 4 without xml has no xml object", "[report][format4]") {
  Report r;
  const auto j = nlohmann::json::parse(to_json(r));
  CHECK(j["format"] == 6);  // feature 007
  CHECK_FALSE(j.contains("xml"));
  CHECK_FALSE(j.contains("xml_ruleset"));
}

TEST_CASE("report format 4 states what the XML layer keeps", "[report][format4]") {
  const auto j = nlohmann::json::parse(to_json(with_xml()));
  std::string all;
  for (const auto& s : j["not_anonymised"]) all += s.get<std::string>() + "\n";
  CHECK(all.find("MCX XML bodies: the element and attribute structure") != std::string::npos);
  CHECK(all.find("MCX XML bodies: enumerated and boolean values") != std::string::npos);
  CHECK(all.find("MCX XML bodies: the configured location triggers") != std::string::npos);
  CHECK(all.find("MCX XML bodies: body lengths") != std::string::npos);
  CHECK(all.find("MCX XML bodies: signature and encryption algorithm identifiers") != std::string::npos);
}
