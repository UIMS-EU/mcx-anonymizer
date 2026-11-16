// SPDX-License-Identifier: GPL-3.0-or-later
//
// Report format 2 (feature 002). Schema conformance of a fully populated
// report is checked by the CTest report-schema (tests/report_sample_main.cpp).
#include "mcxanon/report.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>

using namespace mcxanon;

namespace {
Report with_sip() {
  Report r;
  r.sip_ruleset = {"mcxanon-sip", "1.0.0", std::string(64, 'b')};
  SipReport s;
  s.requests["INVITE"] = 2;
  s.requests["X Bad Method"] = 1;         // not a token
  s.requests[std::string(65, 'A')] = 1;   // too long
  s.responses["2xx"] = 2;
  s.malformed = 1;
  s.headers["From"]["pseudonymise"] = 2;
  s.malformed_headers["P-Asserted-Identity"] = 1;
  s.removed_unknown["sip-header"]["X-Vendor-Id"] = 3;
  s.removed_unknown["sip-header"]["X:Bad"] = 1;
  s.removed_unknown["sip-header"]["Bad\xff"] = 1;
  s.removed_unknown["content-type"]["application/x-thing"] = 1;
  s.removed_unknown["content-type"]["application"] = 1;  // no subtype
  s.sdp["o="]["pseudonymise"] = 2;
  s.bodies["application/sdp"]["sdp"] = 2;
  s.tcp.bytes_unframable = 5;
  s.fragments.datagrams_zeroed["missing"] = 1;
  s.limits.max_message_bytes = 1048576;
  r.sip = s;
  r.scan.unscannable_by_category["string/vocabulary"] = 2;
  return r;
}
}  // namespace

TEST_CASE("the report is format 2 with the SIP rule set", "[report][format2]") {
  const auto j = nlohmann::json::parse(to_json(with_sip()));
  CHECK(j["format"] == 6);  // feature 007
  CHECK(j["sip_ruleset"]["name"] == "mcxanon-sip");
  CHECK(j["sip_ruleset"]["digest"] == std::string(64, 'b'));
  CHECK(j["sip"]["messages"]["requests"]["INVITE"] == 2);
  CHECK(j["sip"]["messages"]["malformed"] == 1);
  CHECK(j["sip"]["headers"]["From"]["pseudonymise"] == 2);
  CHECK(j["sip"]["tcp"]["bytes_unframable"] == 5);
  CHECK(j["sip"]["fragments"]["datagrams_zeroed"]["missing"] == 1);
  CHECK(j["sip"]["limits"]["max_message_bytes"] == 1048576);
  CHECK(j["scan"]["unscannable_by_category"]["string/vocabulary"] == 2);
}

TEST_CASE("names outside the token grammar are reported as (invalid-name)", "[report][format2]") {
  CHECK(report_name("X-Vendor-Id") == "X-Vendor-Id");
  CHECK(report_name("a.b!c%d*e_f+g`h~i") == "a.b!c%d*e_f+g`h~i");
  CHECK(report_name("") == "(invalid-name)");
  CHECK(report_name("X Bad") == "(invalid-name)");
  CHECK(report_name("X:Bad") == "(invalid-name)");
  CHECK(report_name("O'Brien") == "(invalid-name)");  // the schema excludes the apostrophe
  CHECK(report_name(std::string(64, 'a')) == std::string(64, 'a'));
  CHECK(report_name(std::string(65, 'a')) == "(invalid-name)");
  CHECK(report_name("application/vnd.3gpp.mcptt-info+xml", true) ==
        "application/vnd.3gpp.mcptt-info+xml");
  CHECK(report_name("application", true) == "(invalid-name)");
  CHECK(report_name("a/b/c", true) == "(invalid-name)");
  CHECK(report_name("text/pl ain", true) == "(invalid-name)");

  const auto j = nlohmann::json::parse(to_json(with_sip()));
  const auto& req = j["sip"]["messages"]["requests"];
  CHECK(req.size() == 2);
  CHECK(req["(invalid-name)"] == 2);  // both invalid names counted together
  const auto& hdr = j["sip"]["removed_unknown"]["sip-header"];
  CHECK(hdr["X-Vendor-Id"] == 3);
  CHECK(hdr["(invalid-name)"] == 2);
  const auto& ct = j["sip"]["removed_unknown"]["content-type"];
  CHECK(ct["application/x-thing"] == 1);
  CHECK(ct["(invalid-name)"] == 1);
  const std::string text = to_json(with_sip());
  CHECK(text.find("X Bad Method") == std::string::npos);
  CHECK(text.find("X:Bad") == std::string::npos);
}

TEST_CASE("the sip object is absent without a SIP report", "[report][format2]") {
  Report r;
  r.command = "scan";
  const auto j = nlohmann::json::parse(to_json(r));
  CHECK(j["format"] == 6);  // feature 007
  CHECK_FALSE(j.contains("sip"));
  CHECK_FALSE(j.contains("sip_ruleset"));
}
