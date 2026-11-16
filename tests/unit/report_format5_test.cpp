// SPDX-License-Identifier: GPL-3.0-or-later
//
// Report format 5 (feature 005). Schema conformance of a fully
// populated report is checked by the CTest report-schema (tests/report_sample_main.cpp).
#include "mcxanon/report.hpp"

#include "report/self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>

using namespace mcxanon;

namespace {
Report with_mikey(const std::string& mode = "ciphertext") {
  Report r;
  r.options.encrypted = mode;
  r.mikey_ruleset = {"mcxanon-mikey", "1.0.0", std::string(64, 'd')};
  MikeyReport m;
  m.carriers["sdp"].rewritten = 2;
  m.carriers["sdp"].fallback["malformed"] = 1;
  m.carriers["body"].passed_through = 1;
  m.payloads["SIGN"]["invalidated"] = 2;
  m.payloads["RAND"]["pseudonymised"] = 2;
  m.uids.resolved = 1;
  m.uids.unresolved = 1;
  m.key_ids["PCK"] = 1;
  m.mki.pseudonymised = 10;
  m.encrypted_xml.kept = 2;
  m.encrypted_uri.structured = 1;
  r.mikey = m;
  return r;
}
std::string statements(const nlohmann::json& j) {
  std::string all;
  for (const auto& s : j["not_anonymised"]) all += s.get<std::string>() + "\n";
  return all;
}
}  // namespace

TEST_CASE("report format 5 carries the mikey ruleset, the mikey object and the mode", "[report][format5]") {
  const auto j = nlohmann::json::parse(to_json(with_mikey()));
  CHECK(j["format"] == 6);  // feature 007
  CHECK(j["options"]["encrypted"] == "ciphertext");
  CHECK(j["mikey_ruleset"]["name"] == "mcxanon-mikey");
  const auto& m = j["mikey"];
  CHECK(m["carriers"]["sdp"]["rewritten"] == 2);
  CHECK(m["carriers"]["sdp"]["passed_through"] == 0);
  CHECK(m["carriers"]["sdp"]["fallback"]["malformed"] == 1);
  CHECK(m["carriers"]["body"]["passed_through"] == 1);
  CHECK(m["unexpected_carrier"] == 0);
  CHECK(m["payloads"]["SIGN"]["invalidated"] == 2);
  CHECK(m["uids"]["resolved"] == 1);
  CHECK(m["uids"]["unresolved"] == 1);
  CHECK(m["key_ids"]["PCK"] == 1);
  CHECK(m["mki"]["pseudonymised"] == 10);
  CHECK(m["mki"]["unmatched"] == 0);
  CHECK(m["encrypted_xml"]["kept"] == 2);
  CHECK(m["encrypted_uri"]["structured"] == 1);
  CHECK(m["incomplete"] == 0);
  CHECK(m["limits"]["max_message_bytes"] == 65535);
  CHECK(m["limits"]["max_payloads"] == 64);
  CHECK(m["limits"]["max_id_bytes"] == 1024);
}

TEST_CASE("report format 5 without key management has no mikey object", "[report][format5]") {
  Report r;
  const auto j = nlohmann::json::parse(to_json(r));
  CHECK(j["format"] == 6);  // feature 007
  CHECK_FALSE(j.contains("mikey"));
  CHECK_FALSE(j.contains("mikey_ruleset"));
  CHECK(j["options"]["encrypted"] == "ciphertext");
}

TEST_CASE("report format 5 states the invalidated signatures and the mode", "[report][format5]") {
  const auto c = statements(nlohmann::json::parse(to_json(with_mikey())));
  CHECK(c.find("MIKEY-SAKKE: signatures of rewritten I_MESSAGEs do not verify") != std::string::npos);
  CHECK(c.find("are kept as ciphertext") != std::string::npos);
  CHECK(c.find("passthrough:") == std::string::npos);
  const auto p = statements(nlohmann::json::parse(to_json(with_mikey("passthrough"))));
  CHECK(p.find("passthrough: the output contains original identities") != std::string::npos);
}

TEST_CASE("report format 5: passthrough warnings in the scan object", "[report][format5]") {
  Report r = with_mikey("passthrough");
  r.scan.performed = true;
  r.scan.warnings.push_back(ReportScanWarning{12, 3410, "sdp", "string"});
  const auto j = nlohmann::json::parse(to_json(r));
  REQUIRE(j["scan"]["warnings"].size() == 1);
  CHECK(j["scan"]["warnings"][0]["frame"] == 12);
  CHECK(j["scan"]["warnings"][0]["offset"] == 3410);
  CHECK(j["scan"]["warnings"][0]["carrier"] == "sdp");
  CHECK(j["scan"]["warnings"][0]["category"] == "string");
  // Without passthrough there is no warnings key.
  const auto k = nlohmann::json::parse(to_json(with_mikey()));
  CHECK_FALSE(k["scan"].contains("warnings"));
}

TEST_CASE("report format 5: every new key and word passes the self-check", "[report][format5]") {
  Report r = with_mikey("passthrough");
  r.scan.warnings.push_back(ReportScanWarning{1, 2, "encrypted-xml", "key"});
  const auto items = to_json_for_self_check(r);
  for (const char* w : {"mikey", "carriers", "sdp", "body", "rewritten", "passed_through", "fallback", "malformed",
                        "unexpected_carrier", "payloads", "SIGN", "invalidated", "RAND", "pseudonymised", "uids",
                        "resolved", "unresolved", "key_ids", "PCK", "mki", "unmatched", "ambiguous", "encrypted_xml",
                        "kept", "removed_parts", "encrypted_uri", "structured", "whole_user_part", "incomplete",
                        "limits", "max_message_bytes", "max_payloads", "max_id_bytes", "mikey_ruleset", "encrypted",
                        "passthrough", "warnings", "carrier", "encrypted-xml", "key", "cs_ids"}) {
    CHECK(std::find(items.begin(), items.end(), std::string(w)) == items.end());
  }
}
