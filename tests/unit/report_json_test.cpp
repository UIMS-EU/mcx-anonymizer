// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/report.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>

using namespace mcxanon;

namespace {
Report sample() {
  Report r;
  r.command = "anonymize";
  r.tool_version = "0.1.0";
  r.ruleset_name = "mcxanon-l2l4";
  r.ruleset_version = "1.0.0";
  r.ruleset_digest = std::string(64, 'a');
  r.files.input = "/very/secret/customer-site/capture.pcapng";
  r.files.output = "/tmp/out/anon.pcapng";
  r.files.input_format = "pcapng";
  r.files.output_format = "pcapng";
  r.files.frames = 42;
  r.counters["ipv4.src"]["pseudonymise"] = 40;
  r.counters["eth.src"]["pseudonymise"] = 42;
  r.counters["eth.type"]["keep"] = 42;
  r.removed_blocks["0x00000004"] = 1;
  r.removed_options["0x00000001/2"] = 1;
  r.unknown_protocols.push_back({"ip_proto", 253, 2});
  r.unknown_protocols.push_back({"ethertype", 0x88b5, 1});
  r.scan.performed = true;
  r.scan.tokens = 10;
  r.scan.hits.push_back({3, 1234, "text", "ipv4", "240.1.2.3"});
  return r;
}
}  // namespace

TEST_CASE("report JSON is deterministic with sorted keys", "[report]") {
  const std::string a = to_json(sample());
  const std::string b = to_json(sample());
  CHECK(a == b);
  CHECK(a.find("\"checksums\"") < a.find("\"command\""));
  CHECK(a.find("\"eth.src\"") < a.find("\"ipv4.src\""));
  // Unknown protocols are sorted by kind, then id.
  CHECK(a.find("\"ethertype\"") < a.find("\"ip_proto\""));
}

TEST_CASE("report keeps base names only", "[report]") {
  const std::string j = to_json(sample());
  CHECK(j.find("customer-site") == std::string::npos);
  CHECK(j.find("/very/secret") == std::string::npos);
  CHECK(j.find("\"capture.pcapng\"") != std::string::npos);
  CHECK(j.find("\"anon.pcapng\"") != std::string::npos);
}

TEST_CASE("report lists what is not anonymised", "[report]") {
  const std::string j = to_json(Report{});
  CHECK(j.find("\"not_anonymised\"") != std::string::npos);
  CHECK(j.find("packet sizes") != std::string::npos);
  CHECK(j.find("TCP timestamp values") != std::string::npos);
  CHECK(j.find("\"format\": 6") != std::string::npos);
}

TEST_CASE("the not-anonymised list carries the SIP statements (FR-037, R9)", "[report][sip]") {
  const auto v = not_anonymised_statements(Report::Options{});
  const auto has = [&](std::initializer_list<std::string_view> words) {
    return std::any_of(v.begin(), v.end(), [&](const std::string& s) {
      return std::all_of(words.begin(), words.end(),
                         [&](std::string_view w) { return s.find(w) != std::string::npos; });
    });
  };
  // FR-037: the method and response sequence and timing.
  CHECK(has({"SIP", "methods", "response", "timing"}));
  // FR-037: header order and the capability sets, which can fingerprint an implementation.
  CHECK(has({"header order", "Allow", "Supported", "Require", "fingerprint"}));
  // FR-037 with FR-024: the lengths of the values a rule keeps on purpose.
  CHECK(has({"length", "telephone numbers"}));
  // R9: a short-number pseudonym can collide with an original seen later.
  CHECK(has({"short telephone numbers", "collision", "fresh project"}));
  // The statements are in the report itself.
  const std::string j = to_json(Report{});
  for (const auto& s : v) CHECK(j.find(nlohmann::json(s).dump()) != std::string::npos);
}
