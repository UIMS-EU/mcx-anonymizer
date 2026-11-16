// SPDX-License-Identifier: GPL-3.0-or-later
//
// The MIKEY rule set loader.
#include "policy/mikey_rules.hpp"
#include "policy/ruleset_embedded.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {

const MikeyRuleSet& embedded() {
  static const MikeyRuleSet rs = [] {
    auto r = load_embedded_mikey_ruleset();
    if (!r) FAIL(r.error().message);
    return *r;
  }();
  return rs;
}

Result<MikeyRuleSet> load_text(const std::string& text) {
  std::vector<RuleFile> f{RuleFile{"test.yaml", text}};
  return load_mikey_ruleset(f);
}

// The embedded file with one line replaced, to test the loader's checks on a complete set.
std::string embedded_text() {
  std::string all;
  for (const auto& f : embedded_mikey_rule_files()) all += std::string(f.text);
  return all;
}

std::string replace_once(std::string s, const std::string& from, const std::string& to) {
  const auto p = s.find(from);
  REQUIRE(p != std::string::npos);
  return s.replace(p, from.size(), to);
}

}  // namespace

TEST_CASE("mikey rules: the embedded rule set loads with its name and version", "[mikey][rules]") {
  const auto& rs = embedded();
  CHECK(rs.name == "mcxanon-mikey");
  CHECK_FALSE(rs.version.empty());
  CHECK(rs.digest.size() == 64);
  CHECK(rs.message.data_type == 26);
  CHECK(rs.message.version == 1);
  CHECK(rs.message.v_flag == 0);
  CHECK(rs.message.sign_s_type == 2);
  CHECK(rs.message.max_size == 65535);
  CHECK(rs.message.max_payloads == 64);
  CHECK(rs.message.max_id_data == 1024);
  CHECK(rs.message.mandatory == std::vector<std::string>{"T", "RAND", "IDR", "SAKKE", "SIGN"});
}

TEST_CASE("mikey rules: the payload allowlist", "[mikey][rules]") {
  const auto& rs = embedded();
  const std::pair<unsigned, MikeyAction> expected[] = {
      {5, MikeyAction::shift},  {11, MikeyAction::nonce}, {14, MikeyAction::rewrite}, {10, MikeyAction::rewrite},
      {26, MikeyAction::sakke}, {21, MikeyAction::rewrite}, {4, MikeyAction::zero}};
  for (const auto& [next, action] : expected) {
    const auto* r = rs.payload(next);
    REQUIRE(r != nullptr);
    CHECK(r->action == action);
    CHECK_FALSE(r->source.spec.empty());
  }
  for (unsigned next : {1u, 2u, 3u, 6u, 7u, 8u, 9u, 12u, 20u}) {
    const auto* r = rs.payload(next);
    REQUIRE(r != nullptr);
    CHECK(r->action == MikeyAction::fallback);
  }
}

TEST_CASE("mikey rules: timestamp types, roles and extensions", "[mikey][rules]") {
  const auto& rs = embedded();
  CHECK(rs.ts_types.at(0).action == MikeyAction::shift);
  CHECK(rs.ts_types.at(1).action == MikeyAction::shift);
  CHECK(rs.ts_types.at(2).action == MikeyAction::keep);
  CHECK_FALSE(rs.ts_types.contains(3));
  for (unsigned role : {1u, 2u}) {
    for (unsigned type : {0u, 1u}) CHECK(rs.id_role(role, type)->action == MikeyAction::identity);
  }
  for (unsigned role : {3u, 6u, 7u}) CHECK(rs.id_role(role, 1)->action == MikeyAction::kms);
  for (unsigned role : {8u, 9u, 240u, 241u}) {
    CHECK(rs.id_role(role, 1)->action == MikeyAction::uid);
    CHECK(rs.id_role(role, 2)->action == MikeyAction::uid);
  }
  CHECK(rs.id_role(4, 2)->action == MikeyAction::fallback);
  CHECK(rs.id_role(5, 1)->action == MikeyAction::fallback);
  CHECK(rs.id_role(1, 2) == nullptr);  // IDRi with a byte string: not a defined combination
  CHECK(rs.extensions.at(6).action == MikeyAction::sakke);
  CHECK(rs.extensions.at(7).action == MikeyAction::key_parameters);
  CHECK(rs.extensions.at(0).action == MikeyAction::zero);
  CHECK(rs.extensions.at(1).action == MikeyAction::zero);
}

TEST_CASE("mikey rules: SRTP policy parameters, CS IDs, purpose tags and trailers", "[mikey][rules]") {
  const auto& rs = embedded();
  const auto& srtp = rs.sp.at(0);
  for (unsigned t = 0; t <= 13; ++t) CHECK(srtp.at(t).action == MikeyAction::keep);
  for (unsigned t : {18u, 19u, 20u}) CHECK(srtp.at(t).action == MikeyAction::keep);
  CHECK_FALSE(srtp.contains(14));
  for (unsigned cs = 0; cs <= 9; ++cs) CHECK_FALSE(rs.cs_ids.at(cs).name.empty());
  CHECK(rs.cs_ids.at(4).name == "MCPTT Group Call");
  const char* tags[] = {"GMK", "PCK", "CSK", "SPK", "MKFC", "MSCCK", "MuSiK"};
  for (unsigned t = 0; t < 7; ++t) CHECK(rs.purpose_tags.at(t).name == tags[t]);
  CHECK(rs.default_trailer.at("GMK").first == 4);
  CHECK(rs.default_trailer.at("PCK").first == 0);
  CHECK(rs.default_trailer.at("CSK").first == 0);
  CHECK(rs.default_trailer.at("MuSiK").first == 0);
}

TEST_CASE("mikey rules: the loader rejects what is not a valid rule set", "[mikey][rules]") {
  const std::string base = embedded_text();
  CHECK_FALSE(load_text(replace_once(base, "ruleset: mcxanon-mikey", "ruleset: mcxanon-media")).has_value());
  // An unknown key.
  CHECK_FALSE(load_text(replace_once(base, "\npayloads:", "\nbogus: 1\npayloads:")).has_value());
  // A source document outside rules/SOURCES.md § MIKEY rule set.
  CHECK_FALSE(load_text(replace_once(base, "spec: RFC 6509", "spec: RFC 9999")).has_value());
  // An action that the section does not allow.
  CHECK_FALSE(load_text(replace_once(base, "name: RAND, action: nonce", "name: RAND, action: uid")).has_value());
  // A required entry missing: the IDRkmsr role.
  CHECK_FALSE(load_text(replace_once(base, "role: 7,", "role: 77,")).has_value());
  // A rule without a source.
  auto no_source = load_text(R"(ruleset: mcxanon-mikey
version: 1.0.0
payloads:
  - {next: 5, name: T, action: shift}
)");
  CHECK_FALSE(no_source.has_value());
}
