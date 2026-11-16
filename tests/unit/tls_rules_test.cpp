// SPDX-License-Identifier: GPL-3.0-or-later
//
// The TLS rule set loader.
#include "policy/tls_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {

const TlsRuleSet& embedded() {
  static const TlsRuleSet rs = [] {
    auto r = load_embedded_tls_ruleset();
    if (!r) FAIL(r.error().message);
    return *r;
  }();
  return rs;
}

Result<TlsRuleSet> load_text(const std::string& text) {
  std::vector<RuleFile> f{RuleFile{"tls.yaml", "ruleset: mcxanon-tls\nversion: 1.0.0\n" + text}};
  return load_tls_ruleset(f);
}

}  // namespace

TEST_CASE("tls rules: the embedded rule set loads", "[tls][rules]") {
  const auto& rs = embedded();
  CHECK(rs.name == "mcxanon-tls");
  CHECK(rs.known_version(0x0303));
  CHECK_FALSE(rs.known_version(0x0305));
  CHECK(rs.find_record(23)->action == TlsRecordAction::zero);
  CHECK(rs.find_record(22)->action == TlsRecordAction::parse);
  CHECK(rs.find_handshake(1)->action == TlsHandshakeAction::hello);
  CHECK(rs.find_handshake(8) == nullptr);  // encrypted_extensions is never in the clear
  CHECK(rs.find_extension(0)->action == TlsExtensionAction::server_name);
  CHECK(rs.find_extension(16)->values.size() == 2);
  CHECK(rs.find_extension(0xfe0d) == nullptr);  // encrypted client hello: unknown, zeroed
  REQUIRE(rs.find_suite(0xC02F) != nullptr);
  CHECK(rs.find_suite(0xC02F)->family == KexFamily::ecdhe);
  CHECK(rs.find_suite(0x1301)->family == KexFamily::tls13);
  CHECK(rs.find_suite(0x008C)->family == KexFamily::psk);
  CHECK(rs.find_attribute("2.5.4.6")->action == X509AttributeAction::keep);
  CHECK(rs.find_attribute("2.5.4.3")->action == X509AttributeAction::identity);
  CHECK(rs.find_x509_extension("2.5.29.17")->action == X509ExtensionAction::general_names);
  CHECK(rs.find_public_key("1.2.840.113549.1.1.1")->action == PublicKeyAction::rsa);
}

TEST_CASE("tls rules: load-time validation", "[tls][rules]") {
  const auto src = std::string(", source: {spec: RFC 8446, version: \"2018-08\", clause: \"4.2\"}}\n");
  CHECK_FALSE(load_text("extensions:\n  - {type: 70000, name: x, action: keep" + src).has_value());
  CHECK_FALSE(load_text("extensions:\n  - {type: 1, name: x, action: magic" + src).has_value());
  CHECK_FALSE(load_text("extensions:\n  - {type: 1, name: x, action: keep, values: [a]" + src).has_value());
  CHECK_FALSE(load_text("x509:\n  attributes:\n    - {oid: 2..5, name: x, action: keep" + src).has_value());
  CHECK_FALSE(load_text("records:\n  - {type: 1, name: x, action: keep}\n").has_value());
  CHECK_FALSE(load_text("key_exchange:\n  - {suite: 1, family: quantum" + src).has_value());
  CHECK(load_text("extensions:\n  - {type: 1, name: x, action: keep" + src).has_value());
}
