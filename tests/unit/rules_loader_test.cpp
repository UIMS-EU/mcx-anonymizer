// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcxanon/error.hpp"

#include "dissect/catalogue.hpp"
#include "policy/ruleset.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {

Catalogue test_catalogue() {
  Catalogue c;
  c.add({"ipv4.src", FieldKind::address_ipv4});
  c.add({"ipv4.ttl", FieldKind::numeric});
  c.add({"ipv4.checksum", FieldKind::checksum});
  c.add({"ipv4.opt.other", FieldKind::option});
  c.add({"pcapng.idb.opt.2", FieldKind::pcapng_option});
  return c;
}

const char* const kHeader = "ruleset: test-set\nversion: 1.2.3\nrules:\n";

std::string rule(const char* field, const char* action, const char* extra = "") {
  return std::string("  - field: ") + field + "\n    action: " + action + "\n" + extra +
         "    source: {spec: RFC 791, version: \"1981-09\", clause: \"3.1\"}\n";
}

Result<RuleSet> load(const std::string& text) {
  const RuleFile f{"a.yaml", text};
  return load_ruleset({&f, 1}, test_catalogue());
}

}  // namespace

TEST_CASE("valid rule file loads", "[policy]") {
  auto rs = load(std::string(kHeader) + rule("ipv4.src", "pseudonymise", "    category: ipv4\n") +
                 rule("ipv4.ttl", "keep") + rule("ipv4.checksum", "recompute") +
                 rule("ipv4.opt.other", "pad") + rule("pcapng.idb.opt.2", "remove"));
  REQUIRE(rs.has_value());
  CHECK(rs->name == "test-set");
  CHECK(rs->version == "1.2.3");
  CHECK(rs->rules.size() == 5);
  const Rule* r = rs->find("ipv4.src");
  REQUIRE(r != nullptr);
  CHECK(r->action == Action::pseudonymise);
  CHECK(r->category == "ipv4");
  CHECK(r->source.spec == "RFC 791");
  CHECK(r->source.clause == "3.1");
  CHECK(rs->find("ipv4.unknown") == nullptr);
}

TEST_CASE("missing source is a load error", "[policy]") {
  auto rs = load(std::string(kHeader) + "  - field: ipv4.ttl\n    action: keep\n");
  REQUIRE_FALSE(rs.has_value());
  CHECK(rs.error().message.find("source") != std::string::npos);
}

TEST_CASE("incomplete source is a load error", "[policy]") {
  auto rs = load(std::string(kHeader) +
                 "  - field: ipv4.ttl\n    action: keep\n    source: {spec: RFC 791}\n");
  REQUIRE_FALSE(rs.has_value());
}

TEST_CASE("duplicate field is a load error", "[policy]") {
  auto rs = load(std::string(kHeader) + rule("ipv4.ttl", "keep") + rule("ipv4.ttl", "zero"));
  REQUIRE_FALSE(rs.has_value());
  CHECK(rs.error().message.find("duplicate") != std::string::npos);
}

TEST_CASE("unknown FieldId is a load error", "[policy]") {
  auto rs = load(std::string(kHeader) + rule("ipv4.nonexistent", "keep"));
  REQUIRE_FALSE(rs.has_value());
  CHECK(rs.error().message.find("ipv4.nonexistent") != std::string::npos);
}

TEST_CASE("action that does not fit the field kind is a load error", "[policy]") {
  SECTION("pad on a numeric field") {
    CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.ttl", "pad")).has_value());
  }
  SECTION("remove on a packet field") {
    CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.src", "remove")).has_value());
  }
  SECTION("keep on a checksum") {
    CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.checksum", "keep")).has_value());
  }
  SECTION("zero on a pcapng option") {
    CHECK_FALSE(load(std::string(kHeader) + rule("pcapng.idb.opt.2", "zero")).has_value());
  }
  SECTION("pseudonymise without category") {
    CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.src", "pseudonymise")).has_value());
  }
  SECTION("pseudonymise with a category of another family") {
    CHECK_FALSE(load(std::string(kHeader) +
                     rule("ipv4.src", "pseudonymise", "    category: mac\n"))
                    .has_value());
  }
  SECTION("unknown action") {
    CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.ttl", "obliterate")).has_value());
  }
}

TEST_CASE("malformed YAML and unknown keys are load errors", "[policy]") {
  CHECK_FALSE(load("ruleset: [unterminated\n").has_value());
  CHECK_FALSE(load("ruleset: x\nversion: 1.0.0\nrules: {}\n").has_value());
  CHECK_FALSE(load(std::string(kHeader) + rule("ipv4.ttl", "keep", "    colour: red\n"))
                  .has_value());
  CHECK_FALSE(load("version: 1.0.0\nrules: []\n").has_value());
}

TEST_CASE("files of one rule set must agree on name and version", "[policy]") {
  const RuleFile a{"a.yaml", "ruleset: s\nversion: 1.0.0\nrules: []\n"};
  const RuleFile b{"b.yaml", "ruleset: s\nversion: 1.0.1\nrules: []\n"};
  const RuleFile files[] = {a, b};
  CHECK_FALSE(load_ruleset(files, test_catalogue()).has_value());
}

TEST_CASE("digest is the SHA-256 of the concatenated files in name order", "[policy]") {
  const RuleFile a{"a.yaml", "ruleset: s\nversion: 1.0.0\nrules: []\n"};
  const RuleFile b{"b.yaml", "ruleset: s\nversion: 1.0.0\nrules: []\n"};
  const RuleFile ab[] = {a, b};
  const RuleFile ba[] = {b, a};
  auto x = load_ruleset(ab, test_catalogue());
  auto y = load_ruleset(ba, test_catalogue());
  REQUIRE(x.has_value());
  REQUIRE(y.has_value());
  CHECK(x->digest == y->digest);
  CHECK(x->digest.size() == 64);
  // SHA-256 of the empty string, for an empty file list:
  auto empty = load_ruleset({}, test_catalogue());
  REQUIRE_FALSE(empty.has_value());  // a rule set needs at least one file
}

TEST_CASE("embedded rule set loads and matches the build-time digest", "[policy]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  CHECK(rs->name == embedded_ruleset_name());
  CHECK(rs->digest == embedded_ruleset_digest());
}
