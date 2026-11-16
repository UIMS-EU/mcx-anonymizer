// SPDX-License-Identifier: GPL-3.0-or-later
// Every FieldId the dissectors and the pcapng handling can emit has exactly one
// rule in the embedded rule set, and every rule names a source.
#include "dissect/catalogue.hpp"
#include "dissect/fields.hpp"
#include "policy/ruleset.hpp"

#include <catch2/catch_test_macros.hpp>

#include <utility>

#include <set>
#include <string>
#include <vector>

using namespace mcxanon;

TEST_CASE("the embedded rule set classifies every field exactly once", "[rules]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  CHECK(rs->name == "mcxanon-l2l4");
  std::set<std::string> ruled;
  for (const auto& r : rs->rules) {
    INFO(r.field);
    CHECK(ruled.insert(r.field).second);
    CHECK_FALSE(r.source.spec.empty());
    CHECK_FALSE(r.source.version.empty());
    CHECK_FALSE(r.source.clause.empty());
  }
  for (const auto& decl : Catalogue::builtin().all()) {
    INFO(decl.id);
    CHECK(ruled.contains(decl.id));
  }
  CHECK(ruled.size() == Catalogue::builtin().all().size());
  CHECK(Catalogue::builtin().all().size() == static_cast<std::size_t>(Fid::count_));
}

TEST_CASE("fail-closed defaults of the embedded rule set", "[rules]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  // Every payload field is zeroed (or dropped), every address pseudonymised.
  for (const auto& decl : Catalogue::builtin().all()) {
    const Rule* r = rs->find(decl.id);
    REQUIRE(r != nullptr);
    INFO(decl.id);
    if (decl.kind == FieldKind::payload && decl.id != "payload.sip" && decl.id != "payload.media") {
      CHECK(r->action == Action::zero);
    }
    if (decl.kind == FieldKind::address_mac || decl.kind == FieldKind::address_ipv4 ||
        decl.kind == FieldKind::address_ipv6) {
      CHECK(r->action == Action::pseudonymise);
    }
    if (decl.kind == FieldKind::opaque) CHECK(r->action == Action::zero);
  }
  // Metadata that names hosts, people or secrets is removed.
  for (const char* id : {"pcapng.opt.comment", "pcapng.shb.hardware", "pcapng.shb.os",
                         "pcapng.shb.userappl", "pcapng.idb.name", "pcapng.idb.description",
                         "pcapng.idb.ipv4addr", "pcapng.idb.macaddr", "pcapng.idb.filter",
                         "pcapng.blk.nrb", "pcapng.blk.dsb", "pcapng.blk.custom",
                         "pcapng.blk.other", "pcapng.opt.custom", "pcapng.epb.hash"}) {
    INFO(id);
    CHECK(rs->find(id)->action == Action::remove);
  }
}

TEST_CASE("payload.sip and payload.media delegate to their layers and are the only l7 fields", "[rules][sip]") {
  auto rs = load_embedded_ruleset();
  REQUIRE(rs.has_value());
  for (auto [field, spec] : {std::pair{"payload.sip", "RFC 3261"}, std::pair{"payload.media", "RFC 3550"}}) {
    INFO(field);
    const FieldDecl* decl = Catalogue::builtin().find(field);
    REQUIRE(decl != nullptr);
    CHECK(decl->kind == FieldKind::payload);
    const Rule* r = rs->find(field);
    REQUIRE(r != nullptr);
    CHECK(r->action == Action::l7);
    CHECK(r->source.spec == spec);
  }
  for (const auto& rule : rs->rules) {
    if (rule.field != "payload.sip" && rule.field != "payload.media") CHECK(rule.action != Action::l7);
  }
}

TEST_CASE("the l7 action is rejected for every other field", "[rules][sip]") {
  Catalogue c;
  c.add({"payload.sip", FieldKind::payload});
  c.add({"payload.l7", FieldKind::payload});
  c.add({"ipv4.ttl", FieldKind::numeric});
  const auto load = [&](const char* field, const char* action) {
    const std::string text = std::string("ruleset: t\nversion: 1.0.0\nrules:\n  - field: ") + field +
                             "\n    action: " + action +
                             "\n    source: {spec: RFC 3261, version: \"2002-06\", clause: \"7\"}\n";
    const RuleFile f{"a.yaml", text};
    return load_ruleset({&f, 1}, c);
  };
  CHECK(load("payload.sip", "l7").has_value());
  CHECK_FALSE(load("payload.l7", "l7").has_value());
  CHECK_FALSE(load("ipv4.ttl", "l7").has_value());
  // payload.sip accepts nothing but l7: a zero rule would silently disable the SIP layer.
  CHECK_FALSE(load("payload.sip", "zero").has_value());
}
