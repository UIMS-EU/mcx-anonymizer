// SPDX-License-Identifier: GPL-3.0-or-later
//
// Composite categories of User Story 1 (A3, A10):
// their parts map with the 002 mappings exactly as the same values in SIP headers do.
#include "pipeline/mapper_adapter.hpp"
#include "pseudo/pseudonymiser.hpp"
#include "sip/rewrite.hpp"
#include "xml/categories.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace mcxanon;

namespace {
Secret secret() {
  Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 5 + 3);
  return s;
}

struct Fixture {
  SipRuleSet rules = *load_embedded_sip_ruleset();
  Secret key = secret();
  Mapping mapping;
  Pseudonymiser p{key, mapping};
  MapperAdapter mapper{p};
  sip::SipCounters counters;
  sip::Context ctx{rules, mapper, {}, counters};

  std::string sip(SipCategory c, std::string_view v) { return **sip::map_value(c, v, ctx); }
};
}  // namespace

TEST_CASE("kms_uri: a URI with a scheme maps like a SIP URI, a bare host like a host", "[xml][composite]") {
  Fixture f;
  const auto uri = xml::map_category(XmlCategory::kms_uri, "sip:kms@kms.example.net", f.ctx);
  REQUIRE(uri.has_value());
  REQUIRE(uri->has_value());
  CHECK(**uri == **sip::rewrite_uri_text("sip:kms@kms.example.net", f.ctx));
  CHECK(**uri != "sip:kms@kms.example.net");
  const auto host = xml::map_category(XmlCategory::kms_uri, "kms.example.net", f.ctx);
  REQUIRE(host.has_value());
  REQUIRE(host->has_value());
  CHECK(**host == **sip::map_host("kms.example.net", f.ctx));
  CHECK(**host != "kms.example.net");
  // Anything else does not fit: the caller removes it and counts it malformed.
  const auto bad = xml::map_category(XmlCategory::kms_uri, "not a host", f.ctx);
  REQUIRE(bad.has_value());
  CHECK_FALSE(bad->has_value());
}

TEST_CASE("replaces: Call-ID, from-tag and to-tag map with the 002 call-id and tag mappings", "[xml][composite]") {
  Fixture f;
  const std::string cid = "a84b4c76e66710@pc33.example.net";
  const auto raw = xml::map_category(XmlCategory::replaces, cid + ";1928301774;a6c85cf", f.ctx);
  REQUIRE(raw.has_value());
  REQUIRE(raw->has_value());
  CHECK(**raw == f.sip(SipCategory::call_id, cid) + ";" + f.sip(SipCategory::tag, "1928301774") + ";" +
                     f.sip(SipCategory::tag, "a6c85cf"));
  // The RFC 3891 parameter form keeps its parameter names.
  const auto named = xml::map_category(XmlCategory::replaces, cid + ";from-tag=1928301774;to-tag=a6c85cf", f.ctx);
  REQUIRE(named.has_value());
  REQUIRE(named->has_value());
  CHECK(**named == f.sip(SipCategory::call_id, cid) + ";from-tag=" + f.sip(SipCategory::tag, "1928301774") +
                       ";to-tag=" + f.sip(SipCategory::tag, "a6c85cf"));
  for (const char* bad : {"only-a-call-id", "a;b", "a;b;c;d", ";b;c", "a;;c"}) {
    INFO(bad);
    const auto r = xml::map_category(XmlCategory::replaces, bad, f.ctx);
    REQUIRE(r.has_value());
    CHECK_FALSE(r->has_value());
  }
}

TEST_CASE("instance: a UUID or IMEI URN maps like +sip.instance", "[xml][composite]") {
  // X16, A.3 mcptt-client-id: the MCPTT client ID is a UUID URN (RFC 9562); it gets the 002
  // instance mapping, so the same client has one pseudonym in Contact and in mcptt-info.
  Fixture f;
  const std::string urn = "urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18";
  const auto x = xml::map_category(XmlCategory::instance, urn, f.ctx);
  REQUIRE(x.has_value());
  REQUIRE(x->has_value());
  CHECK(**x == **sip::map_instance(urn, f.ctx));
  CHECK((*x)->starts_with("urn:uuid:"));
  CHECK(**x != urn);
  // X16: a bare UUID maps with the 002 UUID mapping (the pseudonym of the urn:uuid: form's UUID).
  const auto bare = xml::map_category(XmlCategory::instance, "5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18", f.ctx);
  REQUIRE(bare.has_value());
  REQUIRE(bare->has_value());
  CHECK("urn:uuid:" + **bare == **x);
  const auto bad = xml::map_category(XmlCategory::instance, "not-an-urn", f.ctx);
  REQUIRE(bad.has_value());
  CHECK_FALSE(bad->has_value());
}
