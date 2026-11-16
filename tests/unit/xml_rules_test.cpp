// SPDX-License-Identifier: GPL-3.0-or-later
//
// The XML rule set loader (feature 003).
#include "policy/sip_rules.hpp"
#include "policy/http_rules.hpp"
#include "policy/xml_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mcxanon;

namespace {

const std::string kSrc = R"(source: {spec: TS 24.379, version: "19.6.0", clause: "F.1.3"})";

std::string base(const std::string& elements, const std::string& attributes = "",
                 const std::string& extra_ns = "") {
  return "ruleset: mcxanon-xml\nversion: 1.0.0\n"
         "documents:\n"
         "  - content_type: application/vnd.3gpp.mcptt-info+xml\n"
         "    roots: [{ns: \"urn:3gpp:ns:mcpttInfo:1.0\", name: mcpttinfo}]\n"
         "    source: {spec: TS 24.379, version: \"19.6.0\", clause: \"F.1.4\"}\n"
         "namespaces:\n"
         "  - name: \"urn:3gpp:ns:mcpttInfo:1.0\"\n"
         "    source: {spec: TS 24.379, version: \"19.6.0\", clause: \"F.1.2\"}\n"
         "    elements:\n" +
         elements + (attributes.empty() ? "" : "    attributes:\n" + attributes) + extra_ns;
}

const std::string kRoot = "      - {name: mcpttinfo, action: container, " + kSrc + "}\n";

Result<XmlRuleSet> load(const std::string& text) {
  std::vector<RuleFile> files{RuleFile{"xml-test.yaml", text}};
  return load_xml_ruleset(files);
}

std::string error_of(const std::string& text) {
  auto r = load(text);
  REQUIRE_FALSE(r.has_value());
  return r.error().message;
}

bool contains(const std::string& s, const std::string& part) { return s.find(part) != std::string::npos; }

}  // namespace

TEST_CASE("xml rules: a valid set loads with every action and value type") {
  const std::string els = kRoot +
      "      - {name: session-type, action: keep, value: {enum: [private, prearranged]}, " + kSrc + "}\n"
      "      - {name: emergency-ind, action: keep, value: boolean, " + kSrc + "}\n"
      "      - {name: count, action: keep, value: {int: [0, 18446744073709551615]}, " + kSrc + "}\n"
      "      - {name: when, action: keep, value: datetime, " + kSrc + "}\n"
      "      - {name: sai, action: keep, value: {hex: [4]}, " + kSrc + "}\n"
      "      - {name: trigger, action: keep, value: {token: trigger-id}, " + kSrc + "}\n"
      "      - {name: mcpttURI, action: pseudonymise, category: uri, " + kSrc + "}\n"
      "      - {name: mcpttString, parent: [mcptt-access-token], action: remove, reason: credential, " + kSrc + "}\n"
      "      - {name: mcpttString, parent: [mcptt-client-id], action: pseudonymise, category: instance, " + kSrc + "}\n"
      "      - {name: mcpttString, action: keep, value: {enum: [a]}, " + kSrc + "}\n"
      "      - {name: latitude, action: fixed, constant: \"0\", value: {int: [0, 16777215]}, " + kSrc + "}\n"
      "      - {name: SignatureValue, action: empty, " + kSrc + "}\n"
      "      - {name: alert, action: remove, reason: free-text, encryptable: true, " + kSrc + "}\n";
  const std::string attrs =
      "      - {element: \"*\", name: type, action: keep, value: {enum: [Normal, Encrypted]}, " + kSrc + "}\n"
      "      - {element: entry, name: uri, action: pseudonymise, category: uri, embeds_body: true, " + kSrc + "}\n"
      "      - {element: \"*\", ns: \"http://www.w3.org/XML/1998/namespace\", name: lang, action: keep, value: lang, " + kSrc + "}\n";
  const std::string xenc =
      "  - name: \"http://www.w3.org/2001/04/xmlenc#\"\n"
      "    disposition: remove_encrypted\n"
      "    source: {spec: TS 33.180, version: \"20.0.0\", clause: \"9.3.4.2\"}\n";
  auto rs = load(base(els, attrs, xenc));
  if (!rs) FAIL(rs.error().message);
  CHECK(rs->name == "mcxanon-xml");
  CHECK(rs->version == "1.0.0");
  CHECK_FALSE(rs->digest.empty());
  const auto* doc = rs->document("application/vnd.3gpp.mcptt-info+xml");
  REQUIRE(doc != nullptr);
  REQUIRE(doc->roots.size() == 1);
  CHECK(doc->roots[0].local == "mcpttinfo");
  const auto* ns = rs->ns("urn:3gpp:ns:mcpttInfo:1.0");
  REQUIRE(ns != nullptr);
  CHECK(ns->element("session-type", "mcptt-Params")->rule.value->values.size() == 2);
  CHECK(ns->element("count", "x")->rule.value->max == 18446744073709551615ull);
  CHECK(ns->element("trigger", "x")->rule.value->grammar == XmlTokenGrammar::trigger_id);
  CHECK(ns->element("mcpttURI", "x")->rule.category == XmlCategory::uri);
  CHECK(ns->element("latitude", "x")->rule.constant == "0");
  CHECK(ns->element("alert", "x")->rule.encryptable);
  CHECK(ns->element("alert", "x")->rule.reason == XmlRemoveReason::free_text);
  CHECK(ns->element("nope", "x") == nullptr);
  // X1: the parent rule wins, the rule without parent is the fallback.
  CHECK(ns->element("mcpttString", "mcptt-access-token")->rule.action == XmlAction::remove);
  CHECK(ns->element("mcpttString", "mcptt-client-id")->rule.category == XmlCategory::instance);
  CHECK(ns->element("mcpttString", "session-type")->rule.action == XmlAction::keep);
  // Attributes: (element, attribute) first, then ("*", attribute).
  CHECK(ns->attribute("entry", "", "uri")->rule.embeds_body);
  CHECK(ns->attribute("anything", "", "type")->rule.action == XmlAction::keep);
  CHECK(ns->attribute("anything", "http://www.w3.org/XML/1998/namespace", "lang") != nullptr);
  CHECK(ns->attribute("anything", "", "lang") == nullptr);
  CHECK(rs->ns("http://www.w3.org/2001/04/xmlenc#")->disposition == XmlDisposition::remove_encrypted);
  CHECK(rs->ns("urn:unknown") == nullptr);
}

TEST_CASE("xml rules: validation failures name the rule") {
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: keep, value: boolean}\n")), "source"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: keep, value: boolean, "
                                       "source: {spec: RFC 9999, version: \"2030-01\", clause: \"1\"}}\n")),
                 "RFC 9999"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: keep, " + kSrc + "}\n")), "value"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: pseudonymise, " + kSrc + "}\n")), "category"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: pseudonymise, category: nonsense, " + kSrc + "}\n")),
                 "nonsense"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: fixed, " + kSrc + "}\n")), "constant"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: fixed, constant: x, value: {int: [0, 9]}, " + kSrc + "}\n")),
                 "constant"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: remove, " + kSrc + "}\n")), "reason"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: keep, value: {token: free-text}, " + kSrc + "}\n")),
                 "free-text"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: container, " + kSrc + "}\n"
                                       "      - {name: a, action: container, " + kSrc + "}\n")),
                 "duplicate"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, parent: [p, q], action: container, " + kSrc + "}\n"
                                       "      - {name: a, parent: [q], action: container, " + kSrc + "}\n")),
                 "parent"));
  CHECK(contains(error_of(base("      - {name: other, action: container, " + kSrc + "}\n")), "root"));
  CHECK(contains(error_of(base("      - {name: mcpttinfo, action: keep, value: boolean, " + kSrc + "}\n")), "root"));
  CHECK(contains(error_of(base(kRoot + "      - {name: a, action: frobnicate, " + kSrc + "}\n")), "frobnicate"));
  CHECK(contains(error_of("ruleset: mcxanon-sip\nversion: 1.0.0\n"), "mcxanon-xml"));
  CHECK(contains(error_of(base(kRoot, "", "  - name: \"urn:3gpp:ns:mcpttInfo:1.0\"\n"
                                          "    source: {spec: TS 24.379, version: \"19.6.0\", clause: \"F.1.2\"}\n")),
                 "more than once"));
}

TEST_CASE("xml rules: the cross-check with the SIP body rules") {
  auto xml = load(base(kRoot));
  REQUIRE(xml.has_value());
  auto sip = load_embedded_sip_ruleset();
  REQUIRE(sip.has_value());
  // The minimal set has a document for mcptt-info only: switch every other type off in a copy.
  for (auto& b : sip->bodies) {
    if (b.handling == BodyHandling::xml && b.content_type != "application/vnd.3gpp.mcptt-info+xml") {
      b.handling = BodyHandling::empty;
    }
  }
  CHECK(check_xml_bodies(*sip, *xml, false).has_value());
  // A document for a Content-Type the SIP rules do not know is rejected.
  std::string unknown = base(kRoot);
  unknown.replace(unknown.find("application/vnd.3gpp.mcptt-info+xml"), 35, "application/x-unknown+xml");
  auto xml2 = load(unknown);
  REQUIRE(xml2.has_value());
  CHECK_FALSE(check_xml_bodies(*sip, *xml2, false).has_value());
}

TEST_CASE("xml rules: the embedded rule set loads") {
  auto rs = load_embedded_xml_ruleset();
  if (!rs) FAIL(rs.error().message);
  CHECK(rs->name == "mcxanon-xml");
  CHECK(rs->digest == embedded_xml_ruleset_digest());
  auto sip = load_embedded_sip_ruleset();
  REQUIRE(sip.has_value());
  // Feature 007: the CMS, GMS and KMS documents are HTTP bodies only.
  auto http = load_embedded_http_ruleset();
  REQUIRE(http.has_value());
  std::vector<std::string> http_xml;
  for (const auto& b : http->bodies) {
    if (b.handling == HttpBodyHandling::xml) http_xml.push_back(b.content_type);
  }
  CHECK(check_xml_bodies(*sip, *rs, false, http_xml).has_value());
  // Feature 003 complete: every document rule's Content-Type is switched on.
  CHECK(check_xml_bodies(*sip, *rs, true, http_xml).has_value());
  CHECK_FALSE(check_xml_bodies(*sip, *rs, true).has_value());  // without the HTTP types
}
