// SPDX-License-Identifier: GPL-3.0-or-later
//
// User Story 2 composites: xcap_selector, user_at_host, any_id and opaque, mapped with the 002 mappings.
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
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i * 7 + 2);
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

  std::string map(XmlCategory c, std::string_view v) {
    auto r = xml::map_category(c, v, ctx);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    return **r;
  }
  bool fits(XmlCategory c, std::string_view v) {
    auto r = xml::map_category(c, v, ctx);
    REQUIRE(r.has_value());
    return r->has_value();
  }
  std::string uri(std::string_view v) { return **sip::rewrite_uri_text(v, ctx); }
};

std::string no_scheme(const std::string& u) { return u.substr(u.find(':') + 1); }
}  // namespace

TEST_CASE("opaque keeps length and character classes", "[xml][xcap]") {
  Fixture f;
  const auto o = f.map(XmlCategory::opaque, "acD4rhU87bK");
  CHECK(o.size() == 11);
  CHECK(o != "acD4rhU87bK");
  CHECK(f.map(XmlCategory::opaque, "acD4rhU87bK") == o);  // deterministic
}

TEST_CASE("any_id dispatches by scheme (E1)", "[xml][xcap]") {
  Fixture f;
  CHECK(f.map(XmlCategory::any_id, "sip:alice@example.net") == f.uri("sip:alice@example.net"));
  const auto inst = f.map(XmlCategory::any_id, "urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18");
  CHECK(inst == **sip::map_instance("urn:uuid:5f0e8c2a-3b71-4d9e-9a44-2c7b1e6f0d18", f.ctx));
  CHECK(f.map(XmlCategory::any_id, "acD4rhU87bK") == f.map(XmlCategory::opaque, "acD4rhU87bK"));
  CHECK_FALSE(f.fits(XmlCategory::any_id, "not an id"));
}

TEST_CASE("user_at_host maps as sip: and is written without the scheme (E9)", "[xml][xcap]") {
  Fixture f;
  CHECK(f.map(XmlCategory::user_at_host, "user1@example.com") == no_scheme(f.uri("sip:user1@example.com")));
  CHECK_FALSE(f.fits(XmlCategory::user_at_host, "no-at-sign"));
}

TEST_CASE("xcap_selector: document selectors of the users and global trees (E.7.4)", "[xml][xcap]") {
  Fixture f;
  const auto alice = f.uri("sip:alice@example.net");
  // AUID and tree kept, XUI through the 002 URI mapping, a numbered profile name kept.
  CHECK(f.map(XmlCategory::xcap_selector,
              "org.3gpp.mcptt.user-profile/users/sip:alice@example.net/mcptt-user-profile-2.xml") ==
        "org.3gpp.mcptt.user-profile/users/" + alice + "/mcptt-user-profile-2.xml");
  // A scheme-less XUI (E9); the IMEI segment and the document name become opaque (E8).
  const auto ue = f.map(XmlCategory::xcap_selector,
                        "org.3gpp.mcptt.ue-config/users/user1@example.com/imei-90420156-025763-0/mcptt-ue-config.xml");
  CHECK(ue == "org.3gpp.mcptt.ue-config/users/" + no_scheme(f.uri("sip:user1@example.com")) + "/" +
                  f.map(XmlCategory::opaque, "imei-90420156-025763-0") + "/" +
                  f.map(XmlCategory::opaque, "mcptt-ue-config.xml"));
  // Global tree; a collection (trailing slash) stays a collection.
  CHECK(f.map(XmlCategory::xcap_selector, "org.3gpp.mcptt.service-config/global/service-config.xml") ==
        "org.3gpp.mcptt.service-config/global/" + f.map(XmlCategory::opaque, "service-config.xml"));
  CHECK(f.map(XmlCategory::xcap_selector, "org.3gpp.mcptt.ue-config/users/sip:alice@example.net/") ==
        "org.3gpp.mcptt.ue-config/users/" + alice + "/");
  // A group document: byGroupID kept, the group ID mapped as a URI.
  CHECK(f.map(XmlCategory::xcap_selector, "org.openmobilealliance.groups/global/byGroupID/sip:grp@example.net") ==
        "org.openmobilealliance.groups/global/byGroupID/" + f.uri("sip:grp@example.net"));
  // An unknown AUID is opaque.
  CHECK(f.map(XmlCategory::xcap_selector, "vendor.secret/global/doc.xml") ==
        f.map(XmlCategory::opaque, "vendor.secret") + "/global/" + f.map(XmlCategory::opaque, "doc.xml"));
}

TEST_CASE("xcap_selector: escaping, node selector literals and the absolute form", "[xml][xcap]") {
  Fixture f;
  const auto alice = f.uri("sip:alice@example.net");
  // Escaped octets stay escaped in the output (here "@" as %40).
  const auto esc = f.map(XmlCategory::xcap_selector, "resource-lists/users/sip:alice%40example.net/index");
  std::string want = alice;
  want.replace(want.find('@'), 1, "%40");
  CHECK(esc == "resource-lists/users/" + want + "/index");
  // Node selector: steps kept, quoted literals mapped (opaque, or a URI).
  const auto node = f.map(XmlCategory::xcap_selector,
                          "resource-lists/users/sip:alice@example.net/index/~~/resource-lists/list%5b@name=%22friends%22%5d"
                          "/entry%5b@uri=%22sip:bob@example.net%22%5d");
  const auto bob = f.uri("sip:bob@example.net");
  CHECK(node == "resource-lists/users/" + alice + "/index/~~/resource-lists/list%5b@name=%22" +
                    f.map(XmlCategory::opaque, "friends") + "%22%5d/entry%5b@uri=%22" + bob + "%22%5d");
  // Absolute form: scheme and port kept, host mapped, XCAP root segments opaque.
  const auto abs = f.map(XmlCategory::xcap_selector,
                         "https://xcap.example.net:8443/MCO-12345/org.3gpp.mcptt.user-profile/users/"
                         "sip:alice@example.net/mcptt-user-profile-0.xml");
  CHECK(abs == "https://" + **sip::map_host("xcap.example.net", f.ctx) + ":8443/" +
                   f.map(XmlCategory::opaque, "MCO-12345") + "/org.3gpp.mcptt.user-profile/users/" + alice +
                   "/mcptt-user-profile-0.xml");
  // An XCAP root alone: every path segment opaque.
  CHECK(f.map(XmlCategory::xcap_selector, "https://xcap.example.net/MCO-12345/") ==
        "https://" + **sip::map_host("xcap.example.net", f.ctx) + "/" + f.map(XmlCategory::opaque, "MCO-12345") + "/");
  CHECK_FALSE(f.fits(XmlCategory::xcap_selector, ""));
  CHECK_FALSE(f.fits(XmlCategory::xcap_selector, "resource-lists/users/sip:a@b/~~/list%5b@name=%22open"));
}

TEST_CASE("xcap_node: an RFC 5261 patch selector keeps its steps and maps its literals", "[xml][xcap]") {
  Fixture f;
  CHECK(f.map(XmlCategory::xcap_node, "/resource-lists/list[@name='friends']/entry[@uri='sip:bob@example.net']") ==
        "/resource-lists/list[@name='" + f.map(XmlCategory::opaque, "friends") + "']/entry[@uri='" +
            f.uri("sip:bob@example.net") + "']");
  CHECK(f.map(XmlCategory::xcap_node, "/cp:ruleset/cp:rule[2]/@id") == "/cp:ruleset/cp:rule[2]/@id");
  CHECK_FALSE(f.fits(XmlCategory::xcap_node, "/a[@n='open"));
}
